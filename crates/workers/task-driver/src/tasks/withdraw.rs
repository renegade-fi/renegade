//! Defines a task to withdraw a balance from the darkpool

use std::fmt::{Display, Formatter, Result as FmtResult};

use alloy::primitives::{Address, Bytes};
use async_trait::async_trait;
use circuit_types::Amount;
use circuits_core::zk_circuits::valid_withdrawal::{
    SizedValidWithdrawalWitness, ValidWithdrawalStatement, ValidWithdrawalWitness,
};
use darkpool_types::withdrawal::Withdrawal;
use job_types::proof_manager::{ProofJob, ProofManagerResponse};
use renegade_solidity_abi::v2::IDarkpoolV2::WithdrawalAuth;
use serde::Serialize;
use state::{State, error::StateError};
use tracing::{info, instrument};
use types_account::{MerkleAuthenticationPath, balance::Balance};
use types_core::AccountId;
use types_proofs::ValidWithdrawalBundle;
use types_tasks::WithdrawTaskDescriptor;

use crate::{
    hooks::TaskHook,
    task_state::TaskStateWrapper,
    tasks::validity_proofs::balance_update::refresh_validity_proofs_for_updated_balance,
    traits::{Descriptor, Task, TaskContext, TaskError, TaskState},
    utils::enqueue_proof_job,
};
use darkpool_client::DarkpoolClient;

/// The task name for the withdraw task
const WITHDRAW_TASK_NAME: &str = "withdraw";

// --------------
// | Task State |
// --------------

/// Represents the state of the task through its async execution
#[derive(Clone, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum WithdrawTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// Generating a proof of `VALID WITHDRAWAL`
    Proving,
    /// The task is submitting the withdrawal transaction
    SubmittingTx,
    /// The task is updating the relayer state
    UpdatingState,
    /// The task is updating validity proofs for affected Ring 2/3 orders
    UpdatingValidityProofs,
    /// The task is completed
    Completed,
}

impl TaskState for WithdrawTaskState {
    fn commit_point() -> Self {
        WithdrawTaskState::SubmittingTx
    }

    fn completed(&self) -> bool {
        matches!(self, WithdrawTaskState::Completed)
    }
}

impl Display for WithdrawTaskState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            WithdrawTaskState::Pending => write!(f, "Pending"),
            WithdrawTaskState::Proving => write!(f, "Proving"),
            WithdrawTaskState::SubmittingTx => write!(f, "SubmittingTx"),
            WithdrawTaskState::UpdatingState => write!(f, "UpdatingState"),
            WithdrawTaskState::UpdatingValidityProofs => write!(f, "UpdatingValidityProofs"),
            WithdrawTaskState::Completed => write!(f, "Completed"),
        }
    }
}

impl From<WithdrawTaskState> for TaskStateWrapper {
    fn from(state: WithdrawTaskState) -> Self {
        TaskStateWrapper::Withdraw(state)
    }
}

// ---------------
// | Task Errors |
// ---------------

/// The error type thrown by the withdraw task
#[derive(Clone, Debug, thiserror::Error)]
pub enum WithdrawTaskError {
    /// An error interacting with the darkpool client
    #[error("darkpool client error: {0}")]
    DarkpoolClient(String),
    /// An error generating a proof of `VALID WITHDRAWAL`
    #[error("proof generation error: {0}")]
    ProofGeneration(String),
    /// An error updating validity proofs affected by this balance update
    #[error("validity proof update error: {0}")]
    ValidityProof(String),
    /// An error interacting with global state
    #[error("state error: {0}")]
    State(String),
}

impl TaskError for WithdrawTaskError {
    fn retryable(&self) -> bool {
        matches!(
            self,
            WithdrawTaskError::DarkpoolClient(_)
                | WithdrawTaskError::ProofGeneration(_)
                | WithdrawTaskError::ValidityProof(_)
        )
    }
}

impl From<StateError> for WithdrawTaskError {
    fn from(e: StateError) -> Self {
        WithdrawTaskError::State(e.to_string())
    }
}

/// A type alias for a result in this task
type Result<T> = std::result::Result<T, WithdrawTaskError>;

// -------------------
// | Task Definition |
// -------------------

/// Represents a task to withdraw a balance from the darkpool
pub struct WithdrawTask {
    /// The account ID to withdraw from
    pub account_id: AccountId,
    /// The token address for the balance
    pub token: Address,
    /// The amount to withdraw
    pub amount: Amount,
    /// The signature authorizing the withdrawal
    pub signature: Vec<u8>,
    /// The updated balance after the withdrawal
    pub updated_balance: Option<Balance>,
    /// A proof of `VALID WITHDRAWAL` created in the proving step
    pub proof_bundle: Option<ValidWithdrawalBundle>,
    /// The state of the task's execution
    pub task_state: WithdrawTaskState,
    /// The context of the task
    pub ctx: TaskContext,
}

#[async_trait]
impl Task for WithdrawTask {
    type State = WithdrawTaskState;
    type Error = WithdrawTaskError;
    type Descriptor = WithdrawTaskDescriptor;

    async fn new(descriptor: Self::Descriptor, ctx: TaskContext) -> Result<Self> {
        Ok(Self {
            account_id: descriptor.account_id,
            token: descriptor.token,
            amount: descriptor.amount,
            signature: descriptor.signature,
            updated_balance: None,
            proof_bundle: None,
            task_state: WithdrawTaskState::Pending,
            ctx,
        })
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(skip_all, err, fields(task = %self.name(), state = %self.task_state()))]
    async fn step(&mut self) -> Result<()> {
        // Dispatch based on task state
        match self.task_state {
            WithdrawTaskState::Pending => {
                self.task_state = WithdrawTaskState::Proving;
            },
            WithdrawTaskState::Proving => {
                // Generate a proof of `VALID WITHDRAWAL`
                self.generate_proof().await?;
                self.task_state = WithdrawTaskState::SubmittingTx;
            },
            WithdrawTaskState::SubmittingTx => {
                // Submit the withdrawal transaction to the darkpool
                self.submit_withdrawal().await?;
                self.task_state = WithdrawTaskState::UpdatingState;
            },
            WithdrawTaskState::UpdatingState => {
                // Update the relayer state with the new balance
                self.update_state().await?;
                self.task_state = WithdrawTaskState::UpdatingValidityProofs;
            },
            WithdrawTaskState::UpdatingValidityProofs => {
                self.update_validity_proofs().await?;
                self.task_state = WithdrawTaskState::Completed;
            },
            WithdrawTaskState::Completed => {
                unreachable!("step called on task in Completed state")
            },
        }

        Ok(())
    }

    fn name(&self) -> String {
        WITHDRAW_TASK_NAME.to_string()
    }

    fn task_state(&self) -> Self::State {
        self.task_state.clone()
    }

    fn failure_hooks(&self) -> Vec<Box<dyn TaskHook>> {
        vec![]
    }

    fn success_hooks(&self) -> Vec<Box<dyn TaskHook>> {
        vec![]
    }
}

impl Descriptor for WithdrawTaskDescriptor {}

// -----------------------
// | Task Implementation |
// -----------------------

impl WithdrawTask {
    // --------------
    // | Task Steps |
    // --------------

    /// Generate a proof of `VALID WITHDRAWAL` for the withdrawal
    pub async fn generate_proof(&mut self) -> Result<()> {
        info!("Generating withdrawal proof...");
        let (witness, statement, updated_balance) = self.build_witness_statement().await?;
        self.updated_balance = Some(updated_balance);

        let job = ProofJob::ValidWithdrawal { statement, witness };
        let proof_recv =
            enqueue_proof_job(job, &self.ctx).map_err(WithdrawTaskError::ProofGeneration)?;

        // Await the proof
        let bundle: ProofManagerResponse =
            proof_recv.await.map_err(|e| WithdrawTaskError::ProofGeneration(e.to_string()))?;
        self.proof_bundle = Some(bundle.into());
        Ok(())
    }

    /// Update the relayer state with the post-withdrawal balance
    pub async fn update_state(&self) -> Result<()> {
        info!("Updating relayer state after withdrawal...");
        let balance = self.updated_balance.clone().unwrap();
        let waiter = self.state().update_account_balance(self.account_id, balance).await?;
        waiter.await?;

        Ok(())
    }

    /// Refresh validity proofs for affected Ring 2/3 orders
    pub async fn update_validity_proofs(&self) -> Result<()> {
        refresh_validity_proofs_for_updated_balance(self.account_id, self.token, &self.ctx)
            .await
            .map_err(|e| WithdrawTaskError::ValidityProof(e.to_string()))
    }

    /// Submit the withdrawal transaction to the darkpool
    pub async fn submit_withdrawal(&self) -> Result<()> {
        info!("Submitting withdrawal...");
        let proof_bundle = self
            .proof_bundle
            .clone()
            .ok_or_else(|| WithdrawTaskError::State("proof bundle not found".to_string()))?;

        let commitment = proof_bundle.statement.new_balance_commitment;
        let auth = self.build_withdrawal_auth();
        let receipt = self
            .darkpool_client()
            .withdraw(auth, proof_bundle)
            .await
            .map_err(|e| WithdrawTaskError::DarkpoolClient(e.to_string()))?;

        // Parse a Merkle opening for the new balance from the receipt
        let opening = self
            .darkpool_client()
            .find_merkle_authentication_path_with_tx(commitment, &receipt)
            .map_err(|e| WithdrawTaskError::DarkpoolClient(e.to_string()))?;

        // Store the Merkle opening in state
        let waiter =
            self.state().add_balance_merkle_proof(self.account_id, self.token, opening).await?;
        waiter.await?;

        Ok(())
    }

    /// Build the withdrawal authorization from the signature
    fn build_withdrawal_auth(&self) -> WithdrawalAuth {
        let signature = Bytes::from(self.signature.clone());
        WithdrawalAuth { signature }
    }
}

// -----------
// | Helpers |
// -----------

impl WithdrawTask {
    /// Get a reference to the relayer state
    fn state(&self) -> &State {
        &self.ctx.state
    }

    /// Get a reference to the darkpool client
    fn darkpool_client(&self) -> &DarkpoolClient {
        &self.ctx.darkpool_client
    }

    /// Generate a witness and statement for a withdrawal
    ///
    /// Returns the witness, statement, and the updated balance after the
    /// withdrawal has been applied.
    async fn build_witness_statement(
        &self,
    ) -> Result<(SizedValidWithdrawalWitness, ValidWithdrawalStatement, Balance)> {
        let mut balance = self.get_balance().await?;
        let old_balance = balance.state_wrapper.clone();
        let balance_opening = self.get_balance_merkle_proof().await?;
        let root = balance_opening.compute_root();
        let nullifier = balance.state_wrapper.compute_nullifier();

        // Modify the balance
        balance.withdraw(self.amount);
        let new_amount_share = balance.state_wrapper.reencrypt_amount_share();

        // Compute a new recovery ID and commitment
        let recovery_id = balance.state_wrapper.compute_recovery_id();
        let new_balance_commitment = balance.state_wrapper.compute_commitment();

        let witness =
            ValidWithdrawalWitness { old_balance, old_balance_opening: balance_opening.into() };

        let withdrawal = self.build_withdrawal(&balance);
        let statement = ValidWithdrawalStatement {
            withdrawal,
            merkle_root: root,
            old_balance_nullifier: nullifier,
            new_balance_commitment,
            recovery_id,
            new_amount_share,
        };

        Ok((witness, statement, balance))
    }

    /// Build the withdrawal
    fn build_withdrawal(&self, bal: &Balance) -> Withdrawal {
        Withdrawal { token: bal.mint(), amount: self.amount, to: bal.owner() }
    }

    /// Get the balance from which to withdraw
    async fn get_balance(&self) -> Result<Balance> {
        let balance = self
            .state()
            .get_account_darkpool_balance(&self.account_id, &self.token)
            .await?
            .ok_or_else(|| WithdrawTaskError::State("balance not found".to_string()))?;
        Ok(balance)
    }

    /// Get a Merkle proof for the balance
    async fn get_balance_merkle_proof(&self) -> Result<MerkleAuthenticationPath> {
        let proof = self
            .state()
            .get_balance_merkle_proof(&self.account_id, &self.token)
            .await?
            .ok_or_else(|| {
                WithdrawTaskError::State("balance merkle proof not found".to_string())
            })?;
        Ok(proof)
    }
}
