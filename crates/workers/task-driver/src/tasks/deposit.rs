//! Defines a task to deposit into the darkpool

use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
};

use alloy::primitives::Address;
use async_trait::async_trait;
use circuit_types::{Amount, primitives::schnorr::SchnorrPublicKey};
use circuits_core::zk_circuits::valid_deposit::{
    SizedValidDepositWitness, ValidDepositStatement, ValidDepositWitness,
};
use darkpool_client::DarkpoolClient;
use darkpool_types::deposit::Deposit;
use job_types::proof_manager::ProofJob;
use renegade_solidity_abi::v2::IDarkpoolV2::DepositAuth;
use serde::Serialize;
use state::{State, error::StateError};
use tracing::{info, instrument};
use types_account::{MerkleAuthenticationPath, balance::Balance};
use types_core::AccountId;
use types_proofs::ValidDepositBundle;
use types_tasks::DepositTaskDescriptor;

use crate::{
    hooks::{RefreshAccountHook, RunMatchingEngineForBalanceHook, TaskHook},
    task_state::TaskStateWrapper,
    tasks::validity_proofs::balance_update::refresh_validity_proofs_for_updated_balance,
    traits::{Descriptor, Task, TaskContext, TaskError, TaskState},
    utils::enqueue_proof_job,
};

/// The task name for the deposit task
const DEPOSIT_TASK_NAME: &str = "deposit";

// --------------
// | Task State |
// --------------

/// Represents the state of the task through its async execution
#[derive(Clone, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum DepositTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is generating a proof of `VALID DEPOSIT`
    Proving,
    /// The task is submitting the deposit transaction
    Submitting,
    /// The task is updating the relayer state
    UpdatingState,
    /// The task is updating validity proofs for affected Ring 2/3 orders
    UpdatingValidityProofs,
    /// The task is completed
    Completed,
}

impl TaskState for DepositTaskState {
    fn commit_point() -> Self {
        DepositTaskState::Submitting
    }

    fn completed(&self) -> bool {
        matches!(self, DepositTaskState::Completed)
    }
}

impl Display for DepositTaskState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            DepositTaskState::Pending => write!(f, "Pending"),
            DepositTaskState::Proving => write!(f, "Proving"),
            DepositTaskState::Submitting => write!(f, "Submitting"),
            DepositTaskState::UpdatingState => write!(f, "UpdatingState"),
            DepositTaskState::UpdatingValidityProofs => write!(f, "UpdatingValidityProofs"),
            DepositTaskState::Completed => write!(f, "Completed"),
        }
    }
}

impl From<DepositTaskState> for TaskStateWrapper {
    fn from(state: DepositTaskState) -> Self {
        TaskStateWrapper::Deposit(state)
    }
}

// ---------------
// | Task Errors |
// ---------------

/// The error type thrown by the deposit task
#[derive(Clone, Debug)]
pub enum DepositTaskError {
    /// Error interacting with darkpool client
    DarkpoolClient(String),
    /// Error generating a proof of `VALID DEPOSIT`
    ProofGeneration(String),
    /// Error updating validity proofs affected by this balance update
    ValidityProof(String),
    /// A state element was not found that is necessary for task execution
    Missing(String),
}

impl DepositTaskError {
    /// Error generating a proof of `VALID DEPOSIT`
    #[allow(clippy::needless_pass_by_value)]
    pub fn proof_generation<T: ToString>(msg: T) -> Self {
        Self::ProofGeneration(msg.to_string())
    }
}

impl DepositTaskError {
    /// Create a new missing error
    #[allow(clippy::needless_pass_by_value)]
    pub fn missing<T: ToString>(msg: T) -> Self {
        Self::Missing(msg.to_string())
    }

    /// Create a new validity proof update error
    #[allow(clippy::needless_pass_by_value)]
    pub fn validity_proof<T: ToString>(msg: T) -> Self {
        Self::ValidityProof(msg.to_string())
    }
}

impl TaskError for DepositTaskError {
    fn retryable(&self) -> bool {
        matches!(
            self,
            DepositTaskError::DarkpoolClient(_)
                | DepositTaskError::ProofGeneration(_)
                | DepositTaskError::ValidityProof(_)
        )
    }
}

impl Display for DepositTaskError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{self:?}")
    }
}

impl Error for DepositTaskError {}

impl From<darkpool_client::errors::DarkpoolClientError> for DepositTaskError {
    fn from(e: darkpool_client::errors::DarkpoolClientError) -> Self {
        DepositTaskError::DarkpoolClient(e.to_string())
    }
}

impl From<StateError> for DepositTaskError {
    fn from(e: StateError) -> Self {
        DepositTaskError::Missing(e.to_string())
    }
}

/// A type alias for a result in this task
type Result<T> = std::result::Result<T, DepositTaskError>;

// -------------------
// | Task Definition |
// -------------------

/// Represents a task to deposit into the darkpool
pub struct DepositTask {
    /// The account ID to deposit into
    pub account_id: AccountId,
    /// The address to deposit from
    pub from_address: Address,
    /// The token address to deposit
    pub token: Address,
    /// The amount to deposit
    pub amount: Amount,
    /// The deposit authorization
    pub auth: DepositAuth,
    /// The authority public key
    pub authority: SchnorrPublicKey,
    /// The updated balance after the deposit
    pub updated_balance: Option<Balance>,
    /// A proof of `VALID DEPOSIT` created in the proving step
    pub proof_bundle: Option<ValidDepositBundle>,
    /// The state of the task's execution
    pub task_state: DepositTaskState,
    /// The context of the task
    pub ctx: TaskContext,
}

#[async_trait]
impl Task for DepositTask {
    type State = DepositTaskState;
    type Error = DepositTaskError;
    type Descriptor = DepositTaskDescriptor;

    async fn new(descriptor: Self::Descriptor, ctx: TaskContext) -> Result<Self> {
        Ok(Self {
            account_id: descriptor.account_id,
            from_address: descriptor.from_address,
            token: descriptor.token,
            amount: descriptor.amount,
            auth: descriptor.auth,
            authority: descriptor.authority,
            updated_balance: None,
            proof_bundle: None,
            task_state: DepositTaskState::Pending,
            ctx,
        })
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(skip_all, err, fields(task = %self.name(), state = %self.task_state()))]
    async fn step(&mut self) -> Result<()> {
        // Dispatch based on task state
        match self.task_state {
            DepositTaskState::Pending => {
                self.task_state = DepositTaskState::Proving;
            },
            DepositTaskState::Proving => {
                // Generate a proof of `VALID DEPOSIT`
                self.generate_proof().await?;
                self.task_state = DepositTaskState::Submitting;
            },
            DepositTaskState::Submitting => {
                // Submit the deposit transaction to the darkpool
                self.submit_deposit().await?;
                self.task_state = DepositTaskState::UpdatingState;
            },
            DepositTaskState::UpdatingState => {
                // Update the relayer state with the new balance
                self.update_state().await?;
                self.task_state = DepositTaskState::UpdatingValidityProofs;
            },
            DepositTaskState::UpdatingValidityProofs => {
                self.update_validity_proofs().await?;
                self.task_state = DepositTaskState::Completed;
            },
            DepositTaskState::Completed => {
                unreachable!("step called on task in Completed state")
            },
        }

        Ok(())
    }

    fn name(&self) -> String {
        DEPOSIT_TASK_NAME.to_string()
    }

    fn task_state(&self) -> Self::State {
        self.task_state.clone()
    }

    fn failure_hooks(&self) -> Vec<Box<dyn TaskHook>> {
        let refresh = RefreshAccountHook::new(vec![self.account_id]);
        vec![Box::new(refresh)]
    }

    fn success_hooks(&self) -> Vec<Box<dyn TaskHook>> {
        let run_matching = RunMatchingEngineForBalanceHook::new(self.account_id, self.token);
        vec![Box::new(run_matching)]
    }
}

impl Descriptor for DepositTaskDescriptor {}

// -----------------------
// | Task Implementation |
// -----------------------

impl DepositTask {
    // --------------
    // | Task Steps |
    // --------------

    /// Generate a proof of `VALID DEPOSIT` for the deposit
    pub async fn generate_proof(&mut self) -> Result<()> {
        info!("Generating deposit proof...");
        let (witness, statement, updated_balance) =
            self.get_valid_deposit_witness_statement().await?;
        self.updated_balance = Some(updated_balance);

        let job = ProofJob::ValidDeposit { statement, witness };
        let proof_recv =
            enqueue_proof_job(job, &self.ctx).map_err(DepositTaskError::ProofGeneration)?;

        // Await the proof
        let bundle = proof_recv.await.map_err(DepositTaskError::proof_generation)?;
        self.proof_bundle = Some(bundle.into());
        Ok(())
    }

    /// Submit the deposit transaction to the darkpool
    pub async fn submit_deposit(&self) -> Result<()> {
        // Submit the deposit transaction to the darkpool
        info!("Submitting deposit...");
        let proof_bundle = self
            .proof_bundle
            .clone()
            .ok_or_else(|| DepositTaskError::Missing("proof bundle not found".to_string()))?;

        let commitment = proof_bundle.statement.new_balance_commitment;
        let receipt = self.darkpool_client().deposit(self.auth.clone(), proof_bundle).await?;

        // Parse a Merkle opening for the balance from the receipt
        let opening =
            self.darkpool_client().find_merkle_authentication_path_with_tx(commitment, &receipt)?;

        // Store the Merkle opening in state
        let waiter =
            self.state().add_balance_merkle_proof(self.account_id, self.token, opening).await?;
        waiter.await?;
        Ok(())
    }

    /// Update the relayer state with the post-deposit balance
    pub async fn update_state(&self) -> Result<()> {
        info!("Updating relayer state after deposit...");
        let balance = self
            .updated_balance
            .clone()
            .ok_or_else(|| DepositTaskError::Missing("updated balance not found".to_string()))?;

        let waiter = self.state().update_account_balance(self.account_id, balance).await?;
        waiter.await?;

        Ok(())
    }

    /// Refresh validity proofs for affected Ring 2/3 orders
    pub async fn update_validity_proofs(&self) -> Result<()> {
        refresh_validity_proofs_for_updated_balance(self.account_id, self.token, &self.ctx)
            .await
            .map_err(DepositTaskError::validity_proof)
    }

    // --- Helpers --- //

    /// Generate a witness and statement for an existing balance deposit
    ///
    /// Returns the witness, statement, and the updated balance after the
    /// deposit has been applied.
    async fn get_valid_deposit_witness_statement(
        &self,
    ) -> Result<(SizedValidDepositWitness, ValidDepositStatement, Balance)> {
        // Get the balance and its Merkle proof
        let mut balance = self.get_balance().await?;
        let old_balance = balance.state_wrapper.clone();
        let balance_opening = self.get_balance_merkle_proof().await?;
        let merkle_root = balance_opening.compute_root();
        let old_balance_nullifier = balance.state_wrapper.compute_nullifier();

        // Add the deposit amount to the balance
        *balance.amount_mut() += self.amount;
        let new_amount_share = balance.state_wrapper.reencrypt_amount_share();

        // Compute a new recovery ID and commitment
        let recovery_id = balance.state_wrapper.compute_recovery_id();
        let new_balance_commitment = balance.state_wrapper.compute_commitment();

        // Build the witness
        let witness =
            ValidDepositWitness { old_balance, old_balance_opening: balance_opening.into() };

        // Build the statement
        let deposit = self.create_deposit();
        let statement = ValidDepositStatement {
            deposit,
            merkle_root,
            old_balance_nullifier,
            new_balance_commitment,
            recovery_id,
            new_amount_share,
        };

        Ok((witness, statement, balance))
    }

    // --- State Access Helpers --- //

    /// Get a reference to the relayer state
    fn state(&self) -> &State {
        &self.ctx.state
    }

    /// Get a reference to the darkpool client
    fn darkpool_client(&self) -> &DarkpoolClient {
        &self.ctx.darkpool_client
    }

    /// Get the balance to deposit into
    async fn get_balance(&self) -> Result<Balance> {
        let balance = self
            .state()
            .get_account_darkpool_balance(&self.account_id, &self.token)
            .await?
            .ok_or_else(|| DepositTaskError::missing("balance not found"))?;
        Ok(balance)
    }

    /// Get a Merkle proof for the balance
    async fn get_balance_merkle_proof(&self) -> Result<MerkleAuthenticationPath> {
        let proof = self
            .state()
            .get_balance_merkle_proof(&self.account_id, &self.token)
            .await?
            .ok_or_else(|| DepositTaskError::missing("balance merkle proof not found"))?;
        Ok(proof)
    }
}

// -----------
// | Helpers |
// -----------

impl DepositTask {
    /// Create a deposit for the descriptor
    fn create_deposit(&self) -> Deposit {
        Deposit::new(self.from_address, self.token, self.amount)
    }
}
