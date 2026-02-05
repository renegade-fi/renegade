//! Defines a task to create a balance in the darkpool

use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
};

use alloy::primitives::Address;
use async_trait::async_trait;
use circuit_types::{Amount, primitives::schnorr::SchnorrPublicKey};
use circuits_core::zk_circuits::valid_balance_create::{
    ValidBalanceCreateStatement, ValidBalanceCreateWitness,
};
use constants::Scalar;
use darkpool_client::{DarkpoolClient, errors::DarkpoolClientError};
use darkpool_types::{balance::DarkpoolBalance, deposit::Deposit, state_wrapper::StateWrapper};
use job_types::proof_manager::ProofJob;
use renegade_solidity_abi::v2::IDarkpoolV2::DepositAuth;
use serde::Serialize;
use state::{State, error::StateError};
use tracing::{info, instrument};
use types_account::{balance::Balance, keychain::KeyChain};
use types_core::AccountId;
use types_proofs::ValidBalanceCreateBundle;
use types_tasks::CreateBalanceTaskDescriptor;

use crate::{
    hooks::{RefreshAccountHook, RunMatchingEngineForBalanceHook, TaskHook},
    task_state::TaskStateWrapper,
    traits::{Descriptor, Task, TaskContext, TaskError, TaskState},
    utils::{enqueue_proof_job, get_relayer_fee_addr},
};

/// The task name for the create balance task
const CREATE_BALANCE_TASK_NAME: &str = "create-balance";

// --------------
// | Task State |
// --------------

/// Represents the state of the task through its async execution
#[derive(Clone, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum CreateBalanceTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is generating a proof of `VALID BALANCE CREATE`
    Proving,
    /// The task is submitting the deposit transaction
    Submitting,
    /// The task is updating the raft state
    UpdatingState,
    /// The task is completed
    Completed,
}

impl TaskState for CreateBalanceTaskState {
    fn commit_point() -> Self {
        CreateBalanceTaskState::Proving
    }

    fn completed(&self) -> bool {
        matches!(self, CreateBalanceTaskState::Completed)
    }
}

impl Display for CreateBalanceTaskState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            CreateBalanceTaskState::Pending => write!(f, "Pending"),
            CreateBalanceTaskState::Proving => write!(f, "Proving"),
            CreateBalanceTaskState::Submitting => write!(f, "Submitting"),
            CreateBalanceTaskState::UpdatingState => write!(f, "UpdatingState"),
            CreateBalanceTaskState::Completed => write!(f, "Completed"),
        }
    }
}

impl From<CreateBalanceTaskState> for TaskStateWrapper {
    fn from(state: CreateBalanceTaskState) -> Self {
        TaskStateWrapper::CreateBalance(state)
    }
}

// ---------------
// | Task Errors |
// ---------------

/// The error type thrown by the create balance task
#[derive(Clone, Debug)]
pub enum CreateBalanceTaskError {
    /// Error interacting with darkpool client
    DarkpoolClient(String),
    /// Error generating a proof of `VALID BALANCE CREATE`
    ProofGeneration(String),
    /// A state element was not found that is necessary for task execution
    Missing(String),
}

impl CreateBalanceTaskError {
    /// Create a new missing error
    #[allow(clippy::needless_pass_by_value)]
    pub fn missing<T: ToString>(msg: T) -> Self {
        Self::Missing(msg.to_string())
    }
}

impl TaskError for CreateBalanceTaskError {
    fn retryable(&self) -> bool {
        matches!(
            self,
            CreateBalanceTaskError::DarkpoolClient(_) | CreateBalanceTaskError::ProofGeneration(_)
        )
    }
}

impl Display for CreateBalanceTaskError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{self:?}")
    }
}

impl Error for CreateBalanceTaskError {}

impl From<StateError> for CreateBalanceTaskError {
    fn from(e: StateError) -> Self {
        CreateBalanceTaskError::Missing(e.to_string())
    }
}

impl From<DarkpoolClientError> for CreateBalanceTaskError {
    fn from(e: darkpool_client::errors::DarkpoolClientError) -> Self {
        CreateBalanceTaskError::DarkpoolClient(e.to_string())
    }
}

/// A type alias for a result in this task
type Result<T> = std::result::Result<T, CreateBalanceTaskError>;

// -------------------
// | Task Definition |
// -------------------

/// Represents a task to create a balance in the darkpool
pub struct CreateBalanceTask {
    /// The account ID to create the balance for
    pub account_id: AccountId,
    /// The address to deposit from
    pub from_address: Address,
    /// The token address for the balance
    pub token: Address,
    /// The amount for the balance
    pub amount: Amount,
    /// The authority public key
    pub authority: SchnorrPublicKey,
    /// The deposit authorization
    pub auth: DepositAuth,
    /// The updated balance and keychain
    pub updated_balance_keychain: Option<(Balance, KeyChain)>,
    /// A proof of `VALID BALANCE CREATE` created in the proving step
    pub proof_bundle: Option<ValidBalanceCreateBundle>,
    /// The state of the task's execution
    pub task_state: CreateBalanceTaskState,
    /// The context of the task
    pub ctx: TaskContext,
}

#[async_trait]
impl Task for CreateBalanceTask {
    type State = CreateBalanceTaskState;
    type Error = CreateBalanceTaskError;
    type Descriptor = CreateBalanceTaskDescriptor;

    async fn new(descriptor: Self::Descriptor, ctx: TaskContext) -> Result<Self> {
        Ok(Self {
            account_id: descriptor.account_id,
            from_address: descriptor.from_address,
            token: descriptor.token,
            amount: descriptor.amount,
            authority: descriptor.authority,
            auth: descriptor.auth,
            updated_balance_keychain: None,
            proof_bundle: None,
            task_state: CreateBalanceTaskState::Pending,
            ctx,
        })
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(skip_all, err, fields(task = %self.name(), state = %self.task_state()))]
    async fn step(&mut self) -> Result<()> {
        // Dispatch based on task state
        match self.task_state {
            CreateBalanceTaskState::Pending => {
                self.task_state = CreateBalanceTaskState::Proving;
            },
            CreateBalanceTaskState::Proving => {
                // Generate a proof of `VALID BALANCE CREATE`
                self.generate_proof().await?;
                self.task_state = CreateBalanceTaskState::Submitting;
            },
            CreateBalanceTaskState::Submitting => {
                // Submit the deposit transaction to the darkpool
                self.submit_deposit().await?;
                self.task_state = CreateBalanceTaskState::UpdatingState;
            },
            CreateBalanceTaskState::UpdatingState => {
                // Update the raft state
                self.update_state().await?;
                self.task_state = CreateBalanceTaskState::Completed;
            },
            CreateBalanceTaskState::Completed => {
                unreachable!("step called on task in Completed state")
            },
        }

        Ok(())
    }

    fn name(&self) -> String {
        CREATE_BALANCE_TASK_NAME.to_string()
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

impl Descriptor for CreateBalanceTaskDescriptor {}

// -----------------------
// | Task Implementation |
// -----------------------

impl CreateBalanceTask {
    // --------------
    // | Task Steps |
    // --------------

    /// Generate a proof of `VALID BALANCE CREATE` for the balance
    pub async fn generate_proof(&mut self) -> Result<()> {
        info!("Generating balance create proof...");

        // Create a new balance and update the wallet keychain
        let (mut balance, keychain) = self.create_balance_and_update_keychain().await?;

        // Generate a witness and statement for a valid balance create
        // This method mutates the balance, so we store the updated balance only after
        // this method updates the balance and returns
        let (witness, statement) = self.get_balance_create_witness_statement(&mut balance).await?;
        self.updated_balance_keychain = Some((balance, keychain));

        // Forward to the proof manager
        let job = ProofJob::ValidBalanceCreate { statement, witness };
        let proof_recv =
            enqueue_proof_job(job, &self.ctx).map_err(CreateBalanceTaskError::ProofGeneration)?;

        // Await the proof
        let bundle =
            proof_recv.await.map_err(|e| CreateBalanceTaskError::ProofGeneration(e.to_string()))?;
        self.proof_bundle = Some(bundle.into());
        Ok(())
    }

    /// Generate a witness and statement for a valid balance create
    async fn get_balance_create_witness_statement(
        &self,
    ) -> Result<(ValidBalanceCreateWitness, ValidBalanceCreateStatement)> {
        // Fetch the account keychain
        let mut keychain = self.get_account_keychain().await?;
        let recovery_id_stream = keychain.sample_recovery_id_stream_seed();
        let share_stream = keychain.sample_share_stream_seed();

        let mut bal = self.create_balance(share_stream.seed, recovery_id_stream.seed).await?;
        let witness = ValidBalanceCreateWitness {
            initial_share_stream: share_stream,
            initial_recovery_stream: recovery_id_stream,
            balance: bal.inner().clone(),
        };

        let deposit = self.create_deposit();

        let recovery_id = bal.state_wrapper.compute_recovery_id();
        let balance_commitment = bal.state_wrapper.compute_commitment();
        let statement = ValidBalanceCreateStatement {
            deposit,
            balance_commitment,
            recovery_id,
            new_balance_share: bal.state_wrapper.public_share(),
        };
        Ok((witness, statement))
    }

    /// Submit the deposit transaction to the darkpool
    pub async fn submit_deposit(&self) -> Result<()> {
        let proof_bundle = self.proof_bundle.clone().unwrap();
        let commitment = proof_bundle.statement.balance_commitment;
        let receipt =
            self.darkpool_client().create_balance(self.auth.clone(), proof_bundle).await?;
        info!("Successfully created balance at tx: {:#x}", receipt.transaction_hash);

        // Parse a Merkle opening for the balance from the receipt
        let opening =
            self.darkpool_client().find_merkle_authentication_path_with_tx(commitment, &receipt)?;

        // Store the Merkle opening in state
        let waiter =
            self.state().add_balance_merkle_proof(self.account_id, self.token, opening).await?;
        waiter.await?;
        Ok(())
    }

    /// Update the account state with the new balance
    pub async fn update_state(&self) -> Result<()> {
        let (balance, keychain) = self.updated_balance_keychain.clone().unwrap();

        // Update the balance
        let waiter = self.state().update_account_balance(self.account_id, balance).await?;
        waiter.await?;

        // Update the keychain
        let waiter = self.state().update_account_keychain(self.account_id, keychain).await?;
        waiter.await?;

        Ok(())
    }
}

// -----------
// | Helpers |
// -----------

impl CreateBalanceTask {
    /// Get a reference to the state
    fn state(&self) -> &State {
        &self.ctx.state
    }

    /// Get a reference to the darkpool client
    fn darkpool_client(&self) -> &DarkpoolClient {
        &self.ctx.darkpool_client
    }

    /// Fetch the account's keychain
    async fn get_account_keychain(&self) -> Result<KeyChain> {
        self.ctx
            .state
            .get_account_keychain(&self.account_id)
            .await?
            .ok_or_else(|| CreateBalanceTaskError::Missing("keychain not found".to_string()))
    }

    /// Create a deposit for the descriptor
    fn create_deposit(&self) -> Deposit {
        Deposit::new(self.from_address, self.token, self.amount)
    }

    /// Create a balance for the descriptor
    async fn create_balance(
        &self,
        share_stream_seed: Scalar,
        recovery_stream_seed: Scalar,
    ) -> Result<Balance> {
        let fee_addr = get_relayer_fee_addr(&self.ctx).map_err(CreateBalanceTaskError::missing)?;
        let bal_inner =
            DarkpoolBalance::new(self.token, self.from_address, fee_addr, self.authority)
                .with_amount(self.amount);
        let state_wrapper = StateWrapper::new(bal_inner, share_stream_seed, recovery_stream_seed);
        let bal = Balance::new_darkpool(state_wrapper);
        Ok(bal)
    }

    /// Create a new balance and update the wallet keychain
    async fn create_balance_and_update_keychain(&self) -> Result<(Balance, KeyChain)> {
        // Read the current keychain
        let mut keychain = self.get_account_keychain().await?;
        let recovery_id_stream = keychain.sample_recovery_id_stream_seed();
        let share_stream = keychain.sample_share_stream_seed();

        // Create a new balance
        let balance = self.create_balance(share_stream.seed, recovery_id_stream.seed).await?;
        Ok((balance, keychain))
    }

    /// Generate a witness and statement for a valid balance create
    async fn get_balance_create_witness_statement(
        &self,
        bal: &mut Balance,
    ) -> Result<(ValidBalanceCreateWitness, ValidBalanceCreateStatement)> {
        let share_stream = bal.state_wrapper.get_original_share_stream();
        let recovery_id_stream = bal.state_wrapper.get_original_recovery_stream();
        let witness = ValidBalanceCreateWitness {
            initial_share_stream: share_stream,
            initial_recovery_stream: recovery_id_stream,
            balance: bal.inner().clone(),
        };

        let deposit = self.create_deposit();
        let recovery_id = bal.state_wrapper.compute_recovery_id();
        let balance_commitment = bal.state_wrapper.compute_commitment();

        let statement = ValidBalanceCreateStatement {
            deposit,
            balance_commitment,
            recovery_id,
            new_balance_share: bal.state_wrapper.public_share(),
        };
        Ok((witness, statement))
    }
}
