//! Defines a task to deposit into the darkpool

use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
};

use alloy::primitives::Address;
use async_trait::async_trait;
use circuit_types::Amount;
use circuits_core::zk_circuits::valid_balance_create::{
    ValidBalanceCreateStatement, ValidBalanceCreateWitness,
};
use job_types::proof_manager::{ProofJob, ProofManagerResponse};
use renegade_solidity_abi::v2::IDarkpoolV2::DepositAuth;
use serde::Serialize;
use state::error::StateError;
use tracing::{info, instrument};
use types_core::AccountId;
use types_tasks::DepositTaskDescriptor;

use crate::{
    task_state::StateWrapper,
    tasks::ERR_ACCOUNT_NOT_FOUND,
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
    /// The task is waiting for confirmation
    Confirming,
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
            DepositTaskState::Confirming => write!(f, "Confirming"),
            DepositTaskState::Completed => write!(f, "Completed"),
        }
    }
}

impl From<DepositTaskState> for StateWrapper {
    fn from(state: DepositTaskState) -> Self {
        StateWrapper::Deposit(state)
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
    /// A state element was not found that is necessary for task execution
    Missing(String),
}

impl TaskError for DepositTaskError {
    fn retryable(&self) -> bool {
        matches!(self, DepositTaskError::DarkpoolClient(_) | DepositTaskError::ProofGeneration(_))
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
    /// Whether or not the task must create a new balance
    pub must_create_balance: bool,
    /// A proof of `VALID DEPOSIT` created in the proving step
    pub proof_bundle: Option<ProofManagerResponse>,
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
        let mut this = Self {
            account_id: descriptor.account_id,
            from_address: descriptor.from_address,
            token: descriptor.token,
            amount: descriptor.amount,
            auth: descriptor.auth,
            must_create_balance: false,
            proof_bundle: None,
            task_state: DepositTaskState::Pending,
            ctx,
        };

        // Check if the balance must be created in the darkpool for the first time
        if this.should_create_balance().await? {
            this.must_create_balance = true;
        }
        Ok(this)
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(skip_all, err, fields(task = %self.name(), state = %self.state()))]
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
                self.submit_deposit().await?;
                self.task_state = DepositTaskState::Confirming;
            },
            DepositTaskState::Confirming => {
                // The deposit transaction has been submitted and confirmed
                // The receipt is already returned from submit_deposit
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

    fn state(&self) -> Self::State {
        self.task_state.clone()
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
        // Placeholder - actual implementation needed above
        Err(DepositTaskError::ProofGeneration("Proof generation not yet implemented".to_string()))
    }

    /// Submit the deposit transaction to the darkpool
    pub async fn submit_deposit(&self) -> Result<()> {
        // TODO: Use the proof_bundle when submitting
        // let proof = self.proof_bundle.as_ref()
        //     .ok_or_else(|| DepositTaskError::Missing("proof bundle not
        // found".to_string()))?;
        //
        // let tx = self.ctx.darkpool_client.deposit(
        //     self.auth.clone(),
        //     proof.clone(),
        // ).await?;
        //
        // // Store transaction receipt if needed
        // info!("Deposit transaction submitted: {:?}", tx);

        info!("Submitting deposit...");
        Ok(())
    }

    // --- Helpers --- //

    /// Generate a proof for a valid new balance statement
    async fn new_balance_proof(&mut self) -> Result<()> {
        let (witness, statement) = self.get_new_balance_witness_statement()?;
        let job = ProofJob::ValidBalanceCreate { statement, witness };
        let proof_recv =
            enqueue_proof_job(job, &self.ctx).map_err(DepositTaskError::ProofGeneration)?;

        // Await the proof
        let bundle =
            proof_recv.await.map_err(|e| DepositTaskError::ProofGeneration(e.to_string()))?;
        self.proof_bundle = Some(bundle);
        Ok(())
    }

    /// Generate a witness and statement for a valid new balance
    fn get_new_balance_witness_statement(
        &self,
    ) -> Result<(ValidBalanceCreateWitness, ValidBalanceCreateStatement)> {
        todo!()
    }
}

// -----------
// | Helpers |
// -----------

impl DepositTask {
    /// Whether or not this is a new balance
    pub async fn should_create_balance(&self) -> Result<bool> {
        let account = self
            .ctx
            .state
            .get_account(&self.account_id)
            .await?
            .ok_or_else(|| DepositTaskError::Missing(ERR_ACCOUNT_NOT_FOUND.to_string()))?;

        let has_balance = account.balances.contains_key(&self.token);
        Ok(has_balance)
    }
}
