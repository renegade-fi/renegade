//! Defines a task to deposit into the darkpool

use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
};

use alloy::primitives::Address;
use async_trait::async_trait;
use circuit_types::{Amount, primitives::schnorr::SchnorrPublicKey};
use circuits_core::zk_circuits::valid_deposit::{SizedValidDepositWitness, ValidDepositStatement};
use darkpool_types::deposit::Deposit;
use job_types::proof_manager::{ProofJob, ProofManagerResponse};
use renegade_solidity_abi::v2::IDarkpoolV2::DepositAuth;
use serde::Serialize;
use state::error::StateError;
use tracing::{info, instrument};
use types_account::keychain::KeyChain;
use types_core::AccountId;
use types_tasks::DepositTaskDescriptor;

use crate::{
    task_state::TaskStateWrapper,
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
    /// A state element was not found that is necessary for task execution
    Missing(String),
}

impl DepositTaskError {
    /// Create a new missing error
    #[allow(clippy::needless_pass_by_value)]
    pub fn missing<T: ToString>(msg: T) -> Self {
        Self::Missing(msg.to_string())
    }
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
    /// The authority public key
    pub authority: SchnorrPublicKey,
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
        Ok(Self {
            account_id: descriptor.account_id,
            from_address: descriptor.from_address,
            token: descriptor.token,
            amount: descriptor.amount,
            auth: descriptor.auth,
            authority: descriptor.authority,
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

    fn task_state(&self) -> Self::State {
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
        self.existing_balance_proof().await?;
        Ok(())
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

    /// Generate a proof for an existing balance deposit
    async fn existing_balance_proof(&mut self) -> Result<()> {
        let (witness, statement) = self.get_existing_balance_witness_statement().await?;
        let job = ProofJob::ValidDeposit { statement, witness };
        let proof_recv =
            enqueue_proof_job(job, &self.ctx).map_err(DepositTaskError::ProofGeneration)?;

        // Await the proof
        let bundle =
            proof_recv.await.map_err(|e| DepositTaskError::ProofGeneration(e.to_string()))?;
        self.proof_bundle = Some(bundle);
        Ok(())
    }

    /// Generate a witness and statement for an existing balance deposit
    async fn get_existing_balance_witness_statement(
        &self,
    ) -> Result<(SizedValidDepositWitness, ValidDepositStatement)> {
        todo!("Implement existing balance witness and statement generation")
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
