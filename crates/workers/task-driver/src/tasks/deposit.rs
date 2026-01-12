//! Defines a task to deposit into the darkpool

use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
};

use alloy::primitives::Address;
use async_trait::async_trait;
use circuit_types::Amount;
use renegade_solidity_abi::v2::IDarkpoolV2::DepositAuth;
use serde::Serialize;
use tracing::instrument;
use types_core::AccountId;
use types_tasks::DepositTaskDescriptor;

use crate::{
    task_state::StateWrapper,
    traits::{Descriptor, Task, TaskContext, TaskError, TaskState},
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
}

impl TaskError for DepositTaskError {
    fn retryable(&self) -> bool {
        matches!(self, DepositTaskError::DarkpoolClient(_))
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
            task_state: DepositTaskState::Pending,
            ctx,
        })
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(skip_all, err, fields(task = %self.name(), state = %self.state()))]
    async fn step(&mut self) -> Result<()> {
        // Dispatch based on task state
        match self.task_state {
            DepositTaskState::Pending => {
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
    /// Submit the deposit transaction to the darkpool
    pub async fn submit_deposit(&self) -> Result<()> {
        todo!()
    }
}
