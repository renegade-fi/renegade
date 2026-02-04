//! Defines a task to withdraw a balance from the darkpool

use core::panic;
use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
};

use alloy::primitives::Address;
use async_trait::async_trait;
use circuit_types::Amount;
use serde::Serialize;
use tracing::{info, instrument};
use types_core::AccountId;
use types_tasks::WithdrawTaskDescriptor;

use crate::{
    hooks::TaskHook,
    task_state::TaskStateWrapper,
    traits::{Descriptor, Task, TaskContext, TaskError, TaskState},
};

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
#[derive(Clone, Debug)]
pub enum WithdrawTaskError {
    /// Error executing the withdrawal
    Withdraw(String),
}

impl TaskError for WithdrawTaskError {
    fn retryable(&self) -> bool {
        matches!(self, WithdrawTaskError::Withdraw(_))
    }
}

impl Display for WithdrawTaskError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{self:?}")
    }
}

impl Error for WithdrawTaskError {}

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
        panic!("Got to withdrawal");
        Ok(())
    }

    /// Submit the withdrawal transaction to the darkpool
    pub async fn submit_withdrawal(&self) -> Result<()> {
        info!("Submitting withdrawal...");
        // TODO: Implement withdrawal submission
        Ok(())
    }
}
