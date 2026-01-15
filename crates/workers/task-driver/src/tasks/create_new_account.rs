//! Defines a task to create a new account

use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
};

use async_trait::async_trait;
use serde::Serialize;
use state::error::StateError;
use tracing::instrument;
use types_account::{Account, keychain::KeyChain};
use types_core::AccountId;
use types_tasks::NewAccountTaskDescriptor;

use crate::{
    task_state::TaskStateWrapper,
    traits::{Descriptor, Task, TaskContext, TaskError, TaskState},
};

/// The task name for the create new account task
const CREATE_NEW_ACCOUNT_TASK_NAME: &str = "create-new-account";

// --------------
// | Task State |
// --------------

/// Represents the state of the task through its async execution
#[derive(Clone, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum CreateNewAccountTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is creating the account
    Creating,
    /// The task is completed
    Completed,
}

impl TaskState for CreateNewAccountTaskState {
    fn commit_point() -> Self {
        CreateNewAccountTaskState::Creating
    }

    fn completed(&self) -> bool {
        matches!(self, CreateNewAccountTaskState::Completed)
    }
}

impl Display for CreateNewAccountTaskState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            CreateNewAccountTaskState::Pending => write!(f, "Pending"),
            CreateNewAccountTaskState::Creating => write!(f, "Creating"),
            CreateNewAccountTaskState::Completed => write!(f, "Completed"),
        }
    }
}

impl From<CreateNewAccountTaskState> for TaskStateWrapper {
    fn from(state: CreateNewAccountTaskState) -> Self {
        TaskStateWrapper::CreateNewAccount(state)
    }
}

// ---------------
// | Task Errors |
// ---------------

/// The error type thrown by the create new account task
#[derive(Clone, Debug)]
pub enum CreateNewAccountTaskError {
    /// Error interacting with global state
    State(String),
}

impl TaskError for CreateNewAccountTaskError {
    fn retryable(&self) -> bool {
        matches!(self, CreateNewAccountTaskError::State(_))
    }
}

impl Display for CreateNewAccountTaskError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{self:?}")
    }
}

impl Error for CreateNewAccountTaskError {}

impl From<StateError> for CreateNewAccountTaskError {
    fn from(e: StateError) -> Self {
        CreateNewAccountTaskError::State(e.to_string())
    }
}

/// A type alias for a result in this task
type Result<T> = std::result::Result<T, CreateNewAccountTaskError>;

// -------------------
// | Task Definition |
// -------------------

/// Represents a task to create a new account
pub struct CreateNewAccountTask {
    /// The account ID to create
    pub account_id: AccountId,
    /// The keychain for the account
    pub keychain: KeyChain,
    /// The state of the task's execution
    pub task_state: CreateNewAccountTaskState,
    /// The context of the task
    pub ctx: TaskContext,
}

#[async_trait]
impl Task for CreateNewAccountTask {
    type State = CreateNewAccountTaskState;
    type Error = CreateNewAccountTaskError;
    type Descriptor = NewAccountTaskDescriptor;

    async fn new(descriptor: Self::Descriptor, ctx: TaskContext) -> Result<Self> {
        Ok(Self {
            account_id: descriptor.account_id,
            keychain: descriptor.keychain,
            task_state: CreateNewAccountTaskState::Pending,
            ctx,
        })
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(skip_all, err, fields(task = %self.name(), state = %self.task_state()))]
    async fn step(&mut self) -> Result<()> {
        // Dispatch based on task state
        match self.task_state {
            CreateNewAccountTaskState::Pending => {
                self.task_state = CreateNewAccountTaskState::Creating;
            },
            CreateNewAccountTaskState::Creating => {
                self.create_account().await?;
                self.task_state = CreateNewAccountTaskState::Completed;
            },
            CreateNewAccountTaskState::Completed => {
                unreachable!("step called on task in Completed state")
            },
        }

        Ok(())
    }

    fn name(&self) -> String {
        CREATE_NEW_ACCOUNT_TASK_NAME.to_string()
    }

    fn task_state(&self) -> Self::State {
        self.task_state.clone()
    }
}

impl Descriptor for NewAccountTaskDescriptor {}

// -----------------------
// | Task Implementation |
// -----------------------

impl CreateNewAccountTask {
    /// Create a new account
    pub async fn create_account(&self) -> Result<()> {
        let acct = Account::new_empty_account(self.account_id, self.keychain.clone());
        let waiter = self.ctx.state.new_account(acct).await?;
        waiter.await?;

        Ok(())
    }
}
