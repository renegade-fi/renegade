//! Defines a task to create an order

use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
};

use async_trait::async_trait;
use darkpool_types::{intent::Intent, state_wrapper::StateWrapper};
use serde::Serialize;
use state::error::StateError;
use tracing::instrument;
use types_account::order::Order;
use types_core::AccountId;
use types_tasks::CreateOrderTaskDescriptor;

use crate::{
    task_state::TaskStateWrapper,
    traits::{Descriptor, Task, TaskContext, TaskError, TaskState},
};

/// The task name for the create order task
const CREATE_ORDER_TASK_NAME: &str = "create-order";

// --------------
// | Task State |
// --------------

/// Represents the state of the task through its async execution
#[derive(Clone, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum CreateOrderTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is creating the order
    Creating,
    /// The task is completed
    Completed,
}

impl TaskState for CreateOrderTaskState {
    fn commit_point() -> Self {
        CreateOrderTaskState::Creating
    }

    fn completed(&self) -> bool {
        matches!(self, CreateOrderTaskState::Completed)
    }
}

impl Display for CreateOrderTaskState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            CreateOrderTaskState::Pending => write!(f, "Pending"),
            CreateOrderTaskState::Creating => write!(f, "Creating"),
            CreateOrderTaskState::Completed => write!(f, "Completed"),
        }
    }
}

impl From<CreateOrderTaskState> for TaskStateWrapper {
    fn from(state: CreateOrderTaskState) -> Self {
        TaskStateWrapper::CreateOrder(state)
    }
}

// ---------------
// | Task Errors |
// ---------------

/// The error type thrown by the create order task
#[derive(Clone, Debug)]
pub enum CreateOrderTaskError {
    /// Error interacting with global state
    State(String),
}

impl TaskError for CreateOrderTaskError {
    fn retryable(&self) -> bool {
        matches!(self, CreateOrderTaskError::State(_))
    }
}

impl Display for CreateOrderTaskError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{self:?}")
    }
}

impl Error for CreateOrderTaskError {}

impl From<StateError> for CreateOrderTaskError {
    fn from(e: StateError) -> Self {
        CreateOrderTaskError::State(e.to_string())
    }
}

/// A type alias for a result in this task
type Result<T> = std::result::Result<T, CreateOrderTaskError>;

// -------------------
// | Task Definition |
// -------------------

/// Represents a task to create an order
pub struct CreateOrderTask {
    /// The account ID creating the order
    pub account_id: AccountId,
    /// The order to create
    pub order: Order,
    /// The state of the task's execution
    pub task_state: CreateOrderTaskState,
    /// The context of the task
    pub ctx: TaskContext,
}

#[async_trait]
impl Task for CreateOrderTask {
    type State = CreateOrderTaskState;
    type Error = CreateOrderTaskError;
    type Descriptor = CreateOrderTaskDescriptor;

    async fn new(descriptor: Self::Descriptor, ctx: TaskContext) -> Result<Self> {
        // Construct StateWrapper<Intent> from the descriptor
        // TODO: Get seeds from account state or generate deterministically
        // The seeds should come from the account's CSPRNG state, not be randomly
        // generated For now, this is a placeholder that needs to be implemented
        // properly
        //
        // The proper implementation should:
        // 1. Get the account from state using descriptor.account_id
        // 2. Extract or generate seeds from the account's CSPRNG state
        // 3. Use those seeds to construct the StateWrapper<Intent>

        // Temporary: Using zero seeds as placeholder - this will need proper
        // implementation
        use constants::Scalar;
        let share_stream_seed = Scalar::zero();
        let recovery_stream_seed = Scalar::zero();

        let intent_wrapper =
            StateWrapper::new(descriptor.intent, share_stream_seed, recovery_stream_seed);
        let order = Order::new_with_ring(intent_wrapper, descriptor.metadata, descriptor.ring);

        Ok(Self {
            account_id: descriptor.account_id,
            order,
            task_state: CreateOrderTaskState::Pending,
            ctx,
        })
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(skip_all, err, fields(task = %self.name(), state = %self.task_state()))]
    async fn step(&mut self) -> Result<()> {
        // Dispatch based on task state
        match self.task_state {
            CreateOrderTaskState::Pending => {
                self.task_state = CreateOrderTaskState::Creating;
            },
            CreateOrderTaskState::Creating => {
                self.create_order().await?;
                self.task_state = CreateOrderTaskState::Completed;
            },
            CreateOrderTaskState::Completed => {
                unreachable!("step called on task in Completed state")
            },
        }

        Ok(())
    }

    fn name(&self) -> String {
        CREATE_ORDER_TASK_NAME.to_string()
    }

    fn task_state(&self) -> Self::State {
        self.task_state.clone()
    }
}

impl Descriptor for CreateOrderTaskDescriptor {}

// -----------------------
// | Task Implementation |
// -----------------------

impl CreateOrderTask {
    /// Create a new order
    pub async fn create_order(&self) -> Result<()> {
        tracing::info!("GOT TO CREATE ORDER");
        Ok(())
    }
}
