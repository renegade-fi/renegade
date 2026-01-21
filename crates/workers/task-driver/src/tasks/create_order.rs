//! Defines a task to create an order

use std::fmt::{Display, Formatter, Result as FmtResult};

use async_trait::async_trait;
use constants::Scalar;
use darkpool_types::intent::{DarkpoolStateIntent, Intent};
use serde::Serialize;
use state::{State, error::StateError};
use tracing::instrument;
use types_account::{
    order::{Order, OrderMetadata, PrivacyRing},
    order_auth::OrderAuth,
};
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
#[derive(Clone, Debug, thiserror::Error)]
pub enum CreateOrderTaskError {
    /// The descriptor is invalid
    #[error("invalid descriptor: {0}")]
    InvalidDescriptor(String),
    /// Error interacting with global state
    #[error("state error: {0}")]
    State(String),
}

impl CreateOrderTaskError {
    /// Create a new invalid descriptor error
    #[allow(clippy::needless_pass_by_value)]
    pub fn invalid_descriptor<T: ToString>(msg: T) -> Self {
        Self::InvalidDescriptor(msg.to_string())
    }

    /// Create a new state error
    #[allow(clippy::needless_pass_by_value)]
    pub fn state<T: ToString>(msg: T) -> Self {
        Self::State(msg.to_string())
    }
}

impl TaskError for CreateOrderTaskError {
    fn retryable(&self) -> bool {
        matches!(self, CreateOrderTaskError::State(_))
    }
}

impl From<StateError> for CreateOrderTaskError {
    fn from(e: StateError) -> Self {
        CreateOrderTaskError::state(e)
    }
}

/// A type alias for a result in this task
type Result<T> = std::result::Result<T, CreateOrderTaskError>;

// -------------------
// | Task Definition |
// -------------------

/// Represents a task to create an order
#[derive(Clone)]
pub struct CreateOrderTask {
    /// The account ID creating the order
    pub account_id: AccountId,
    /// The intent to create an order for
    pub intent: Intent,
    /// The privacy ring in which the intent is allocated
    pub ring: PrivacyRing,
    /// The metadata for the order
    pub metadata: OrderMetadata,
    /// The order authorization
    pub auth: OrderAuth,
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
        let ring = descriptor.ring;
        if !matches!(ring, PrivacyRing::Ring0) {
            let msg = format!("ring must be Ring0, got {ring:?}");
            return Err(CreateOrderTaskError::invalid_descriptor(msg));
        }

        Ok(Self {
            account_id: descriptor.account_id,
            intent: descriptor.intent,
            ring: descriptor.ring,
            metadata: descriptor.metadata,
            auth: descriptor.auth,
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
        let CreateOrderTask { intent, ring, metadata, auth, account_id, .. } = self.clone();

        // Create the order in the state
        let state_intent = create_ring0_state_wrapper(intent);
        let order = Order::new_with_ring(state_intent, metadata, ring);
        let waiter = self.state().add_order_to_account(account_id, order, auth).await?;
        waiter.await.map_err(CreateOrderTaskError::state).map(|_| ())
    }
}

// -----------
// | Helpers |
// -----------

impl CreateOrderTask {
    /// Get a handle on the state
    fn state(&self) -> &State {
        &self.ctx.state
    }
}

/// Create a state wrapper for a ring 0 intent
///
/// A ring 0 intent does not have secret share or a recovery id stream, so we
/// use the default stream seeds.
fn create_ring0_state_wrapper(intent: Intent) -> DarkpoolStateIntent {
    let share_stream_seed = Scalar::zero();
    let recovery_stream_seed = Scalar::zero();
    DarkpoolStateIntent::new(intent, share_stream_seed, recovery_stream_seed)
}
