//! Defines a task to cancel a public order

use std::fmt::{Display, Formatter, Result as FmtResult};

use async_trait::async_trait;
use darkpool_client::errors::DarkpoolClientError;
use renegade_solidity_abi::v2::IDarkpoolV2::{OrderCancellationAuth, SignatureWithNonce};
use serde::Serialize;
use state::{State, error::StateError};
use tracing::{info, instrument};
use types_account::{OrderId, order::PrivacyRing, order_auth::OrderAuth};
use types_core::AccountId;
use types_tasks::CancelOrderTaskDescriptor;

use crate::{
    hooks::{RefreshAccountHook, TaskHook},
    task_state::TaskStateWrapper,
    traits::{Descriptor, Task, TaskContext, TaskError, TaskState},
};

/// The task name for the cancel order task
const CANCEL_ORDER_TASK_NAME: &str = "cancel-order";

// --------------
// | Task State |
// --------------

/// Represents the state of the task through its async execution
#[derive(Clone, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum CancelOrderTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is submitting the cancellation transaction
    SubmittingCancellation,
    /// The task is updating the local state
    UpdatingLocalState,
    /// The task is completed
    Completed,
}

impl TaskState for CancelOrderTaskState {
    fn commit_point() -> Self {
        CancelOrderTaskState::SubmittingCancellation
    }

    fn completed(&self) -> bool {
        matches!(self, CancelOrderTaskState::Completed)
    }
}

impl Display for CancelOrderTaskState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            CancelOrderTaskState::Pending => write!(f, "Pending"),
            CancelOrderTaskState::SubmittingCancellation => write!(f, "SubmittingCancellation"),
            CancelOrderTaskState::UpdatingLocalState => write!(f, "UpdatingLocalState"),
            CancelOrderTaskState::Completed => write!(f, "Completed"),
        }
    }
}

impl From<CancelOrderTaskState> for TaskStateWrapper {
    fn from(state: CancelOrderTaskState) -> Self {
        TaskStateWrapper::CancelOrder(state)
    }
}

// ---------------
// | Task Errors |
// ---------------

/// The error type thrown by the cancel order task
#[derive(Clone, Debug, thiserror::Error)]
pub enum CancelOrderTaskError {
    /// An error interacting with the darkpool client
    #[error("darkpool client error: {0}")]
    DarkpoolClient(String),
    /// The order was not found
    #[error("order not found: {0}")]
    OrderNotFound(OrderId),
    /// The order is not a Ring0 (public) order
    #[error("invalid order type: expected Ring0, got {0:?}")]
    InvalidOrderType(PrivacyRing),
    /// Error interacting with global state
    #[error("state error: {0}")]
    State(String),
}

impl CancelOrderTaskError {
    /// Create a new darkpool client error
    #[allow(clippy::needless_pass_by_value)]
    pub fn darkpool_client<T: ToString>(msg: T) -> Self {
        Self::DarkpoolClient(msg.to_string())
    }

    /// Create a new state error
    #[allow(clippy::needless_pass_by_value)]
    pub fn state<T: ToString>(msg: T) -> Self {
        Self::State(msg.to_string())
    }
}

impl TaskError for CancelOrderTaskError {
    fn retryable(&self) -> bool {
        matches!(self, CancelOrderTaskError::DarkpoolClient(_))
    }
}

impl From<DarkpoolClientError> for CancelOrderTaskError {
    fn from(e: DarkpoolClientError) -> Self {
        CancelOrderTaskError::darkpool_client(e)
    }
}

impl From<StateError> for CancelOrderTaskError {
    fn from(e: StateError) -> Self {
        CancelOrderTaskError::state(e)
    }
}

/// A type alias for a result in this task
type Result<T> = std::result::Result<T, CancelOrderTaskError>;

// -------------------
// | Task Definition |
// -------------------

/// Represents a task to cancel a public order
#[derive(Clone)]
pub struct CancelOrderTask {
    /// The account ID that owns the order
    pub account_id: AccountId,
    /// The order ID to cancel
    pub order_id: OrderId,
    /// The order authorization
    pub order_auth: OrderAuth,
    /// The cancellation signature
    pub cancel_signature: SignatureWithNonce,
    /// The state of the task's execution
    pub task_state: CancelOrderTaskState,
    /// The context of the task
    pub ctx: TaskContext,
}

#[async_trait]
impl Task for CancelOrderTask {
    type State = CancelOrderTaskState;
    type Error = CancelOrderTaskError;
    type Descriptor = CancelOrderTaskDescriptor;

    async fn new(descriptor: Self::Descriptor, ctx: TaskContext) -> Result<Self> {
        Ok(Self {
            account_id: descriptor.account_id,
            order_id: descriptor.order_id,
            order_auth: descriptor.order_auth,
            cancel_signature: descriptor.cancel_signature,
            task_state: CancelOrderTaskState::Pending,
            ctx,
        })
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(skip_all, err, fields(task = %self.name(), state = %self.task_state()))]
    async fn step(&mut self) -> Result<()> {
        // Dispatch based on task state
        match self.task_state {
            CancelOrderTaskState::Pending => {
                self.task_state = CancelOrderTaskState::SubmittingCancellation;
            },
            CancelOrderTaskState::SubmittingCancellation => {
                self.submit_cancellation().await?;
                self.task_state = CancelOrderTaskState::UpdatingLocalState;
            },
            CancelOrderTaskState::UpdatingLocalState => {
                self.update_local_state().await?;
                self.task_state = CancelOrderTaskState::Completed;
            },
            CancelOrderTaskState::Completed => {
                unreachable!("step called on task in Completed state")
            },
        }

        Ok(())
    }

    fn name(&self) -> String {
        CANCEL_ORDER_TASK_NAME.to_string()
    }

    fn task_state(&self) -> Self::State {
        self.task_state.clone()
    }

    // Refresh the account after a failure
    fn failure_hooks(&self) -> Vec<Box<dyn TaskHook>> {
        let refresh = RefreshAccountHook::new(vec![self.account_id]);
        vec![Box::new(refresh)]
    }
}

impl Descriptor for CancelOrderTaskDescriptor {}

// -----------------------
// | Task Implementation |
// -----------------------

impl CancelOrderTask {
    /// Submit the cancellation transaction on-chain
    async fn submit_cancellation(&self) -> Result<()> {
        // Build the cancellation auth
        let auth = OrderCancellationAuth { signature: self.cancel_signature.clone() };

        // Submit the transaction
        let (permit, intent_signature) = self.order_auth.into_public();
        let receipt =
            self.ctx.darkpool_client.cancel_public_order(auth, permit, intent_signature).await?;

        info!("Submitted cancel_public_order tx: {:#x}", receipt.transaction_hash);
        Ok(())
    }

    /// Update the local state to remove the order
    async fn update_local_state(&self) -> Result<()> {
        let waiter = self.state().remove_order_from_account(self.account_id, self.order_id).await?;
        waiter.await.map_err(CancelOrderTaskError::state)?;

        info!("Removed order {} from account {}", self.order_id, self.account_id);
        Ok(())
    }
}

// -----------
// | Helpers |
// -----------

impl CancelOrderTask {
    /// Get a handle on the state
    fn state(&self) -> &State {
        &self.ctx.state
    }
}
