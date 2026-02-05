//! Defines a task to create an order

use std::fmt::{Display, Formatter, Result as FmtResult};

use alloy::{primitives::keccak256, sol_types::SolValue};
use async_trait::async_trait;
use constants::Scalar;
use darkpool_client::errors::DarkpoolClientError;
use darkpool_types::{
    intent::{DarkpoolStateIntent, Intent},
    state_wrapper::StateWrapper,
};
use serde::Serialize;
use state::{State, error::StateError};
use tracing::{info, instrument, warn};
use types_account::{
    MatchingPoolName, OrderId,
    balance::BalanceLocation,
    order::{Order, OrderMetadata, PrivacyRing},
    order_auth::OrderAuth,
};
use types_core::AccountId;
use types_tasks::CreateOrderTaskDescriptor;

use crate::{
    hooks::{RefreshAccountHook, RunMatchingEngineHook, TaskHook},
    task_state::TaskStateWrapper,
    traits::{Descriptor, Task, TaskContext, TaskError, TaskState},
    utils::{
        fetch_ring0_balance,
        indexer_client::{Message, PublicIntentMetadataUpdateMessage},
    },
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
    /// The task is checking for a balance on-chain approved to the darkpool
    CheckingAllowance,
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
            CreateOrderTaskState::CheckingAllowance => write!(f, "CheckingAllowance"),
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
    /// An error interacting with the darkpool client
    #[error("darkpool client error: {0}")]
    DarkpoolClient(String),
    /// The descriptor is invalid
    #[error("invalid descriptor: {0}")]
    InvalidDescriptor(String),
    /// Error interacting with global state
    #[error("state error: {0}")]
    State(String),
}

impl CreateOrderTaskError {
    /// Create a new darkpool client error
    #[allow(clippy::needless_pass_by_value)]
    pub fn darkpool_client<T: ToString>(msg: T) -> Self {
        Self::DarkpoolClient(msg.to_string())
    }

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

impl From<DarkpoolClientError> for CreateOrderTaskError {
    fn from(e: DarkpoolClientError) -> Self {
        CreateOrderTaskError::darkpool_client(e)
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
    /// The order ID for the new order
    pub order_id: OrderId,
    /// The intent to create an order for
    pub intent: Intent,
    /// The privacy ring in which the intent is allocated
    pub ring: PrivacyRing,
    /// The metadata for the order
    pub metadata: OrderMetadata,
    /// The order authorization
    pub auth: OrderAuth,
    /// The matching pool to assign the order to
    pub matching_pool: MatchingPoolName,
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
            order_id: descriptor.order_id,
            intent: descriptor.intent,
            ring: descriptor.ring,
            metadata: descriptor.metadata,
            auth: descriptor.auth,
            matching_pool: descriptor.matching_pool,
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
                self.task_state = CreateOrderTaskState::CheckingAllowance;
            },
            CreateOrderTaskState::CheckingAllowance => {
                self.check_allowance().await?;
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

    // Refresh the account after a failure
    fn failure_hooks(&self) -> Vec<Box<dyn TaskHook>> {
        let refresh = RefreshAccountHook::new(vec![self.account_id]);
        vec![Box::new(refresh)]
    }

    // Run the matching engine on the order after a successful creation
    fn success_hooks(&self) -> Vec<Box<dyn TaskHook>> {
        let run_matching_engine = RunMatchingEngineHook::new(self.account_id, vec![self.order_id]);
        vec![Box::new(run_matching_engine)]
    }
}

impl Descriptor for CreateOrderTaskDescriptor {}

// -----------------------
// | Task Implementation |
// -----------------------

impl CreateOrderTask {
    /// Create a new order
    pub async fn create_order(&self) -> Result<()> {
        let CreateOrderTask {
            order_id,
            account_id,
            intent,
            ring,
            metadata,
            auth,
            matching_pool,
            ..
        } = self.clone();

        // Create the order in the state
        let state_intent = create_ring0_state_wrapper(intent);
        let order = Order::new_with_ring(order_id, state_intent, metadata, ring);
        let waiter =
            self.state().add_order_to_account(account_id, order, auth, matching_pool).await?;
        waiter.await.map_err(CreateOrderTaskError::state).map(|_| ())
    }

    /// Check for a balance on-chain approved to the darkpool
    pub async fn check_allowance(&self) -> Result<()> {
        // First, check if a balance already exists for the input token
        // If a balance does exist, we can assume that the on-chain event listener will
        // keep its value up to date as new permits and erc20 transfers happen
        let in_token = self.intent.in_token;
        let state = self.state();
        let loc = BalanceLocation::EOA;
        let bal = state.get_account_balance_value(&self.account_id, &in_token, loc).await?;
        if bal > 0 {
            return Ok(());
        }

        // Otherwise, we need to check for an existing allowance on-chain
        let owner = self.intent.owner;
        let balance = fetch_ring0_balance(&self.ctx, in_token, owner)
            .await
            .map_err(CreateOrderTaskError::darkpool_client)?;

        // Update the account balance if we found a usable balance
        if let Some(bal) = balance {
            info!("Found usable balance on chain, updating account balance");
            let waiter = self.state().update_account_balance(self.account_id, bal).await?;
            waiter.await.map_err(CreateOrderTaskError::state)?;
        }

        self.send_indexer_message().await;
        Ok(())
    }

    /// Send an indexer message to update public intent metadata
    async fn send_indexer_message(&self) {
        // Only send for public orders for now
        let (permit, intent_signature) = match &self.auth {
            OrderAuth::PublicOrder { permit, intent_signature } => (permit, intent_signature),
            _ => return,
        };

        // Compute intent hash
        let intent_hash = keccak256(permit.abi_encode());

        let intent_signature_api = intent_signature.clone().into();

        let message = PublicIntentMetadataUpdateMessage {
            intent_hash,
            intent: self.intent.clone(),
            intent_signature: intent_signature_api,
            permit: permit.clone(),
            order_id: self.order_id,
            matching_pool: self.matching_pool.clone(),
            allow_external_matches: self.metadata.allow_external_matches,
            min_fill_size: self.metadata.min_fill_size,
        };

        let msg = Message::UpdatePublicIntentMetadata(message);
        if let Err(e) = self.ctx.indexer_client.submit_message(msg).await {
            warn!("Failed to send indexer message: {e}");
        }
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
fn create_ring0_state_wrapper(intent: Intent) -> StateWrapper<Intent> {
    let share_stream_seed = Scalar::zero();
    let recovery_stream_seed = Scalar::zero();
    DarkpoolStateIntent::new(intent, share_stream_seed, recovery_stream_seed)
}
