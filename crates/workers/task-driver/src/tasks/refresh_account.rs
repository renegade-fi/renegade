//! Defines a task to refresh an account's state from the indexer

use std::{
    collections::HashSet,
    fmt::{Display, Formatter, Result as FmtResult},
};

use alloy::primitives::Address;
use async_trait::async_trait;
use darkpool_client::errors::DarkpoolClientError;
use serde::Serialize;
use state::error::StateError;
use tracing::{info, instrument};
use types_account::{
    Account, OrderId, OrderRefreshData, keychain::KeyChain, order_auth::OrderAuth,
};
use types_core::AccountId;
use types_tasks::RefreshAccountTaskDescriptor;

use crate::{
    hooks::{RunMatchingEngineHook, TaskHook},
    task_state::TaskStateWrapper,
    traits::{Descriptor, Task, TaskContext, TaskError, TaskState},
    utils::fetch_eoa_balance,
    utils::indexer_client::{ApiPublicIntent, ApiStateObject, IndexerClientError},
};

/// The task name for the refresh account task
const REFRESH_ACCOUNT_TASK_NAME: &str = "refresh-account";

// --------------
// | Task State |
// --------------

/// Represents the state of the task through its async execution
#[derive(Clone, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RefreshAccountTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is ensuring the account exists
    EnsureAccountExists,
    /// The task is refreshing the account state from the indexer
    RefreshingState,
    /// The task is completed
    Completed,
}

impl TaskState for RefreshAccountTaskState {
    fn commit_point() -> Self {
        RefreshAccountTaskState::RefreshingState
    }

    fn completed(&self) -> bool {
        matches!(self, RefreshAccountTaskState::Completed)
    }
}

impl Display for RefreshAccountTaskState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            RefreshAccountTaskState::Pending => write!(f, "Pending"),
            RefreshAccountTaskState::EnsureAccountExists => write!(f, "EnsureAccountExists"),
            RefreshAccountTaskState::RefreshingState => write!(f, "RefreshingState"),
            RefreshAccountTaskState::Completed => write!(f, "Completed"),
        }
    }
}

impl From<RefreshAccountTaskState> for TaskStateWrapper {
    fn from(state: RefreshAccountTaskState) -> Self {
        TaskStateWrapper::RefreshAccount(state)
    }
}

// ---------------
// | Task Errors |
// ---------------

/// The error type thrown by the refresh account task
#[derive(Debug, thiserror::Error)]
pub enum RefreshAccountTaskError {
    /// An error converting types
    #[error("conversion error: {0}")]
    Conversion(String),
    /// An error interacting with the darkpool client
    #[error("darkpool client error: {0}")]
    DarkpoolClient(String),
    /// An error interacting with the indexer
    #[error("indexer error: {0}")]
    Indexer(#[from] IndexerClientError),
    /// Error interacting with global state
    #[error("state error: {0}")]
    State(#[from] StateError),
    /// Error getting relayer fee address
    #[error("{0}")]
    Setup(String),
}

impl RefreshAccountTaskError {
    /// Create a new conversion error
    #[allow(clippy::needless_pass_by_value)]
    pub fn conversion<T: ToString>(msg: T) -> Self {
        Self::Conversion(msg.to_string())
    }

    /// Create a new setup error
    #[allow(clippy::needless_pass_by_value)]
    pub fn setup<T: ToString>(msg: T) -> Self {
        Self::Setup(msg.to_string())
    }

    /// Create a new darkpool client error
    #[allow(clippy::needless_pass_by_value)]
    pub fn darkpool_client<T: ToString>(msg: T) -> Self {
        Self::DarkpoolClient(msg.to_string())
    }
}

impl From<DarkpoolClientError> for RefreshAccountTaskError {
    fn from(e: DarkpoolClientError) -> Self {
        RefreshAccountTaskError::darkpool_client(e)
    }
}

impl TaskError for RefreshAccountTaskError {
    fn retryable(&self) -> bool {
        matches!(
            self,
            RefreshAccountTaskError::Indexer(_) | RefreshAccountTaskError::DarkpoolClient(_)
        )
    }
}

/// A type alias for a result in this task
type Result<T> = std::result::Result<T, RefreshAccountTaskError>;

// -------------------
// | Task Definition |
// -------------------

/// Represents a task to refresh an account's state from the indexer
pub struct RefreshAccountTask {
    /// The account ID to refresh
    pub account_id: AccountId,
    /// The keychain for the account
    pub keychain: KeyChain,
    /// Tokens to refresh balances for in addition to those that appear
    /// in the wallet's active public intents.
    pub additional_tokens: Vec<Address>,
    /// The order IDs that were refreshed (for success hook)
    pub refreshed_order_ids: Vec<OrderId>,
    /// The state of the task's execution
    pub task_state: RefreshAccountTaskState,
    /// The context of the task
    pub ctx: TaskContext,
}

#[async_trait]
impl Task for RefreshAccountTask {
    type State = RefreshAccountTaskState;
    type Error = RefreshAccountTaskError;
    type Descriptor = RefreshAccountTaskDescriptor;

    async fn new(descriptor: Self::Descriptor, ctx: TaskContext) -> Result<Self> {
        Ok(Self {
            account_id: descriptor.account_id,
            keychain: descriptor.keychain,
            additional_tokens: descriptor.additional_tokens,
            refreshed_order_ids: Vec::new(),
            task_state: RefreshAccountTaskState::Pending,
            ctx,
        })
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(skip_all, err, fields(task = %self.name(), state = %self.task_state()))]
    async fn step(&mut self) -> Result<()> {
        // Dispatch based on task state
        match self.task_state {
            RefreshAccountTaskState::Pending => {
                self.task_state = RefreshAccountTaskState::EnsureAccountExists;
            },
            RefreshAccountTaskState::EnsureAccountExists => {
                self.ensure_account_exists().await?;
                self.task_state = RefreshAccountTaskState::RefreshingState;
            },
            RefreshAccountTaskState::RefreshingState => {
                self.refresh_state().await?;
                self.task_state = RefreshAccountTaskState::Completed;
            },
            RefreshAccountTaskState::Completed => {
                unreachable!("step called on task in Completed state")
            },
        }

        Ok(())
    }

    fn name(&self) -> String {
        REFRESH_ACCOUNT_TASK_NAME.to_string()
    }

    fn task_state(&self) -> Self::State {
        self.task_state.clone()
    }

    // Explicitly NOT using RefreshAccountHook as a failure hook
    fn failure_hooks(&self) -> Vec<Box<dyn TaskHook>> {
        vec![]
    }

    // Run the matching engine on all refreshed orders
    fn success_hooks(&self) -> Vec<Box<dyn TaskHook>> {
        if self.refreshed_order_ids.is_empty() {
            return vec![];
        }

        let hook = RunMatchingEngineHook::new(self.account_id, self.refreshed_order_ids.clone());
        vec![Box::new(hook)]
    }
}

impl Descriptor for RefreshAccountTaskDescriptor {}

// -----------------------
// | Task Implementation |
// -----------------------

impl RefreshAccountTask {
    /// Resolve the on-chain owner address for the wallet when no
    /// active intent is available to read the owner from. Reads any
    /// existing balance entry's `owner()`. Errors if the wallet has
    /// neither active intents nor any balance entries.
    async fn fetch_owner_for_account(&self) -> Result<Address> {
        let balances = self.ctx.state.get_account_balances(&self.account_id).await?;
        balances.first().map(|b| b.owner()).ok_or_else(|| {
            RefreshAccountTaskError::setup(format!(
                "cannot resolve owner for account {} — no active intents and no \
                 stored balances; cannot refresh `additional_tokens`",
                self.account_id
            ))
        })
    }

    /// Ensure the account exists, creating it if necessary
    async fn ensure_account_exists(&self) -> Result<()> {
        let state = &self.ctx.state;
        let exists = state.contains_account(&self.account_id).await?;

        if exists {
            info!("Account {} already exists", self.account_id);
            return Ok(());
        }

        // Create the account
        info!("Creating account {}", self.account_id);
        let account = Account::new_empty_account(self.account_id, self.keychain.clone());
        let waiter = state.new_account(account).await?;
        waiter.await?;

        Ok(())
    }

    /// Refresh the account state from the indexer
    async fn refresh_state(&mut self) -> Result<()> {
        // Query the indexer for the user's state
        let response = self.ctx.indexer_client.get_user_state(self.account_id).await?;

        // Filter to only public intents (ring 0 orders)
        let public_intents: Vec<ApiPublicIntent> = response
            .active_state_objects
            .into_iter()
            .filter_map(|obj| match obj {
                ApiStateObject::PublicIntent(intent) => Some(intent),
                _ => None,
            })
            .collect();

        // Early-return only when there's nothing to refresh: no active
        // intents and no caller-provided additional tokens. Without this
        // check the caller-provided-tokens path has no `owner` to query
        // (we currently derive it from the first intent).
        if public_intents.is_empty() && self.additional_tokens.is_empty() {
            info!(
                "No public intents and no additional tokens to refresh for account {}",
                self.account_id
            );
            return Ok(());
        }

        info!(
            "Found {} public intents and {} additional tokens to refresh for account {}",
            public_intents.len(),
            self.additional_tokens.len(),
            self.account_id
        );

        // Collect unique input tokens from the intents, then union with
        // caller-provided additional tokens. Caller-provided tokens let
        // a client force a balance refresh for tokens not currently
        // referenced by any intent (e.g. before placing the first order
        // against a freshly-deposited token).
        let mut input_tokens: HashSet<Address> =
            public_intents.iter().map(|intent| intent.order.input_token()).collect();
        for token in &self.additional_tokens {
            input_tokens.insert(*token);
        }

        // Resolve the on-chain owner address. Prefer the owner declared
        // by an existing intent; fall back to the wallet's stored
        // signer address when only `additional_tokens` was supplied.
        let owner = match public_intents.first() {
            Some(intent) => intent.order.intent.inner.owner,
            None => self.fetch_owner_for_account().await?,
        };

        // Refresh ring 0 balances for the unioned token set
        let mut balances = Vec::new();
        for token in input_tokens {
            if let Some(balance) = fetch_eoa_balance(&self.ctx, token, owner)
                .await
                .map_err(RefreshAccountTaskError::darkpool_client)?
            {
                balances.push(balance);
            }
        }

        // Convert public intents to orders with matching pool assignments and auth
        let orders: Vec<OrderRefreshData> = public_intents
            .iter()
            .map(|intent| {
                let intent_signature = intent.intent_signature.clone().into();

                let auth =
                    OrderAuth::PublicOrder { permit: intent.permit.clone(), intent_signature };

                Ok(OrderRefreshData {
                    order: intent.order.clone(),
                    matching_pool: intent.matching_pool.clone(),
                    auth,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        // Collect order IDs for the success hook
        self.refreshed_order_ids = orders.iter().map(|o| o.order.id).collect();

        // Propose the state transition
        info!("Proposing refresh with {} orders and {} balances", orders.len(), balances.len());

        let waiter = self.ctx.state.refresh_account(self.account_id, orders, balances).await?;

        waiter.await?;

        Ok(())
    }
}
