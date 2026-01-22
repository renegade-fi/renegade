//! Defines execution hooks for the task driver

use alloy::primitives::Address;
use async_trait::async_trait;
use itertools::Itertools;
use job_types::matching_engine::MatchingEngineWorkerJob;
use tracing::info;
use types_account::OrderId;
use types_core::AccountId;

use crate::traits::TaskContext;

/// A task hook is a function that is called in the task execution flow. It may
/// operate on the task context asynchronously to perform some action
#[async_trait]
pub trait TaskHook: Send + Sync {
    /// The name of the task hook
    fn description(&self) -> String;
    /// Run the task hook
    async fn run(&self, ctx: &TaskContext) -> Result<(), TaskHookError>;
}

/// An error type for task hooks
#[derive(thiserror::Error, Debug)]
pub enum TaskHookError {
    /// The hook failed to execute
    #[error("Hook execution failed: {0}")]
    ExecutionFailed(String),
}

impl TaskHookError {
    /// Create a new task hook error
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn execution<T: ToString>(message: T) -> Self {
        Self::ExecutionFailed(message.to_string())
    }
}

// ------------------------
// | Hook Implementations |
// ------------------------

// --- Matching Engine Hook --- //

/// A hook to run the matching engine on the given orders
pub struct RunMatchingEngineHook {
    /// The orders to run the matching engine on
    pub orders: Vec<OrderId>,
}

impl RunMatchingEngineHook {
    /// Create a new run matching engine hook
    pub fn new(orders: Vec<OrderId>) -> Self {
        Self { orders }
    }
}

#[async_trait]
impl TaskHook for RunMatchingEngineHook {
    fn description(&self) -> String {
        let orders = self.orders.iter().map(|o| o.to_string()).collect_vec().join(", ");
        format!("run matching engine on orders: {orders}")
    }

    async fn run(&self, ctx: &TaskContext) -> Result<(), TaskHookError> {
        for order in self.orders.iter().copied() {
            let job = MatchingEngineWorkerJob::run_internal_engine(order);
            ctx.matching_engine_queue.clone().send(job).map_err(TaskHookError::execution)?;
        }

        Ok(())
    }
}

// --- Matching Engine For Balance Hook --- //

/// A hook to run the matching engine on orders affected by a balance update
///
/// This hook queries the state for orders that use the given token as input
/// and runs the matching engine on each of them
pub struct RunMatchingEngineForBalanceHook {
    /// The account ID whose balance was updated
    pub account_id: AccountId,
    /// The token that was updated
    pub token: Address,
}

impl RunMatchingEngineForBalanceHook {
    /// Create a new run matching engine for balance hook
    pub fn new(account_id: AccountId, token: Address) -> Self {
        Self { account_id, token }
    }
}

#[async_trait]
impl TaskHook for RunMatchingEngineForBalanceHook {
    fn description(&self) -> String {
        format!(
            "run matching engine for balance update: account={}, token={}",
            self.account_id, self.token
        )
    }

    async fn run(&self, ctx: &TaskContext) -> Result<(), TaskHookError> {
        // Query orders using this token as input
        let order_ids = ctx
            .state
            .get_orders_with_input_token(&self.account_id, &self.token)
            .await
            .map_err(TaskHookError::execution)?;

        info!(
            "running matching engine on {} orders for balance update (account={}, token={})",
            order_ids.len(),
            self.account_id,
            self.token
        );

        // Queue matching jobs for each order
        for order_id in order_ids {
            let job = MatchingEngineWorkerJob::run_internal_engine(order_id);
            ctx.matching_engine_queue.clone().send(job).map_err(TaskHookError::execution)?;
        }

        Ok(())
    }
}

// --- Refresh Account Hook --- //

/// A hook to refresh the given accounts after a task has failed
pub struct RefreshAccountHook {
    /// The accounts to refresh
    pub account_ids: Vec<AccountId>,
}

impl RefreshAccountHook {
    /// Create a new refresh account hook
    pub fn new(account_ids: Vec<AccountId>) -> Self {
        Self { account_ids }
    }
}

#[async_trait]
impl TaskHook for RefreshAccountHook {
    fn description(&self) -> String {
        let accounts = self.account_ids.iter().map(|a| a.to_string()).collect_vec().join(", ");
        format!("refresh accounts: {accounts}")
    }

    async fn run(&self, ctx: &TaskContext) -> Result<(), TaskHookError> {
        // Append an account refresh task for the given accounts
        for account_id in self.account_ids.iter().copied() {
            let task_id = ctx
                .state
                .append_account_refresh_task(account_id)
                .await
                .map_err(TaskHookError::execution)?;

            info!("enqueued account refresh task ({task_id}) for {account_id}");
        }

        Ok(())
    }
}
