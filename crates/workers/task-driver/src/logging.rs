//! Structured logging tasks for the task driver

use util::logging::LogTask;

/// The set of operations the task driver performs, used as the task dimension
/// of structured log records
#[derive(Copy, Clone, Debug)]
pub enum Task {
    /// The task driver executor loop and per-task lifecycle (scheduling,
    /// state transitions, retries, cleanup, and post-task hooks)
    TaskExecution,
    /// Simulating the effect of queued tasks on an account
    TaskSimulation,
    /// Refreshing an account's state from on-chain and indexer data
    RefreshAccount,
    /// Creating a balance for an account
    CreateBalance,
    /// Creating (placing) an order for an account
    CreateOrder,
    /// Cancelling an order for an account
    CancelOrder,
    /// Depositing a balance into the darkpool
    Deposit,
    /// Withdrawing a balance from the darkpool
    Withdraw,
    /// Settling an external match
    SettleExternalMatch,
    /// Bringing up the local node (constants, gossip warmup, raft init/join)
    NodeStartup,
    /// Looking up an account's usable balance from on-chain data
    LookupBalance,
    /// Sending a message to the indexer
    IndexerMessage,
}

impl LogTask for Task {
    fn as_str(&self) -> &'static str {
        match self {
            Task::TaskExecution => "task-execution",
            Task::TaskSimulation => "task-simulation",
            Task::RefreshAccount => "refresh-account",
            Task::CreateBalance => "create-balance",
            Task::CreateOrder => "create-order",
            Task::CancelOrder => "cancel-order",
            Task::Deposit => "deposit",
            Task::Withdraw => "withdraw",
            Task::SettleExternalMatch => "settle-external-match",
            Task::NodeStartup => "node-startup",
            Task::LookupBalance => "lookup-balance",
            Task::IndexerMessage => "indexer-message",
        }
    }
}
