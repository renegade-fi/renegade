//! The closed `Task` vocabulary for `darkpool-client` log lines.
//!
//! See [`util::logging`] for the shared envelope. Each variant names an
//! on-chain operation this crate performs and is emitted through
//! [`util::log_task!`].

use util::logging::LogTask;

/// Closed vocabulary of on-chain operations the darkpool client performs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Task {
    /// Generic transaction submission to the chain (pre-confirmation).
    SubmitTx,
    /// Create a new balance in the darkpool contract.
    CreateBalance,
    /// Deposit funds into an existing balance.
    Deposit,
    /// Withdraw funds from an existing balance.
    Withdraw,
    /// Settle a match between two parties.
    SettleMatch,
    /// Cancel a public order.
    CancelOrder,
}

impl LogTask for Task {
    fn as_str(&self) -> &'static str {
        match self {
            Task::SubmitTx => "submit-tx",
            Task::CreateBalance => "create-balance",
            Task::Deposit => "deposit",
            Task::Withdraw => "withdraw",
            Task::SettleMatch => "settle-match",
            Task::CancelOrder => "cancel-order",
        }
    }
}
