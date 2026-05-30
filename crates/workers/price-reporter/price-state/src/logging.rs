//! Structured logging vocabulary for the price state primitive.
//!
//! Defines the closed set of operations the price state primitive performs,
//! used as the `task` field in structured log records via [`util::log_task`].

use util::logging::LogTask;

/// The set of operations performed by the price state primitive.
#[derive(Copy, Clone, Debug)]
pub enum Task {
    /// Recording a new price for a pair on an exchange.
    StateUpdate,
    /// Detecting and reporting stale prices.
    PriceStaleness,
    /// Handling prices received from peers.
    PeerPrice,
}

impl LogTask for Task {
    fn as_str(&self) -> &'static str {
        match self {
            Task::StateUpdate => "state-update",
            Task::PriceStaleness => "price-staleness",
            Task::PeerPrice => "peer-price",
        }
    }
}
