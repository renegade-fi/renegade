//! Task taxonomy for the matching engine worker's structured logging.
//!
//! Each variant names a distinct operation the worker performs and is rendered
//! by [`LogTask::as_str`] as a kebab-case task label inside the relayer's
//! `log_task!` envelope.

use util::logging::LogTask;

/// The set of operations performed by the matching engine worker that emit
/// structured logs.
#[derive(Copy, Clone, Debug)]
pub(crate) enum Task {
    /// The worker's top-level startup and job-dispatch loop.
    RunMatchingEngine,
    /// Booting the worker's executor loop.
    StartWorker,
    /// Running the internal matching engine on an order.
    InternalMatch,
    /// Running the external matching engine on an order.
    ExternalMatch,
    /// Settling a matched internal order pair.
    SettleInternalMatch,
    /// Forwarding a quote to an external client.
    ForwardQuote,
    /// Checking whether an order is still valid for matching.
    CheckOrderValid,
}

impl LogTask for Task {
    fn as_str(&self) -> &'static str {
        match self {
            Task::RunMatchingEngine => "run-matching-engine",
            Task::StartWorker => "start-worker",
            Task::InternalMatch => "internal-match",
            Task::ExternalMatch => "external-match",
            Task::SettleInternalMatch => "settle-internal-match",
            Task::ForwardQuote => "forward-quote",
            Task::CheckOrderValid => "check-order-valid",
        }
    }
}
