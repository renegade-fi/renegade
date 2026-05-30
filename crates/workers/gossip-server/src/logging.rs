//! The closed vocabulary of operations the gossip server performs, for use
//! with [`util::log_task!`].
//!
//! Each variant names an operation the gossip server performs; the kebab-cased
//! string forms are what `[task]`-prefixed greps and `@task:X` Datadog
//! aggregations key off of. See [`util::logging`] for the envelope.

use util::logging::LogTask;

/// The closed vocabulary of operations the gossip server performs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Task {
    /// Lifecycle transitions of the gossip protocol executor (startup,
    /// shutdown).
    ServerLifecycle,
    /// Dispatching and executing a gossip server job.
    JobDispatch,
    /// Indexing peers into the local peer index, including cluster auth
    /// signature verification.
    PeerIndexing,
    /// Proposing, rejecting, and applying expiry of peers that have timed out.
    PeerExpiry,
    /// Recording the number of local and remote peers as metrics.
    PeerMetrics,
}

impl LogTask for Task {
    fn as_str(&self) -> &'static str {
        match self {
            Task::ServerLifecycle => "server-lifecycle",
            Task::JobDispatch => "job-dispatch",
            Task::PeerIndexing => "peer-indexing",
            Task::PeerExpiry => "peer-expiry",
            Task::PeerMetrics => "peer-metrics",
        }
    }
}
