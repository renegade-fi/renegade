//! Structured logging taxonomy for the proof manager crate.
//!
//! Defines the closed [`Task`] vocabulary of operations this crate performs,
//! used with [`util::log_task!`] to emit log lines in the relayer taxonomy.

use util::logging::LogTask;

/// A closed vocabulary of operations the proof manager performs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Task {
    /// The proof manager's run / execution loop lifecycle (startup, cancel,
    /// shutdown).
    ManagerLifecycle,
    /// Handling a single proof generation job dispatched to the manager.
    HandleProofJob,
}

impl LogTask for Task {
    fn as_str(&self) -> &'static str {
        match self {
            Task::ManagerLifecycle => "manager-lifecycle",
            Task::HandleProofJob => "handle-proof-job",
        }
    }
}
