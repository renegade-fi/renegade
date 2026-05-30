//! The closed `Task` vocabulary for the relayer coordinator (`core`).
//!
//! See `util::logging` for the shared `[<task>] [<outcome>]` envelope. Each
//! crate owns its own `Task` enum; this one covers the process-level
//! coordinator operations that live in `core`.

use util::logging::LogTask;

/// Closed vocabulary of operations the coordinator performs.
///
/// Add a variant here before introducing a new task at a call site; the
/// closed vocabulary is what makes `@task:X` Datadog aggregations reliable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Task {
    /// Process-level lifecycle: boot, worker startup, teardown, termination.
    ServiceLifecycle,
    /// Recovery of a faulted worker in the coordinator's recovery loop.
    WorkerRecovery,
}

impl LogTask for Task {
    fn as_str(&self) -> &'static str {
        match self {
            Task::ServiceLifecycle => "service-lifecycle",
            Task::WorkerRecovery => "worker-recovery",
        }
    }
}
