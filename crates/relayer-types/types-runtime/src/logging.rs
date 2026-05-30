//! The closed `Task` vocabulary for the runtime's worker watcher.
//!
//! See `util::logging` for the shared `[<task>] [<outcome>]` envelope.

use util::logging::LogTask;

/// Operations the runtime performs that emit structured logs.
#[derive(Copy, Clone, Debug)]
pub(crate) enum Task {
    /// The watcher thread observing a worker for a panic or error exit.
    WorkerWatcher,
}

impl LogTask for Task {
    fn as_str(&self) -> &'static str {
        match self {
            Task::WorkerWatcher => "worker-watcher",
        }
    }
}
