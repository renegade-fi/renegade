//! The closed vocabulary of operations the event manager performs, for use
//! with [`util::log_task!`].

use util::logging::LogTask;

/// The set of operations the event manager performs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Task {
    /// Lifecycle transitions of the event manager (startup, shutdown).
    ManagerLifecycle,
    /// Handling a relayer event received on the event queue.
    HandleEvent,
}

impl LogTask for Task {
    fn as_str(&self) -> &'static str {
        match self {
            Task::ManagerLifecycle => "manager-lifecycle",
            Task::HandleEvent => "handle-event",
        }
    }
}
