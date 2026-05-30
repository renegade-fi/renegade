//! The closed vocabulary of tasks the event export sidecar performs, for use
//! with [`util::log_task!`].

use util::logging::LogTask;

/// The set of operations the event export sidecar performs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Task {
    /// Process-level lifecycle of the sidecar binary.
    SidecarLifecycle,
    /// Establishing and tearing down the Unix event socket connection.
    EventSocket,
    /// Handling a single relayer event received on the socket.
    HandleEvent,
    /// Removing the Unix socket file on drop.
    SocketCleanup,
}

impl LogTask for Task {
    fn as_str(&self) -> &'static str {
        match self {
            Task::SidecarLifecycle => "sidecar-lifecycle",
            Task::EventSocket => "event-socket",
            Task::HandleEvent => "handle-event",
            Task::SocketCleanup => "socket-cleanup",
        }
    }
}
