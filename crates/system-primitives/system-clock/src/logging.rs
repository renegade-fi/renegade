//! The closed `Task` vocabulary for the system clock's structured logging.
//!
//! See `util::logging` for the shared `[<task>] [<outcome>]` envelope.

use util::logging::LogTask;

/// Operations the system clock performs that emit structured logs.
#[derive(Copy, Clone, Debug)]
pub(crate) enum Task {
    /// Execution of a user-supplied periodic clock callback.
    ClockCallback,
}

impl LogTask for Task {
    fn as_str(&self) -> &'static str {
        match self {
            Task::ClockCallback => "clock-callback",
        }
    }
}
