//! The closed `Task` vocabulary for relayer configuration handling.
//!
//! See `util::logging` for the shared `[<task>] [<outcome>]` envelope.

use util::logging::LogTask;

/// Configuration operations that emit structured logs.
#[derive(Copy, Clone, Debug)]
pub(crate) enum Task {
    /// Validating the token remap / disabled-asset configuration against the
    /// CLI arguments.
    ValidateTokenRemap,
}

impl LogTask for Task {
    fn as_str(&self) -> &'static str {
        match self {
            Task::ValidateTokenRemap => "validate-token-remap",
        }
    }
}
