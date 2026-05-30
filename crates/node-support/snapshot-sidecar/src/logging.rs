//! Closed log-task vocabulary for the snapshot sidecar.

use util::logging::LogTask;

/// The closed set of operations the snapshot sidecar performs, used as the
/// `[task]` envelope in [`util::log_task!`] log lines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Task {
    /// Querying the relayer to determine whether the local node is the leader.
    LeaderCheck,
    /// Reacting to a new snapshot emitted by the relayer.
    HandleSnapshot,
    /// Uploading a snapshot file to the configured S3 bucket.
    UploadSnapshot,
}

impl LogTask for Task {
    fn as_str(&self) -> &'static str {
        match self {
            Task::LeaderCheck => "leader-check",
            Task::HandleSnapshot => "handle-snapshot",
            Task::UploadSnapshot => "upload-snapshot",
        }
    }
}
