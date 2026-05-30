//! Task definitions for the sidecar's structured `log_task!` logging

use util::logging::LogTask;

/// The set of logical tasks performed by the indexer message sidecar.
///
/// Each variant maps to a stable kebab-case string used as the `task` field in
/// structured log events.
pub enum Task {
    /// Sidecar process startup and server bring-up
    SidecarLifecycle,
    /// Proxying or handling an inbound HTTP request
    HandleRequest,
    /// Submitting a message to the SQS queue
    SubmitSqs,
    /// Handling a warp rejection into an HTTP error response
    HandleRejection,
}

impl LogTask for Task {
    fn as_str(&self) -> &'static str {
        match self {
            Task::SidecarLifecycle => "sidecar-lifecycle",
            Task::HandleRequest => "handle-request",
            Task::SubmitSqs => "submit-sqs",
            Task::HandleRejection => "handle-rejection",
        }
    }
}
