//! A channel wrapper which adds traces across the channel boundary

use tokio::sync::mpsc::{
    error::SendError, UnboundedReceiver as TokioReceiver, UnboundedSender as TokioSender,
};

use crate::telemetry::propagation::{
    set_parent_span_from_headers, trace_context_headers, TraceContextHeaders,
};

/// A traced wrapper type that adds tracing information to the channel message
/// type
pub struct TracedMessage<T> {
    /// The tracing context
    pub tracing_context: TraceContextHeaders,
    /// The message
    pub message: T,
}

impl<T> TracedMessage<T> {
    /// Create a new traced message
    pub fn new(message: T) -> Self {
        Self { tracing_context: trace_context_headers(), message }
    }
}

// ------------------
// | Tokio Channels |
// ------------------

/// A traced Tokio sender
pub struct TracedTokioSender<T> {
    /// The inner channel
    inner: TokioSender<TracedMessage<T>>,
}

impl<T> TracedTokioSender<T> {
    /// Create a new traced Tokio sender
    pub fn new(inner: TokioSender<TracedMessage<T>>) -> Self {
        Self { inner }
    }

    /// Send a message to the channel
    pub async fn send(&self, message: T) -> Result<(), SendError<T>> {
        let traced_msg = TracedMessage::new(message);
        self.inner.send(traced_msg).map_err(|e| SendError(e.0.message))
    }
}

/// A traced Tokio receiver
pub struct TracedTokioReceiver<T> {
    /// The inner channel
    inner: TokioReceiver<TracedMessage<T>>,
}

impl<T> TracedTokioReceiver<T> {
    /// Create a new traced Tokio receiver
    pub fn new(inner: TokioReceiver<TracedMessage<T>>) -> Self {
        Self { inner }
    }

    /// Receive a message from the channel
    pub async fn recv(&mut self) -> Option<T> {
        // Unwrap the traced message and set the parent span
        let traced_message = self.inner.recv().await?;
        set_parent_span_from_headers(&traced_message.tracing_context);

        Some(traced_message.message)
    }
}
