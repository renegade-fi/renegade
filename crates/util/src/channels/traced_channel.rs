//! A channel wrapper which adds traces across the channel boundary

use crossbeam::channel::{
    Receiver as CrossbeamReceiver, SendError as CrossbeamSendError, Sender as CrossbeamSender,
    unbounded as crossbeam_unbounded_channel,
};
use tokio::sync::mpsc::{
    UnboundedReceiver as TokioReceiver, UnboundedSender as TokioSender, error::SendError,
    unbounded_channel as tokio_unbounded_channel,
};

use crate::telemetry::propagation::{TraceContext, set_parent_span_from_context, trace_context};

/// A traced wrapper type that adds tracing information to the channel message
/// type
pub struct TracedMessage<T> {
    /// The tracing context
    pub trace_context: TraceContext,
    /// The message
    pub message: T,
}

impl<T: std::fmt::Debug> std::fmt::Debug for TracedMessage<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.message.fmt(f)
    }
}

impl<T> TracedMessage<T> {
    /// Create a new traced message
    pub fn new(message: T) -> Self {
        let trace_context = trace_context();
        Self { trace_context, message }
    }

    /// Convert the traced message to the original message
    pub fn into_message(self) -> T {
        self.message
    }

    /// Consume the traced message, setting the parent span and returning the
    /// original message
    pub fn consume(self) -> T {
        set_parent_span_from_context(&self.trace_context);
        self.message
    }
}

// -----------
// | Helpers |
// -----------

/// Create a new traced Tokio sender and receiver
pub fn new_traced_tokio_channel<T>() -> (TracedTokioSender<T>, TracedTokioReceiver<T>) {
    let (tx, rx) = tokio_unbounded_channel();
    (TracedTokioSender::new(tx), TracedTokioReceiver::new(rx))
}

/// Create a new traced Crossbeam sender and receiver
pub fn new_traced_crossbeam_channel<T>() -> (TracedCrossbeamSender<T>, TracedCrossbeamReceiver<T>) {
    let (tx, rx) = crossbeam_unbounded_channel();
    (TracedCrossbeamSender::new(tx), TracedCrossbeamReceiver::new(rx))
}

// ------------------
// | Tokio Channels |
// ------------------

/// A traced Tokio sender
#[derive(Debug)]
pub struct TracedTokioSender<T> {
    /// The inner channel
    inner: TokioSender<TracedMessage<T>>,
}

impl<T> Clone for TracedTokioSender<T> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

impl<T> TracedTokioSender<T> {
    /// Create a new traced Tokio sender
    pub fn new(inner: TokioSender<TracedMessage<T>>) -> Self {
        Self { inner }
    }

    /// Send a message to the channel
    pub fn send(&self, message: T) -> Result<(), SendError<T>> {
        let traced_msg = TracedMessage::new(message);
        self.inner.send(traced_msg).map_err(|e| SendError(e.0.message))
    }
}

/// A traced Tokio receiver
#[derive(Debug)]
pub struct TracedTokioReceiver<T> {
    /// The inner channel
    inner: TokioReceiver<TracedMessage<T>>,
}

impl<T> TracedTokioReceiver<T> {
    /// Create a new traced Tokio receiver
    pub fn new(inner: TokioReceiver<TracedMessage<T>>) -> Self {
        Self { inner }
    }
    /// Check if the channel is empty
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Receive a message from the channel
    pub async fn recv(&mut self) -> Option<TracedMessage<T>> {
        self.inner.recv().await
    }
}

// ----------------------
// | Crossbeam Channels |
// ----------------------

/// A traced Crossbeam sender
#[derive(Debug)]
pub struct TracedCrossbeamSender<T> {
    /// The inner channel
    inner: CrossbeamSender<TracedMessage<T>>,
}

impl<T> Clone for TracedCrossbeamSender<T> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

impl<T> TracedCrossbeamSender<T> {
    /// Create a new traced Crossbeam sender
    pub fn new(inner: CrossbeamSender<TracedMessage<T>>) -> Self {
        Self { inner }
    }

    /// Send a message to the channel
    pub fn send(&self, message: T) -> Result<(), CrossbeamSendError<T>> {
        let traced_msg = TracedMessage::new(message);
        self.inner.send(traced_msg).map_err(|e| CrossbeamSendError(e.0.message))
    }
}

/// A traced Crossbeam receiver
#[derive(Debug)]
pub struct TracedCrossbeamReceiver<T> {
    /// The inner channel
    inner: CrossbeamReceiver<TracedMessage<T>>,
}

impl<T> Clone for TracedCrossbeamReceiver<T> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

impl<T> TracedCrossbeamReceiver<T> {
    /// Create a new traced Crossbeam receiver
    pub fn new(inner: CrossbeamReceiver<TracedMessage<T>>) -> Self {
        Self { inner }
    }

    /// Check if the channel is empty
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Receive a message from the channel
    pub fn recv(&self) -> Result<TracedMessage<T>, crossbeam::channel::RecvError> {
        self.inner.recv()
    }

    /// Try to receive a message from the channel (non-blocking)
    pub fn try_recv(&self) -> Result<TracedMessage<T>, crossbeam::channel::TryRecvError> {
        self.inner.try_recv()
    }
}
