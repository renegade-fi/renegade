//! A simple wrapper around channel receiver types used throughout the codebase
//! which records message queue lengths.

use tokio::sync::mpsc::UnboundedReceiver;

/// Metric describing the length of a worker's job queue
pub const QUEUE_LENGTH_METRIC: &str = "queue_length";

/// A wrapper around an [`UnboundedReceiver`] which records the message queue
/// length when a message is received.
pub struct MeteredUnboundedReceiver<T> {
    /// The inner receiver
    inner: UnboundedReceiver<T>,
    /// The name of the channel
    name: String,
}

impl<T> MeteredUnboundedReceiver<T> {
    /// Create a new metered receiver with the given name
    pub fn new(inner: UnboundedReceiver<T>, name: String) -> Self {
        Self { inner, name }
    }

    /// Receive a message from the channel, recording the queue length
    pub async fn recv(&mut self) -> Option<T> {
        #[cfg(feature = "metered-channels")]
        {
            let metric_name = format!("{}_{}", self.name, QUEUE_LENGTH_METRIC);
            let queue_len = self.inner.len();
            metrics::gauge!(metric_name).set(queue_len as f64);
        }

        self.inner.recv().await
    }
}
