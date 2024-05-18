//! A simple wrapper around channel receiver types used throughout the codebase
//! which records message queue lengths.

use crossbeam::channel::{Receiver, RecvError};
use tokio::sync::mpsc::UnboundedReceiver;

/// Metric describing the length of a worker's job queue
pub const QUEUE_LENGTH_METRIC: &str = "queue_length";

/// A wrapper around an [`UnboundedReceiver`] which records the message queue
/// length when a message is received.
#[derive(Debug)]
pub struct MeteredTokioReceiver<T> {
    /// The inner receiver
    inner: UnboundedReceiver<T>,

    /// The name of the channel
    #[cfg_attr(not(feature = "metered-channels"), allow(dead_code))]
    name: &'static str,
}

impl<T> MeteredTokioReceiver<T> {
    /// Create a new metered receiver with the given name
    pub fn new(inner: UnboundedReceiver<T>, name: &'static str) -> Self {
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

/// A wrapper around a [`Receiver`] which records the message queue
/// length when a message is received.
#[derive(Debug)]
pub struct MeteredCrossbeamReceiver<T> {
    /// The inner receiver
    inner: Receiver<T>,
    /// The name of the channel
    name: &'static str,
}

impl<T> MeteredCrossbeamReceiver<T> {
    /// Create a new metered receiver with the given name
    pub fn new(inner: Receiver<T>, name: &'static str) -> Self {
        Self { inner, name }
    }

    /// Check if the channel is empty
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Receive a message from the channel, recording the queue length
    pub fn recv(&self) -> Result<T, RecvError> {
        #[cfg(feature = "metered-channels")]
        {
            let metric_name = format!("{}_{}", self.name, QUEUE_LENGTH_METRIC);
            let queue_len = self.inner.len();
            metrics::gauge!(metric_name).set(queue_len as f64);
        }

        self.inner.recv()
    }
}

impl<T> Clone for MeteredCrossbeamReceiver<T> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone(), name: self.name }
    }
}
