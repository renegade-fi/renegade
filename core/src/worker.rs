//! Defines the `Worker` trait; abstracting over worker-specific functionalities to allow
//! the coordinator thread to start, cleanup, and restart workers

use std::{
    fmt::Debug,
    thread::{self, JoinHandle},
};

use tokio::sync::oneshot::Sender;

/// The Worker trait abstracts over worker functionality with a series of callbacks that
/// allow a worker to be started, cleaned up, and restarted
pub trait Worker {
    /// The configuration needed to spawn the implementing worker
    type WorkerConfig;
    /// The error type that results from an invalid startup or cleanup
    type Error: 'static + Send + Clone + Debug;

    /// Create a new instance of the implementing worker
    fn new(config: Self::WorkerConfig) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Returns whether or not the implementing type is recoverable
    fn is_recoverable(&self) -> bool;

    /// Called to begin a worker, returns a JoinHandle to be waited on
    fn start(&mut self) -> Result<(), Self::Error>;

    /// Called to join the calling thread's execution to the execution of the worker
    fn join(&mut self) -> JoinHandle<Self::Error>;

    /// Called to cleanup the resources a worker owns when the worker crashes
    fn cleanup(&mut self) -> Result<(), Self::Error>;
}

/// Spawns a thread that waits for a worker to finish then reports this back
/// as an error via a channel
#[allow(unused_must_use)]
pub fn watch_worker<W: Worker>(join_handle: JoinHandle<W::Error>, failure_channel: Sender<()>) {
    thread::spawn(move || {
        join_handle.join();
        failure_channel.send(());
    });
}
