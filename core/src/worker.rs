//! Defines the `Worker` trait; abstracting over worker-specific functionalities to allow
//! the coordinator thread to start, cleanup, and restart workers

use std::{
    fmt::Debug,
    thread::{self, JoinHandle},
};

use tokio::sync::mpsc::Sender;

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
    ///
    /// Returns a set of join handles, each of which is to be watched
    fn join(&mut self) -> Vec<JoinHandle<Self::Error>>;

    /// Called to cleanup the resources a worker owns when the worker crashes
    fn cleanup(&mut self) -> Result<(), Self::Error>;
}

/// Spawn a watcher thread for each join handle in the worker being watched
///
/// A worker may have more than one join handle in the case that it spawns
/// multiple sub-worker threads. Each will be individually watched
#[allow(unused_must_use)]
pub fn watch_worker<W: Worker>(worker: &mut W, failure_channel: Sender<()>) {
    //
    for join_handle in worker.join() {
        let channel_clone = failure_channel.clone();
        thread::spawn(move || {
            join_handle.join();
            channel_clone.send(());
        });
    }
}
