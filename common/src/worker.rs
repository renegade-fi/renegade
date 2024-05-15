//! Defines the `Worker` trait; abstracting over worker-specific functionalities
//! to allow the coordinator thread to start, cleanup, and restart workers

use std::{
    fmt::Debug,
    thread::{Builder, JoinHandle},
};

use async_trait::async_trait;
use tokio::sync::mpsc::Sender;
use tracing::error;

/// The Worker trait abstracts over worker functionality with a series of
/// callbacks that allow a worker to be started, cleaned up, and restarted
#[async_trait]
pub trait Worker {
    /// The configuration needed to spawn the implementing worker
    type WorkerConfig;
    /// The error type that results from an invalid startup or cleanup
    type Error: 'static + Send + Debug;

    /// Create a new instance of the implementing worker
    async fn new(config: Self::WorkerConfig) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Called to begin a worker, returns a JoinHandle to be waited on
    fn start(&mut self) -> Result<(), Self::Error>;

    /// Returns a name by which the worker can be identified
    fn name(&self) -> String;

    /// Called to join the calling thread's execution to the execution of the
    /// worker
    ///
    /// Returns a set of join handles, each of which is to be watched
    fn join(&mut self) -> Vec<JoinHandle<Self::Error>>;

    /// Returns whether or not the implementing type is recoverable
    fn is_recoverable(&self) -> bool;

    /// Recover the worker by re-allocating it
    ///
    /// This method consumes the worker instance so that it can transfer
    /// ownership of any re-usable components.
    ///
    /// The return value of this method should be a fresh instance of the worker
    fn recover(self) -> Self
    where
        Self: Sized,
    {
        unimplemented!("recover not implemented for worker")
    }

    /// Called to cleanup the resources a worker owns when the worker crashes
    fn cleanup(&mut self) -> Result<(), Self::Error>;
}

/// Spawn a watcher thread for each join handle in the worker being watched
///
/// A worker may have more than one join handle in the case that it spawns
/// multiple sub-worker threads. Each will be individually watched
pub fn watch_worker<W: Worker>(worker: &mut W, failure_channel: &Sender<()>) {
    let watcher_name = format!("{}-watcher", worker.name());
    for join_handle in worker.join() {
        let worker_name = worker.name();
        let channel_clone = failure_channel.clone();

        Builder::new()
            .name(watcher_name.clone())
            .spawn(move || {
                match join_handle.join() {
                    Err(panic) => {
                        error!("worker {worker_name} panicked with error: {panic:?}");
                    },
                    Ok(err) => {
                        error!("worker {worker_name} exited with error: {err:?}");
                    },
                }
                channel_clone.blocking_send(()).unwrap();
            })
            .unwrap();
    }
}
