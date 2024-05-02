//! Implements the `Worker` trait for the Raft node

use std::thread::{Builder, JoinHandle};

use common::worker::Worker;

use tracing::info;
use util::err_str;

use super::{
    error::ReplicationError,
    network::traits::RaftNetwork,
    raft_node::{ReplicationNode, ReplicationNodeConfig},
};

/// Manages the Raft replication node thread
pub struct ReplicationNodeWorker<N: RaftNetwork> {
    /// The Raft node that this worker is managing.
    ///
    /// We wrap this in an option so that ownership can be transferred to the
    /// executor thread.
    raft_node: Option<ReplicationNode<N>>,
    /// The handle to the raft node thread
    raft_handle: Option<JoinHandle<ReplicationWorkerError>>,
}

/// The error type for the replication node worker
#[derive(Debug)]
pub enum ReplicationWorkerError {
    /// An error setting up the raft node
    Setup(String),
    /// An error receiving a message on a channel
    RecvError(String),
    /// The worker was cancelled
    Cancelled,
    /// An error from the underlying Raft replication node
    Replication(ReplicationError),
}

impl From<ReplicationError> for ReplicationWorkerError {
    fn from(value: ReplicationError) -> Self {
        Self::Replication(value)
    }
}

impl<N: 'static + RaftNetwork + Send> Worker for ReplicationNodeWorker<N> {
    type Error = ReplicationWorkerError;
    type WorkerConfig = ReplicationNodeConfig<N>;

    fn new(config: Self::WorkerConfig) -> Result<Self, Self::Error> {
        let raft_node = Some(ReplicationNode::new(config)?);

        Ok(Self { raft_node, raft_handle: None })
    }

    fn is_recoverable(&self) -> bool {
        false
    }

    fn name(&self) -> String {
        "raft-replication-node-main".to_string()
    }

    fn join(&mut self) -> Vec<JoinHandle<Self::Error>> {
        vec![self.raft_handle.take().unwrap()]
    }

    fn start(&mut self) -> Result<(), Self::Error> {
        info!("Starting Raft replication node");

        let raft_node = self.raft_node.take().unwrap();
        let raft_handle = Builder::new()
            .name("raft-replication-node-executor".to_string())
            .spawn(move || raft_node.run().unwrap_err())
            .map_err(err_str!(ReplicationWorkerError::Setup))?;

        self.raft_handle = Some(raft_handle);
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), Self::Error> {
        unimplemented!()
    }
}
