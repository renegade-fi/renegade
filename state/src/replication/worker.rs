//! Implements the `Worker` trait for the Raft node

use std::thread::{Builder, JoinHandle};

use ::raft::prelude::Config as RaftConfig;
use common::{types::gossip::WrappedPeerId, worker::Worker};
use config::RelayerConfig;
use tracing::info;
use util::err_str;

use super::{
    error::ReplicationError,
    network::{address_translation::PeerIdTranslationMap, traits::RaftNetwork},
    raft_node::{ReplicationNode, ReplicationNodeConfig},
};

// -------------
// | CONSTANTS |
// -------------

/// The default tick interval for the raft node
pub const DEFAULT_TICK_INTERVAL_MS: u64 = 10; // 10 milliseconds
/// The default number of ticks between Raft heartbeats
const DEFAULT_HEARTBEAT_TICKS: usize = 100; // 1 second at 10ms per tick
/// The default lower bound on the number of ticks before a Raft election
const DEFAULT_MIN_ELECTION_TICKS: usize = 1000; // 10 seconds at 10ms per tick
/// The default upper bound on the number of ticks before a Raft election
const DEFAULT_MAX_ELECTION_TICKS: usize = 1500; // 15 seconds at 10ms per tick

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
        let raft_config = build_raft_config(&config.relayer_config);
        let raft_node = Some(ReplicationNode::new_with_config(config, &raft_config)?);

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

// -----------
// | HELPERS |
// -----------

/// Build the raft config for the node
fn build_raft_config(relayer_config: &RelayerConfig) -> RaftConfig {
    let peer_id = relayer_config.p2p_key.public().to_peer_id();
    let raft_id = PeerIdTranslationMap::get_raft_id(&WrappedPeerId(peer_id));
    RaftConfig {
        id: raft_id,
        heartbeat_tick: DEFAULT_HEARTBEAT_TICKS,
        election_tick: DEFAULT_MIN_ELECTION_TICKS,
        min_election_tick: DEFAULT_MIN_ELECTION_TICKS,
        max_election_tick: DEFAULT_MAX_ELECTION_TICKS,
        ..Default::default()
    }
}
