//! The gossip server manages the general gossip network interaction of a single p2p node

use super::{heartbeat_executor::HeartbeatProtocolExecutor, worker::GossipServerConfig};

/// The server type that manages interactions with the gossip network
#[derive(Debug)]
pub struct GossipServer {
    /// The config for the Gossip Server
    pub(super) config: GossipServerConfig,
    /// The heartbeat executor, handles request/response for heartbeats
    pub(super) heartbeat_executor: Option<HeartbeatProtocolExecutor>,
}
