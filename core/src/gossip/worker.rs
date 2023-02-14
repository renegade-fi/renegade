//! Implements the `Worker` trait for the GossipServer

use std::thread::{Builder, JoinHandle};

use crossbeam::channel::{Receiver, Sender};
use libp2p::Multiaddr;
use tokio::sync::mpsc::UnboundedSender as TokioSender;

use crate::{
    api::{
        gossip::{GossipOutbound, GossipRequest, ManagerControlDirective},
        heartbeat::BootstrapRequest,
    },
    state::RelayerState,
    worker::Worker,
    CancelChannel,
};

use super::{
    errors::GossipError,
    jobs::GossipServerJob,
    server::{GossipProtocolExecutor, GossipServer},
    types::{ClusterId, PeerInfo, WrappedPeerId},
};

/// The configuration passed from the coordinator to the GossipServer
#[derive(Debug)]
pub struct GossipServerConfig {
    /// The libp2p PeerId of the local peer
    pub(crate) local_peer_id: WrappedPeerId,
    /// The multiaddr of the local peer
    pub(crate) local_addr: Multiaddr,
    /// The cluster ID of the local peer
    pub(crate) cluster_id: ClusterId,
    /// The servers to bootstrap into the network with
    pub(crate) bootstrap_servers: Vec<PeerInfo>,
    /// A reference to the relayer-global state
    pub(crate) global_state: RelayerState,
    /// A job queue to send outbound heartbeat requests on
    pub(crate) heartbeat_worker_sender: Sender<GossipServerJob>,
    /// A job queue to receive inbound heartbeat requests on
    pub(crate) heartbeat_worker_receiver: Receiver<GossipServerJob>,
    /// A job queue to send outbound network requests on
    pub(crate) network_sender: TokioSender<GossipOutbound>,
    /// The channel on which the coordinator may mandate that the
    /// gossip server cancel its execution
    pub(crate) cancel_channel: CancelChannel,
}

impl Worker for GossipServer {
    type WorkerConfig = GossipServerConfig;
    type Error = GossipError;

    fn new(config: Self::WorkerConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            config,
            protocol_executor_handle: None,
        })
    }

    fn is_recoverable(&self) -> bool {
        true
    }

    fn name(&self) -> String {
        "gossip-server-main".to_string()
    }

    fn join(&mut self) -> Vec<JoinHandle<Self::Error>> {
        vec![self.protocol_executor_handle.take().unwrap()]
    }

    fn start(&mut self) -> Result<(), Self::Error> {
        // Start the heartbeat executor, this worker manages pinging peers and responding to
        // heartbeat requests from peers
        let protocol_executor = GossipProtocolExecutor::new(
            self.config.local_peer_id,
            self.config.network_sender.clone(),
            self.config.heartbeat_worker_receiver.clone(),
            self.config.global_state.clone(),
            self.config.cancel_channel.clone(),
        )?;

        let sender = self.config.heartbeat_worker_sender.clone();
        self.protocol_executor_handle = Some(
            Builder::new()
                .name("gossip-executor-main".to_string())
                .spawn(move || protocol_executor.execution_loop(sender))
                .map_err(|err| GossipError::ServerSetup(err.to_string()))?,
        );

        // Bootstrap into the network in two steps:
        //  1. Forward all bootstrap addresses to the network manager so it may dial them
        //  2. Send bootstrap requests to all bootstrapping peers
        // Wait until all peers have been indexed before sending requests to give async network
        // manager time to index the peers in the case that these messages are processed concurrently
        for bootstrap_peer in self.config.bootstrap_servers.iter() {
            self.config
                .network_sender
                .send(GossipOutbound::ManagementMessage(
                    ManagerControlDirective::NewAddr {
                        peer_id: bootstrap_peer.get_peer_id(),
                        address: bootstrap_peer.get_addr(),
                    },
                ))
                .map_err(|err| GossipError::SendMessage(err.to_string()))?;
        }

        let req = BootstrapRequest {
            peer_id: self.config.local_peer_id,
        };
        for bootstrap_peer in self.config.bootstrap_servers.iter() {
            self.config
                .network_sender
                .send(GossipOutbound::Request {
                    peer_id: bootstrap_peer.get_peer_id(),
                    message: GossipRequest::Bootstrap(req.clone()),
                })
                .map_err(|err| GossipError::SendMessage(err.to_string()))?;
        }

        // Wait for the local peer to handshake with known other peers
        // before sending a cluster membership message
        self.warmup_then_join_cluster(
            &self.config.global_state,
            self.config.heartbeat_worker_sender.clone(),
        )?;

        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), Self::Error> {
        unimplemented!()
    }
}
