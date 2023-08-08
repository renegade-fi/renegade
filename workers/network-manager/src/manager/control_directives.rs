//! Defines handlers for network manager control directives, which are messages that
//! correspond to some action in the NetworkManager itself

use std::net::SocketAddr;

use common::types::handshake::ConnectionRole;
use gossip_api::gossip::ManagerControlDirective;
use itertools::Itertools;
use job_types::handshake_manager::HandshakeExecutionJob;
use libp2p_core::{Endpoint, Multiaddr};
use libp2p_swarm::{ConnectionId, NetworkBehaviour};
use mpc_stark::network::QuicTwoPartyNet;
use tokio::sync::mpsc::UnboundedSender as TokioSender;
use tracing::log;
use util::networking::{is_dialable_addr, is_dialable_multiaddr, multiaddr_to_socketaddr};
use uuid::Uuid;

use crate::error::NetworkManagerError;

use super::{NetworkManagerExecutor, ERR_BROKER_MPC_NET, ERR_NO_KNOWN_ADDR};

impl NetworkManagerExecutor {
    /// Handles a message from another worker module that explicitly directs the network manager
    /// to take some action
    ///
    /// The end destination of these messages is not a network peer, but the local network manager
    /// itself
    pub(super) fn handle_control_directive(
        &mut self,
        command: ManagerControlDirective,
    ) -> Result<(), NetworkManagerError> {
        match command {
            // Register a new peer in the distributed routing tables
            ManagerControlDirective::NewAddr { peer_id, address } => {
                // If we cannot parse the address or it is not dialable, skip indexing
                if !is_dialable_multiaddr(&address, self.allow_local) {
                    log::info!("skipping local addr {:?}", address);
                    return Ok(());
                }

                self.swarm
                    .behaviour_mut()
                    .kademlia_dht
                    .add_address(&peer_id, address);

                Ok(())
            }

            // Build an MPC net for the given peers to communicate over
            ManagerControlDirective::BrokerMpcNet {
                request_id,
                peer_id,
                peer_port,
                local_port,
                local_role,
            } => {
                // Lookup known remote addresses for the peer
                let known_peer_addrs = self
                    .swarm
                    .behaviour_mut()
                    .handle_pending_outbound_connection(
                        ConnectionId::new_unchecked(0),
                        Some(peer_id.0),
                        &[],
                        Endpoint::Dialer,
                    )
                    .map_err(|_| NetworkManagerError::Network(ERR_NO_KNOWN_ADDR.to_string()))?;

                // Spawn a separate task to asynchronously dial the peer and respond to
                // the handshake manager's brokerage request
                let allow_local = self.allow_local;
                let handshake_queue_clone = self.handshake_work_queue.clone();
                tokio::spawn(async move {
                    if let Err(e) = Self::broker_mpc_net(
                        allow_local,
                        request_id,
                        peer_port,
                        local_port,
                        local_role,
                        known_peer_addrs,
                        handshake_queue_clone,
                    )
                    .await
                    {
                        log::error!("error brokering MPC network: {e}");
                    }
                });

                Ok(())
            }

            // Inform the network manager that the gossip server has warmed up the local node in
            // the cluster by advertising the local node's presence
            //
            // The network manager delays sending pubsub events until the gossip protocol has warmed
            // up, because at startup, there are no known peers to publish to. The network manager gives
            // the gossip server some time to discover new addresses before publishing to the network.
            ManagerControlDirective::GossipWarmupComplete => {
                self.warmup_finished = true;
                // Forward all buffered messages to the network
                for buffered_message in self.warmup_buffer.drain(..).collect_vec() {
                    self.forward_outbound_pubsub(buffered_message.topic, buffered_message.message)?;
                }

                Ok(())
            }
        }
    }

    /// Broker an MPC net between the local and remote peer using the given known addresses
    async fn broker_mpc_net(
        allow_local: bool,
        request_id: Uuid,
        peer_port: u16,
        mut local_port: u16,
        local_role: ConnectionRole,
        known_peer_addrs: Vec<Multiaddr>,
        handshake_work_queue: TokioSender<HandshakeExecutionJob>,
    ) -> Result<(), NetworkManagerError> {
        // Connect on a side-channel to the peer
        let party_id = local_role.get_party_id();

        let mpc_net = match local_role {
            ConnectionRole::Dialer => {
                // Attempt to dial the peer on all known addresses
                let mut brokered_net = None;
                for peer_addr in known_peer_addrs
                    .into_iter()
                    .filter_map(|addr| multiaddr_to_socketaddr(&addr, peer_port))
                    .filter(|addr| is_dialable_addr(addr, allow_local))
                {
                    let local_addr: SocketAddr =
                        format!("0.0.0.0:{:?}", local_port).parse().unwrap();
                    let mut net = QuicTwoPartyNet::new(party_id, local_addr, peer_addr);

                    if let Err(e) = net.connect().await {
                        log::warn!(
                            "failed to broker MPC network on address {peer_addr:?}, error: {e}"
                        )
                    } else {
                        log::info!("successfully connected to peer at addr: {peer_addr:?}");
                        // Forward the net to the handshake manager
                        brokered_net = Some(net);
                        break;
                    }

                    // During the connection attempt, the selected port was bound to, and dropping the `net`
                    // may not immediately free up the port; so we increment the outbound port and continue
                    local_port += 1;
                }

                brokered_net
                    .ok_or_else(|| NetworkManagerError::Network(ERR_BROKER_MPC_NET.to_string()))?
            }

            ConnectionRole::Listener => {
                // As the listener, the peer address is inconsequential, and can be a dummy value
                let local_addr: SocketAddr = format!("0.0.0.0:{local_port}").parse().unwrap();
                let peer_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
                let mut net = QuicTwoPartyNet::new(party_id, local_addr, peer_addr);
                net.connect()
                    .await
                    .map_err(|err| NetworkManagerError::Network(err.to_string()))?;

                net
            }
        };

        // After the dependencies are injected into the network; forward it to the handshake manager to
        // dial the peer and begin the MPC
        handshake_work_queue
            .send(HandshakeExecutionJob::MpcNetSetup {
                request_id,
                party_id,
                net: mpc_net,
            })
            .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string()))?;
        Ok(())
    }
}
