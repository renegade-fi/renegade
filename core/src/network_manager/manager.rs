//! The network manager handles lower level interaction with the p2p network

use crossbeam::channel::Sender;
use ed25519_dalek::Keypair as SigKeypair;
use futures::StreamExt;
use itertools::Itertools;
use libp2p::{
    gossipsub::{GossipsubEvent, GossipsubMessage, Sha256Topic},
    identity::Keypair,
    multiaddr::Protocol,
    request_response::{RequestResponseEvent, RequestResponseMessage},
    swarm::SwarmEvent,
    Multiaddr, PeerId, Swarm,
};
use libp2p_swarm::NetworkBehaviour;
use mpc_ristretto::network::QuicTwoPartyNet;
use portpicker::Port;
use tracing::log;

use std::{net::SocketAddr, thread::JoinHandle};
use tokio::sync::mpsc::{Receiver, UnboundedReceiver};

use crate::{
    api::{
        cluster_management::{ClusterManagementMessage, ReplicatedMessage},
        gossip::{
            AuthenticatedGossipRequest, AuthenticatedGossipResponse, AuthenticatedPubsubMessage,
            ConnectionRole, GossipOutbound, GossipOutbound::Pubsub, GossipRequest, GossipResponse,
            ManagerControlDirective, PubsubMessage,
        },
        orderbook_management::{OrderBookManagementMessage, OrderInfoResponse, ORDER_BOOK_TOPIC},
    },
    gossip::{
        jobs::{ClusterManagementJob, GossipServerJob, OrderBookManagementJob},
        types::{ClusterId, PeerInfo, WrappedPeerId},
    },
    handshake::jobs::HandshakeExecutionJob,
    state::RelayerState,
};

use super::{
    composed_protocol::{ComposedNetworkBehavior, ComposedProtocolEvent},
    error::NetworkManagerError,
    worker::NetworkManagerConfig,
};

/// Occurs when a peer cannot be dialed because their address is not indexed in
/// the network behavior
const ERR_NO_KNOWN_ADDR: &str = "no known address for peer";
/// Error parsing an address from Multiaddr to Socketaddr
const ERR_PARSING_ADDR: &str = "could not parse Multiaddr to SocketAddr";
/// Emitted when signature verification for an authenticated request fails
const ERR_SIG_VERIFY: &str = "signature verification failed";

// -----------
// | Helpers |
// -----------

/// Convert a libp2p multiaddr into a standard library socketaddr representation
fn multiaddr_to_socketaddr(mut addr: Multiaddr, port: Port) -> Option<SocketAddr> {
    while let Some(protoc) = addr.pop() {
        match protoc {
            Protocol::Ip4(ip4_addr) => return Some(SocketAddr::new(ip4_addr.into(), port)),
            Protocol::Ip6(ip6_addr) => return Some(SocketAddr::new(ip6_addr.into(), port)),
            _ => {}
        }
    }

    None
}

// -----------
// | Manager |
// -----------

/// Groups logic around monitoring and requesting the network
pub struct NetworkManager {
    /// The config passed from the coordinator thread
    pub(super) config: NetworkManagerConfig,
    /// The peerId of the locally running node
    pub(crate) local_peer_id: WrappedPeerId,
    /// The multiaddr of the local peer
    pub(crate) local_addr: Multiaddr,
    /// The cluster ID of the local peer
    pub(crate) cluster_id: ClusterId,
    /// The public key of the local peer
    pub(super) local_keypair: Keypair,
    /// The join handle of the executor loop
    pub(super) thread_handle: Option<JoinHandle<NetworkManagerError>>,
    /// The join handle of the cancellation relay
    pub(super) cancellation_relay_handle: Option<JoinHandle<NetworkManagerError>>,
}

/// The NetworkManager handles both incoming and outbound messages to the p2p network
/// It accepts events from workers elsewhere in the relayer that are to be propagated
/// out to the network; as well as listening on the network for messages from other peers.
impl NetworkManager {
    /// Setup global state after peer_id and address have been assigned
    pub(super) fn update_global_state_after_startup(&self) {
        // Add self to peer info index
        self.config.global_state.add_single_peer(
            self.local_peer_id,
            PeerInfo::new_with_cluster_secret_key(
                self.local_peer_id,
                self.cluster_id.clone(),
                self.local_addr.clone(),
                self.config.cluster_keypair.as_ref().unwrap(),
            ),
        );
    }

    /// Setup pubsub subscriptions for the network manager
    pub(super) fn setup_pubsub_subscriptions(
        &self,
        swarm: &mut Swarm<ComposedNetworkBehavior>,
    ) -> Result<(), NetworkManagerError> {
        for topic in [
            self.cluster_id.get_management_topic(), // Cluster management for local cluster
            ORDER_BOOK_TOPIC.to_string(),           // Network order book management
        ]
        .iter()
        {
            swarm
                .behaviour_mut()
                .pubsub
                .subscribe(&Sha256Topic::new(topic))
                .map_err(|err| NetworkManagerError::SetupError(err.to_string()))?;
        }

        Ok(())
    }
}

// ------------
// | Executor |
// ------------

/// Represents a pubsub message that is buffered during the gossip warmup period
#[derive(Clone, Debug)]
struct BufferedPubsubMessage {
    /// The topic this message should be pushed onto
    pub topic: String,
    /// The underlying message that should be forwarded to the network
    pub message: PubsubMessage,
}

/// The executor abstraction runs in a thread separately from the network manager
///
/// This allows the thread to take ownership of the executor object and perform
/// object-oriented operations while allowing the network manager ownership to be
/// held by the coordinator thread
pub(super) struct NetworkManagerExecutor {
    /// The peer ID of the local node
    local_peer_id: WrappedPeerId,
    /// The local cluster's keypair, used to sign and authenticate requests
    cluster_key: SigKeypair,
    /// Whether or not the warmup period has already elapsed
    warmup_finished: bool,
    /// The messages buffered during the warmup period
    warmup_buffer: Vec<BufferedPubsubMessage>,
    /// The underlying swarm that manages low level network behavior
    swarm: Swarm<ComposedNetworkBehavior>,
    /// The channel to receive outbound requests on from other workers
    send_channel: UnboundedReceiver<GossipOutbound>,
    /// The sender for the gossip server's work queue
    gossip_work_queue: Sender<GossipServerJob>,
    /// The sender for the handshake manager's work queue
    handshake_work_queue: Sender<HandshakeExecutionJob>,
    /// A copy of the relayer-global state
    #[allow(unused)]
    global_state: RelayerState,
    /// The cancel channel that the coordinator thread may use to cancel this worker
    cancel: Receiver<()>,
}

impl NetworkManagerExecutor {
    /// Create a new executor
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        local_peer_id: WrappedPeerId,
        cluster_key: SigKeypair,
        swarm: Swarm<ComposedNetworkBehavior>,
        send_channel: UnboundedReceiver<GossipOutbound>,
        gossip_work_queue: Sender<GossipServerJob>,
        handshake_work_queue: Sender<HandshakeExecutionJob>,
        global_state: RelayerState,
        cancel: Receiver<()>,
    ) -> Self {
        Self {
            local_peer_id,
            cluster_key,
            warmup_finished: false,
            warmup_buffer: Vec::new(),
            swarm,
            send_channel,
            gossip_work_queue,
            handshake_work_queue,
            global_state,
            cancel,
        }
    }

    /// The main loop in which the worker thread processes requests
    /// The worker handles two types of events:
    ///      1. Events from the network; which it dispatches to appropriate handler threads
    ///      2. Events from workers to be sent over the network
    /// It handles these in the tokio select! macro below
    pub(super) async fn executor_loop(mut self) -> NetworkManagerError {
        log::info!("Starting executor loop for network manager...");
        loop {
            tokio::select! {
                // Handle network requests from worker components of the relayer
                Some(message) = self.send_channel.recv() => {
                    // Forward the message
                    if let Err(err) = self.handle_outbound_message(message) {
                        log::info!("Error sending outbound message: {}", err);
                    }
                },

                // Handle network events and dispatch
                event = self.swarm.select_next_some() => {
                    match event {
                        SwarmEvent::Behaviour(event) => {
                            if let Err(err) = self.handle_inbound_message(
                                event,
                            ) {
                                log::info!("error in network manager: {:?}", err);
                            }
                        },
                        SwarmEvent::NewListenAddr { address, .. } => {
                            log::info!("Listening on {}/p2p/{}\n", address, self.local_peer_id);
                        },
                        // This catchall may be enabled for fine-grained libp2p introspection
                        _ => {  }
                    }
                }

                // Handle a cancel signal from the coordinator
                _ = self.cancel.recv() => {
                    return NetworkManagerError::Cancelled("received cancel signal".to_string())
                }
            }
        }
    }

    /// Handles a network event from the relayer's protocol
    fn handle_inbound_message(
        &mut self,
        message: ComposedProtocolEvent,
    ) -> Result<(), NetworkManagerError> {
        match message {
            ComposedProtocolEvent::RequestResponse(request_response) => {
                if let RequestResponseEvent::Message { peer, message } = request_response {
                    self.handle_inbound_request_response_message(peer, message)?;
                }

                Ok(())
            }
            // Pubsub events currently do nothing
            ComposedProtocolEvent::PubSub(msg) => {
                if let GossipsubEvent::Message { message, .. } = msg {
                    self.handle_inbound_pubsub_message(message)?;
                }

                Ok(())
            }
            // KAD events do nothing for now, routing tables are automatically updated by libp2p
            ComposedProtocolEvent::Kademlia(_) => Ok(()),

            // Identify events do nothing for now, the behavior automatically updates the `external_addresses`
            // field in the swarm
            ComposedProtocolEvent::Identify(_) => Ok(()),
        }
    }

    /// Handles an outbound message from worker threads to other relayers
    fn handle_outbound_message(&mut self, msg: GossipOutbound) -> Result<(), NetworkManagerError> {
        match msg {
            GossipOutbound::Request { peer_id, message } => {
                // Attach a signature if necessary
                let req_body =
                    AuthenticatedGossipRequest::new_with_body(message, &self.cluster_key)
                        .map_err(|err| NetworkManagerError::Authentication(err.to_string()))?;

                self.swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&peer_id, req_body);

                Ok(())
            }
            GossipOutbound::Response { channel, message } => {
                // Attach a signature if necessary
                let req_body =
                    AuthenticatedGossipResponse::new_with_body(message, &self.cluster_key)
                        .map_err(|err| NetworkManagerError::Authentication(err.to_string()))?;

                self.swarm
                    .behaviour_mut()
                    .request_response
                    .send_response(channel, req_body)
                    .map_err(|_| {
                        NetworkManagerError::Network(
                            "error sending response, channel closed".to_string(),
                        )
                    })
            }
            Pubsub { topic, message } => self.forward_outbound_pubsub(topic, message),
            GossipOutbound::ManagementMessage(command) => self.handle_control_directive(command),
        }
    }

    /// Forward an outbound pubsub message to the network
    fn forward_outbound_pubsub(
        &mut self,
        topic: String,
        message: PubsubMessage,
    ) -> Result<(), NetworkManagerError> {
        // If the gossip server has not warmed up the local node into the network, buffer
        // the pubsub message for forwarding after the warmup
        if !self.warmup_finished {
            self.warmup_buffer
                .push(BufferedPubsubMessage { topic, message });
            return Ok(());
        }

        // If we require a signature on the message attach one
        let req_body = AuthenticatedPubsubMessage::new_with_body(message, &self.cluster_key)
            .map_err(|err| NetworkManagerError::Authentication(err.to_string()))?;

        // Forward to the network
        let topic = Sha256Topic::new(topic);
        self.swarm
            .behaviour_mut()
            .pubsub
            .publish(topic, req_body)
            .map_err(|err| NetworkManagerError::Network(err.to_string()))?;
        Ok(())
    }

    // ------------------------------
    // | Control Directive Handlers |
    // ------------------------------

    /// Handles a message from another worker module that explicitly directs the network manager
    /// to take some action
    ///
    /// The end destination of these messages is not a network peer, but the local network manager
    /// itself
    fn handle_control_directive(
        &mut self,
        command: ManagerControlDirective,
    ) -> Result<(), NetworkManagerError> {
        match command {
            // Register a new peer in the distributed routing tables
            ManagerControlDirective::NewAddr { peer_id, address } => {
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
                let party_id = local_role.get_party_id();
                let local_addr: SocketAddr = format!("127.0.0.1:{:?}", local_port).parse().unwrap();

                // Connect on a side-channel to the peer
                let mpc_net = match local_role {
                    ConnectionRole::Dialer => {
                        // Retrieve known dialable addresses for the peer from the network behavior
                        let all_peer_addrs = self.swarm.behaviour_mut().addresses_of_peer(&peer_id);
                        let peer_multiaddr = all_peer_addrs.get(0).ok_or_else(|| {
                            NetworkManagerError::Network(ERR_NO_KNOWN_ADDR.to_string())
                        })?;
                        let peer_addr = multiaddr_to_socketaddr(peer_multiaddr.clone(), peer_port)
                            .ok_or_else(|| {
                                NetworkManagerError::SerializeDeserialize(
                                    ERR_PARSING_ADDR.to_string(),
                                )
                            })?;

                        // Build an MPC net and dial the connection as the king party
                        QuicTwoPartyNet::new(party_id, local_addr, peer_addr)
                    }
                    ConnectionRole::Listener => {
                        // As the listener, the peer address is inconsequential, and can be a dummy value
                        let peer_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
                        QuicTwoPartyNet::new(party_id, local_addr, peer_addr)
                    }
                };

                // After the dependencies are injected into the network; forward it to the handshake manager to
                // dial the peer and begin the MPC
                self.handshake_work_queue
                    .send(HandshakeExecutionJob::MpcNetSetup {
                        request_id,
                        party_id,
                        net: mpc_net,
                    })
                    .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string()))?;
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

    // -----------------------------
    // | Request/Response Handlers |
    // -----------------------------

    /// Handle an incoming message from the network's request/response protocol
    fn handle_inbound_request_response_message(
        &mut self,
        peer_id: PeerId,
        message: RequestResponseMessage<AuthenticatedGossipRequest, AuthenticatedGossipResponse>,
    ) -> Result<(), NetworkManagerError> {
        // Multiplex over request/response message types
        match message {
            // Handle inbound request from another peer
            RequestResponseMessage::Request {
                request, channel, ..
            } => {
                // Authenticate the request
                if !request.verify_cluster_auth(&self.cluster_key.public) {
                    return Err(NetworkManagerError::Authentication(
                        ERR_SIG_VERIFY.to_string(),
                    ));
                }

                match request.body {
                    // Forward the bootstrap request directly to the gossip server
                    GossipRequest::Bootstrap(req) => self
                        .gossip_work_queue
                        .send(GossipServerJob::Bootstrap(req, channel))
                        .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string())),

                    GossipRequest::Heartbeat(heartbeat_message) => self
                        .gossip_work_queue
                        .send(GossipServerJob::HandleHeartbeatReq {
                            peer_id: WrappedPeerId(peer_id),
                            message: heartbeat_message,
                            channel,
                        })
                        .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string())),

                    GossipRequest::Handshake {
                        request_id,
                        message,
                    } => self
                        .handshake_work_queue
                        .send(HandshakeExecutionJob::ProcessHandshakeMessage {
                            request_id,
                            peer_id: WrappedPeerId(peer_id),
                            message,
                            response_channel: Some(channel),
                        })
                        .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string())),

                    GossipRequest::OrderInfo(req) => self
                        .gossip_work_queue
                        .send(GossipServerJob::OrderBookManagement(
                            OrderBookManagementJob::OrderInfo {
                                order_id: req.order_id,
                                response_channel: channel,
                            },
                        ))
                        .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string())),

                    GossipRequest::Replicate(replicate_message) => {
                        self.gossip_work_queue
                            .send(GossipServerJob::Cluster(
                                ClusterManagementJob::ReplicateRequest(replicate_message),
                            ))
                            .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string()))?;

                        // Send a simple ack back to avoid closing the channel
                        self.swarm
                            .behaviour_mut()
                            .request_response
                            .send_response(channel, AuthenticatedGossipResponse::new_ack())
                            .map_err(|_| {
                                NetworkManagerError::Network("error sending Ack".to_string())
                            })
                    }

                    GossipRequest::ValidityProof { order_id, proof } => {
                        // TODO: Authenticate this
                        self.gossip_work_queue
                            .send(GossipServerJob::Cluster(
                                ClusterManagementJob::UpdateValidityProof(order_id, proof),
                            ))
                            .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string()))
                    }

                    GossipRequest::ValidityWitness { order_id, witness } => {
                        self.gossip_work_queue
                            .send(GossipServerJob::OrderBookManagement(
                                OrderBookManagementJob::OrderWitnessResponse { order_id, witness },
                            ))
                            .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string()))?;

                        // Send back an ack
                        self.handle_outbound_message(GossipOutbound::Response {
                            channel,
                            message: GossipResponse::Ack,
                        })
                    }
                }
            }

            // Handle inbound response
            RequestResponseMessage::Response { response, .. } => {
                if !response.verify_cluster_auth(&self.cluster_key.public) {
                    return Err(NetworkManagerError::Authentication(
                        ERR_SIG_VERIFY.to_string(),
                    ));
                }

                match response.body {
                    GossipResponse::Ack => Ok(()),

                    GossipResponse::Heartbeat(heartbeat_message) => self
                        .gossip_work_queue
                        .send(GossipServerJob::HandleHeartbeatResp {
                            peer_id: WrappedPeerId(peer_id),
                            message: heartbeat_message,
                        })
                        .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string())),

                    GossipResponse::Handshake {
                        request_id,
                        message,
                    } => self
                        .handshake_work_queue
                        .send(HandshakeExecutionJob::ProcessHandshakeMessage {
                            request_id,
                            peer_id: WrappedPeerId(peer_id),
                            message,
                            // The handshake should response via a new request sent on the network manager channel
                            response_channel: None,
                        })
                        .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string())),

                    GossipResponse::OrderInfo(OrderInfoResponse { order_id, info }) => self
                        .gossip_work_queue
                        .send(GossipServerJob::OrderBookManagement(
                            OrderBookManagementJob::OrderInfoResponse { order_id, info },
                        ))
                        .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string())),
                }
            }
        }
    }

    // ------------------
    // | Pubsub Handlers |
    // -------------------

    /// Handle an incoming network request for a pubsub message
    fn handle_inbound_pubsub_message(
        &mut self,
        message: GossipsubMessage,
    ) -> Result<(), NetworkManagerError> {
        // Deserialize into API types and verify auth
        let event: AuthenticatedPubsubMessage = message.data.into();
        if !event.verify_cluster_auth(&self.cluster_key.public) {
            return Err(NetworkManagerError::Authentication(
                ERR_SIG_VERIFY.to_string(),
            ));
        }

        match event.body {
            PubsubMessage::ClusterManagement {
                cluster_id,
                message,
            } => {
                match message {
                    // --------------------
                    // | Cluster Metadata |
                    // --------------------

                    // Forward the management message to the gossip server for processing
                    ClusterManagementMessage::Join(join_request) => {
                        // Forward directly
                        self.gossip_work_queue
                            .send(GossipServerJob::Cluster(
                                ClusterManagementJob::ClusterJoinRequest(cluster_id, join_request),
                            ))
                            .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string()))?;
                    }

                    // Forward the management message to the gossip server for processing
                    ClusterManagementMessage::Replicated(ReplicatedMessage {
                        wallets,
                        peer_id,
                    }) => {
                        // Forward one job per replicated wallet; makes gossip server implementation cleaner
                        for wallet_id in wallets.into_iter() {
                            self.gossip_work_queue
                                .send(GossipServerJob::Cluster(
                                    ClusterManagementJob::AddWalletReplica { wallet_id, peer_id },
                                ))
                                .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string()))?;
                        }
                    }

                    // ---------
                    // | Match |
                    // ---------

                    // Forward the cache sync message to the handshake manager to update the local
                    // cache copy
                    ClusterManagementMessage::CacheSync(order1, order2) => self
                        .handshake_work_queue
                        .send(HandshakeExecutionJob::CacheEntry { order1, order2 })
                        .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string()))?,

                    // Forward the match in progress message to the handshake manager so that it can avoid
                    // scheduling a duplicate handshake for the given order pair
                    ClusterManagementMessage::MatchInProgress(order1, order2) => self
                        .handshake_work_queue
                        .send(HandshakeExecutionJob::PeerMatchInProgress { order1, order2 })
                        .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string()))?,

                    // -------------
                    // | Orderbook |
                    // -------------

                    // Forward a request for validity proofs to the gossip server to check for locally
                    // available proofs
                    ClusterManagementMessage::RequestOrderValidityProof(req) => {
                        self.gossip_work_queue
                            .send(GossipServerJob::Cluster(
                                ClusterManagementJob::ShareValidityProofs(req),
                            ))
                            .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string()))?;
                    }

                    //Forward a request to the gossip server to share validity proof witness
                    ClusterManagementMessage::RequestOrderValidityWitness(req) => self
                        .gossip_work_queue
                        .send(GossipServerJob::OrderBookManagement(
                            OrderBookManagementJob::OrderWitness {
                                order_id: req.order_id,
                                requesting_peer: req.sender,
                            },
                        ))
                        .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string()))?,
                }
            }
            PubsubMessage::OrderBookManagement(msg) => match msg {
                OrderBookManagementMessage::OrderReceived { order_id, match_nullifier, cluster } => self
                    .gossip_work_queue
                    .send(GossipServerJob::OrderBookManagement(
                        OrderBookManagementJob::OrderReceived { order_id, match_nullifier, cluster },
                    ))
                    .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string()))?,

                OrderBookManagementMessage::OrderProofUpdated {
                    order_id,
                    cluster,
                    proof,
                } => self
                    .gossip_work_queue
                    .send(GossipServerJob::OrderBookManagement(
                        OrderBookManagementJob::OrderProofUpdated {
                            order_id,
                            cluster,
                            proof,
                        },
                    ))
                    .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string()))?,
            },
        }

        Ok(())
    }
}
