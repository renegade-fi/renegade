//! The network manager handles lower level interaction with the p2p network

use crossbeam::channel::Sender;
use ed25519_dalek::{Digest, Sha512, Signature};
use futures::StreamExt;
use libp2p::{
    gossipsub::{GossipsubEvent, GossipsubMessage, Sha256Topic},
    identity::Keypair,
    request_response::{RequestResponseEvent, RequestResponseMessage},
    swarm::SwarmEvent,
    PeerId, Swarm,
};
use std::thread::JoinHandle;
use tokio::sync::mpsc::{Receiver, UnboundedReceiver};
use tracing::{event, Level};

use crate::{
    api::gossip::{
        GossipOutbound, GossipOutbound::Pubsub, GossipRequest, GossipResponse, PubsubMessage,
    },
    gossip::{
        jobs::HeartbeatExecutorJob,
        types::{ClusterId, WrappedPeerId},
    },
    handshake::jobs::HandshakeExecutionJob,
};

use super::{
    composed_protocol::{ComposedNetworkBehavior, ComposedProtocolEvent},
    error::NetworkManagerError,
    worker::NetworkManagerConfig,
};

/// Groups logic around monitoring and requesting the network
pub struct NetworkManager {
    /// The config passed from the coordinator thread
    pub(super) config: NetworkManagerConfig,
    /// The peerId of the locally running node
    pub(crate) local_peer_id: WrappedPeerId,
    /// The cluster ID of the local perr
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
    /// Setup pubsub subscriptions for the network manager
    pub(super) fn setup_pubsub_subscriptions(
        &self,
        swarm: &mut Swarm<ComposedNetworkBehavior>,
    ) -> Result<(), NetworkManagerError> {
        // Cluster management topic for the local peer's cluster
        swarm
            .behaviour_mut()
            .pubsub
            .subscribe(&Sha256Topic::new(self.cluster_id.get_management_topic()))
            .map_err(|err| NetworkManagerError::SetupError(err.to_string()))?;

        Ok(())
    }

    /// The main loop in which the worker thread processes requests
    /// The worker handles two types of events:
    ///      1. Events from the network; which it dispatches to appropriate handler threads
    ///      2. Events from workers to be sent over the network
    /// It handles these in the tokio select! macro below
    pub(super) async fn executor_loop(
        local_peer_id: WrappedPeerId,
        mut swarm: Swarm<ComposedNetworkBehavior>,
        mut send_channel: UnboundedReceiver<GossipOutbound>,
        heartbeat_work_queue: Sender<HeartbeatExecutorJob>,
        handshake_work_queue: Sender<HandshakeExecutionJob>,
        mut cancel: Receiver<()>,
    ) -> NetworkManagerError {
        println!("Starting executor loop for network manager...");
        loop {
            tokio::select! {
                // Handle network requests from worker components of the relayer
                Some(message) = send_channel.recv() => {
                    // Check that
                    // Forward the message
                    Self::handle_outbound_message(message, &mut swarm);
                },

                // Handle network events and dispatch
                event = swarm.select_next_some() => {
                    match event {
                        SwarmEvent::Behaviour(event) => {
                            Self::handle_inbound_messsage(
                                event,
                                heartbeat_work_queue.clone(),
                                handshake_work_queue.clone()
                            )
                        },
                        SwarmEvent::NewListenAddr { address, .. } => {
                            println!("Listening on {}/p2p/{}\n", address, local_peer_id);
                        },
                        _ => {  }
                    }
                }

                // Handle a cancel signal from the coordinator
                _ = cancel.recv() => {
                    return NetworkManagerError::Cancelled("received cancel signal".to_string())
                }
            }
        }
    }

    /// Handles an outbound message from worker threads to other relayers
    fn handle_outbound_message(msg: GossipOutbound, swarm: &mut Swarm<ComposedNetworkBehavior>) {
        match msg {
            GossipOutbound::Request { peer_id, message } => {
                swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&peer_id, message);
            }
            GossipOutbound::Response { channel, message } => {
                let res = swarm
                    .behaviour_mut()
                    .request_response
                    .send_response(channel, message);

                // Log errors on response
                if let Err(msg) = res {
                    event!(Level::DEBUG, message = ?msg, "error sending response");
                }
            }
            Pubsub { topic, message } => {
                let topic = Sha256Topic::new(topic);
                let res = swarm.behaviour_mut().pubsub.publish(topic, message);

                if let Err(msg) = res {
                    event!(Level::ERROR, message = ?msg, "error broadcasting pubsub message")
                }
            }
            // Register a new peer in the distributed routing tables
            GossipOutbound::NewAddr { peer_id, address } => {
                swarm
                    .behaviour_mut()
                    .kademlia_dht
                    .add_address(&peer_id, address);
            }
        }
    }

    /// Handles a network event from the relayer's protocol
    fn handle_inbound_messsage(
        message: ComposedProtocolEvent,
        heartbeat_work_queue: Sender<HeartbeatExecutorJob>,
        handshake_work_queue: Sender<HandshakeExecutionJob>,
    ) {
        match message {
            ComposedProtocolEvent::RequestResponse(request_response) => {
                if let RequestResponseEvent::Message { peer, message } = request_response {
                    Self::handle_inbound_request_response_message(
                        peer,
                        message,
                        heartbeat_work_queue,
                        handshake_work_queue,
                    );
                }
            }
            // Pubsub events currently do nothing
            ComposedProtocolEvent::PubSub(msg) => {
                if let GossipsubEvent::Message { message, .. } = msg {
                    if let Err(err) = Self::handle_inbound_pubsub_message(message) {
                        println!("Pubsub handler failed: {:?}", err);
                        event!(Level::ERROR, message = ?err, "error handling pubsub message");
                    }
                }
            }
            // KAD events do nothing for now, routing tables are automatically updated by libp2p
            ComposedProtocolEvent::Kademlia(_) => {}
        }
    }

    /**
     * Request/Response event handlers
     */

    /// Handle an incoming message from the network's request/response protocol
    fn handle_inbound_request_response_message(
        peer_id: PeerId,
        message: RequestResponseMessage<GossipRequest, GossipResponse>,
        heartbeat_work_queue: Sender<HeartbeatExecutorJob>,
        handshake_work_queue: Sender<HandshakeExecutionJob>,
    ) {
        // Multiplex over request/response message types
        match message {
            // Handle inbound request from another peer
            RequestResponseMessage::Request {
                request, channel, ..
            } => match request {
                GossipRequest::Heartbeat(heartbeat_message) => {
                    heartbeat_work_queue
                        .send(HeartbeatExecutorJob::HandleHeartbeatReq {
                            peer_id: WrappedPeerId(peer_id),
                            message: heartbeat_message,
                            channel,
                        })
                        .unwrap();
                }
                GossipRequest::Handshake(handshake_message) => {
                    handshake_work_queue
                        .send(HandshakeExecutionJob::ProcessHandshakeRequest {
                            peer_id: WrappedPeerId(peer_id),
                            message: handshake_message,
                            response_channel: channel,
                        })
                        .unwrap();
                }
            },

            // Handle inbound response
            RequestResponseMessage::Response { response, .. } => match response {
                GossipResponse::Heartbeat(heartbeat_message) => {
                    heartbeat_work_queue
                        .send(HeartbeatExecutorJob::HandleHeartbeatResp {
                            peer_id: WrappedPeerId(peer_id),
                            message: heartbeat_message,
                        })
                        .unwrap();
                }
                GossipResponse::Handshake() => {}
            },
        }
    }

    /**
     * Pubsub handlers
     */

    /// Handle an incoming network request for a pubsub message
    fn handle_inbound_pubsub_message(message: GossipsubMessage) -> Result<(), NetworkManagerError> {
        // Deserialize into API types
        let event: PubsubMessage = message.data.into();
        match event {
            PubsubMessage::Join(join_message, signature) => {
                // Authenticate the join request
                let pubkey = join_message
                    .cluster_id
                    .get_public_key()
                    .map_err(|err| NetworkManagerError::SerializeDeserialize(err.to_string()))?;

                let join_signature = Signature::from_bytes(&signature)
                    .map_err(|err| NetworkManagerError::SerializeDeserialize(err.to_string()))?;

                // Hash the message and verify the input
                let mut hash_digest: Sha512 = Sha512::new();
                hash_digest.update(&Into::<Vec<u8>>::into(&join_message));
                pubkey
                    .verify_prehashed(hash_digest, None, &join_signature)
                    .map_err(|err| NetworkManagerError::Authentication(err.to_string()))?;

                println!(
                    "Peer {:?} joined cluster: {:?}",
                    join_message.peer_id, join_message.cluster_id
                );
            }
        }

        Ok(())
    }
}
