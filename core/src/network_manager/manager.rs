//! The network manager handles lower level interaction with the p2p network

use crossbeam::channel::Sender;
use futures::StreamExt;
use libp2p::{
    identity::Keypair,
    request_response::{RequestResponseEvent, RequestResponseMessage},
    swarm::SwarmEvent,
    PeerId, Swarm,
};
use std::thread::JoinHandle;
use tokio::sync::mpsc::UnboundedReceiver;
use tracing::{event, Level};

use crate::{
    api::gossip::{GossipOutbound, GossipRequest, GossipResponse},
    gossip::{jobs::HeartbeatExecutorJob, types::WrappedPeerId},
    handshake::jobs::HandshakeExecutionJob,
};

use super::{
    composed_protocol::{ComposedNetworkBehavior, ComposedProtocolEvent},
    error::NetworkManagerError,
    worker::NetworkManagerConfig,
};

// Groups logic around monitoring and requesting the network
pub struct NetworkManager {
    /// The config passed from the coordinator thread
    pub(super) config: NetworkManagerConfig,
    /// The peerId of the locally running node
    pub(crate) local_peer_id: WrappedPeerId,
    /// The public key of the local peer
    pub(super) local_keypair: Keypair,
    /// The join handle of the executor loop
    pub(super) thread_handle: Option<JoinHandle<NetworkManagerError>>,
}

// The NetworkManager handles both incoming and outbound messages to the p2p network
// It accepts events from workers elsewhere in the relayer that are to be propagated
// out to the network; as well as listening on the network for messages from other peers.
impl NetworkManager {
    // The main loop in which the worker thread processes requests
    // The worker handles two types of events:
    //      1. Events from the network; which it dispatches to appropriate handler threads
    //      2. Events from workers to be sent over the network
    // It handles these in the tokio select! macro below
    pub(super) async fn executor_loop(
        local_peer_id: WrappedPeerId,
        mut swarm: Swarm<ComposedNetworkBehavior>,
        mut send_channel: UnboundedReceiver<GossipOutbound>,
        heartbeat_work_queue: Sender<HeartbeatExecutorJob>,
        handshake_work_queue: Sender<HandshakeExecutionJob>,
    ) -> Result<(), NetworkManagerError> {
        println!("Starting executor loop for network manager...");
        loop {
            tokio::select! {
                // Handle network requests from worker components of the relayer
                Some(message) = send_channel.recv() => {
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
            }
        }
    }

    // Handles an outbound message from worker threads to other relayers
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

            // Register a new peer in the distributed routing tables
            GossipOutbound::NewAddr { peer_id, address } => {
                swarm
                    .behaviour_mut()
                    .kademlia_dht
                    .add_address(&peer_id, address);
            }
        }
    }

    // Handles a network event from the relayer's protocol
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
            // KAD events do nothing for now, routing tables are automatically updated by libp2p
            ComposedProtocolEvent::Kademlia(_) => {}
        }
    }

    /**
     * Request/Response event handlers
     */

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
}
