//! The handshake module handles the execution of handshakes from negotiating
//! a pair of orders to match, all the way through settling any resulting match

use crossbeam::channel::Receiver;
use rand::{distributions::WeightedIndex, prelude::Distribution, rngs::OsRng, seq::SliceRandom};
use rayon::ThreadPool;
use std::{
    sync::Arc,
    thread::{self, JoinHandle},
    time::Duration,
};
use tokio::sync::mpsc::UnboundedSender;
use uuid::Uuid;

use crate::{
    api::{
        cluster_management::ClusterManagementMessage,
        gossip::{GossipOutbound, GossipRequest, GossipResponse, PubsubMessage},
        handshake::HandshakeMessage,
    },
    gossip::types::WrappedPeerId,
    state::RelayerState,
    CancelChannel,
};

use super::{
    error::HandshakeManagerError, handshake_cache::SharedHandshakeCache,
    jobs::HandshakeExecutionJob,
};

/// The default priority of a newly added node in the handshake priority list
pub const DEFAULT_HANDSHAKE_PRIORITY: u32 = 10;
/// The size of the LRU handshake cache
pub(super) const HANDSHAKE_CACHE_SIZE: usize = 500;
/// How frequently a new handshake is initiated from the local peer
pub(super) const HANDSHAKE_INTERVAL_MS: u64 = 2_000; // 2 seconds
/// Number of nanoseconds in a millisecond, for convenienc
const NANOS_PER_MILLI: u64 = 1_000_000;

/// TODO: Update this with a commitment to an order, UUID for testing
pub type OrderIdentifier = Uuid;

/// Manages requests to handshake from a peer and sends outbound requests to initiate
/// a handshake
pub struct HandshakeManager {
    /// The hanshake timer; periodically enqueues outbound handshake requests
    pub(super) timer: HandshakeTimer,
    /// The job realay; provides a shim between the network interface and the manager
    pub(super) relay: HandshakeJobRelay,
}

impl HandshakeManager {
    /// Perform a handshake, dummy job for now
    pub fn perform_handshake(
        peer_id: WrappedPeerId,
        global_state: RelayerState,
        network_channel: UnboundedSender<GossipOutbound>,
    ) {
        let managed_orders = global_state.get_managed_order_ids();
        let my_order = *managed_orders.choose(&mut rand::thread_rng()).unwrap();

        // Send a handshake message to the given peer_id
        // Panic if channel closed, no way to recover
        network_channel
            .send(GossipOutbound::Request {
                peer_id,
                message: GossipRequest::Handshake(HandshakeMessage::InitiateMatch {
                    sender_order: my_order,
                }),
            })
            .unwrap();
    }

    /// Handle a handshake message from the peer
    pub fn handle_handshake_job(
        job: HandshakeExecutionJob,
        global_state: RelayerState,
        handshake_cache: SharedHandshakeCache<OrderIdentifier>,
        network_channel: UnboundedSender<GossipOutbound>,
    ) -> Result<(), HandshakeManagerError> {
        match job {
            HandshakeExecutionJob::ProcessHandshakeMessage {
                peer_id,
                message,
                response_channel,
            } => {
                // Get a response for the message and forward it to the network
                let resp = Self::handle_handshake_message(
                    message,
                    global_state,
                    handshake_cache,
                    network_channel.clone(),
                )?;
                if let Some(response_message) = resp {
                    let outbound_request = if let Some(channel) = response_channel {
                        GossipOutbound::Response {
                            channel,
                            message: GossipResponse::Handshake(response_message),
                        }
                    } else {
                        GossipOutbound::Request {
                            peer_id,
                            message: GossipRequest::Handshake(response_message),
                        }
                    };

                    network_channel
                        .send(outbound_request)
                        .map_err(|err| HandshakeManagerError::SendMessage(err.to_string()))?;
                }

                Ok(())
            }

            HandshakeExecutionJob::CacheEntry { order1, order2 } => {
                handshake_cache
                    .write()
                    .expect("handshake_cache lock poisoned")
                    .push(order1, order2);

                Ok(())
            }
        }
    }

    /// Respond to a handshake request from a peer
    ///
    /// Returns an optional response; none if no response is to be sent
    /// The caller should handle forwarding the response onto the network
    pub fn handle_handshake_message(
        message: HandshakeMessage,
        global_state: RelayerState,
        handshake_cache: SharedHandshakeCache<OrderIdentifier>,
        network_channel: UnboundedSender<GossipOutbound>,
    ) -> Result<Option<HandshakeMessage>, HandshakeManagerError> {
        match message {
            // A peer has requested a match, find an order that has not already been matched with theirs
            // and propose it back to the peer
            HandshakeMessage::InitiateMatch {
                sender_order: peer_order,
            } => {
                // TODO: Dummy data, remove this
                let mut proposed_order = None;
                {
                    let locked_handshake_cache = handshake_cache
                        .read()
                        .expect("handshake_cache lock poisoned");
                    for order in global_state.get_managed_order_ids().iter() {
                        if !locked_handshake_cache.contains(*order, peer_order) {
                            proposed_order = Some(*order);
                            break;
                        }
                    }
                } // locked_handshake_cache released

                // Send the message and unwrap the result; the only error type possible
                // is that the channel is closed, so panic the thread in that case
                Ok(Some(HandshakeMessage::ProposeMatchCandidate {
                    sender_order: proposed_order,
                    peer_order,
                }))
            }

            // A peer has responded to the local node's InitiateMatch message with a proposed match pair.
            // Check that their proposal has not already been matched and then signal to begin the match
            HandshakeMessage::ProposeMatchCandidate {
                peer_order: my_order,
                sender_order,
            } => {
                // If sender_order is None, the peer has no order to match with ours
                if let Some(peer_order) = sender_order {
                    let previously_matched = {
                        let locked_handshake_cache = handshake_cache
                            .read()
                            .expect("handshake_cache lock poisoned");
                        locked_handshake_cache.contains(my_order, peer_order)
                    }; // locked_handshake_cache released

                    Ok(Some(HandshakeMessage::ExecuteMatch {
                        previously_matched,
                        order1: my_order,
                        order2: peer_order,
                    }))
                } else {
                    Ok(None)
                }
            }

            HandshakeMessage::ExecuteMatch { order1, order2, .. } => {
                // Cache the result of a handshake
                handshake_cache
                    .write()
                    .expect("handshake_cache lock poisoned")
                    .push(order1, order2);

                // Write to global state for debugging
                global_state
                    .write_matched_order_pairs()
                    .push((order1, order2));

                // Send back the message as an ack
                Ok(Some(HandshakeMessage::ExecutionFinished { order1, order2 }))
            }

            HandshakeMessage::ExecutionFinished { order1, order2 } => {
                // Cache the order pair as completed
                handshake_cache
                    .write()
                    .expect("handshake_cache lock poiseoned")
                    .push(order1, order2);

                // Write to global state for debugging
                global_state
                    .write_matched_order_pairs()
                    .push((order1, order2));

                // Send a message to cluster peers indicating the handshake has finished
                let locked_cluster_id = global_state.read_cluster_id();
                network_channel
                    .send(GossipOutbound::Pubsub {
                        topic: locked_cluster_id.get_management_topic(),
                        message: PubsubMessage::new_cluster_management_unsigned(
                            locked_cluster_id.clone(),
                            ClusterManagementMessage::CacheSync(order1, order2),
                        ),
                    })
                    .map_err(|err| HandshakeManagerError::SendMessage(err.to_string()))?;

                Ok(None)
            }
        }
    }
}

/// Implements a timer that periodically enqueues jobs to the threadpool that
/// tell the manager to send outbound handshake requests
pub(super) struct HandshakeTimer {
    /// The join handle of the thread executing timer interrupts
    thread_handle: Option<thread::JoinHandle<HandshakeManagerError>>,
}

impl HandshakeTimer {
    /// Construct a new timer
    pub fn new(
        thread_pool: Arc<ThreadPool>,
        global_state: RelayerState,
        network_channel: UnboundedSender<GossipOutbound>,
        cancel: CancelChannel,
    ) -> Result<Self, HandshakeManagerError> {
        let interval_seconds = HANDSHAKE_INTERVAL_MS / 1000;
        let interval_nanos = (HANDSHAKE_INTERVAL_MS % 1000 * NANOS_PER_MILLI) as u32;

        let refresh_interval = Duration::new(interval_seconds, interval_nanos);

        // Spawn the execution loop
        let thread_handle = thread::Builder::new()
            .name("handshake-manager-timer".to_string())
            .spawn(move || {
                Self::execution_loop(
                    refresh_interval,
                    thread_pool,
                    global_state,
                    network_channel,
                    cancel,
                )
            })
            .map_err(|err| HandshakeManagerError::SetupError(err.to_string()))?;

        Ok(HandshakeTimer {
            thread_handle: Some(thread_handle),
        })
    }

    /// Consume the join handle for the executor thread, this leaves no join handle in
    /// its place, meaning this can only be called once
    pub fn join_handle(&mut self) -> JoinHandle<HandshakeManagerError> {
        self.thread_handle.take().unwrap()
    }

    /// The execution loop of the timer, periodically enqueues handshake jobs
    fn execution_loop(
        refresh_interval: Duration,
        thread_pool: Arc<ThreadPool>,
        global_state: RelayerState,
        network_channel: UnboundedSender<GossipOutbound>,
        cancel: CancelChannel,
    ) -> HandshakeManagerError {
        let mut rng = OsRng {};
        // Enqueue handshakes periodically
        loop {
            // Sample a peer to handshake with
            let random_peer = {
                let locked_priorities = global_state.read_handshake_priorities();
                let mut peers = Vec::with_capacity(locked_priorities.len());
                let mut priorities: Vec<u32> = Vec::with_capacity(locked_priorities.len());

                for (peer, priority) in locked_priorities.iter() {
                    peers.push(*peer);
                    priorities.push((*priority).into());
                }

                if !peers.is_empty() {
                    let distribution = WeightedIndex::new(&priorities).unwrap();
                    Some(*peers.get(distribution.sample(&mut rng)).unwrap())
                } else {
                    None
                }
            }; // locked_priorities released

            // Enqueue a job to handshake with the randomly selected peer
            if let Some(selected_peer) = random_peer {
                let sender_copy = network_channel.clone();
                let state_copy = global_state.clone();
                thread_pool.install(move || {
                    HandshakeManager::perform_handshake(selected_peer, state_copy, sender_copy);
                });
            }

            // Check for a cancel signal before sleeping and after
            if !cancel.is_empty() {
                return HandshakeManagerError::Cancelled("received cancel signal".to_string());
            }

            thread::sleep(refresh_interval);
            if !cancel.is_empty() {
                return HandshakeManagerError::Cancelled("received cancel signal".to_string());
            }
        }
    }
}

/// Implements a listener that relays from a crossbeam channel to the handshake threadpool
/// Used as a layer of indirection to provide a consistent interface at the network level
pub(super) struct HandshakeJobRelay {
    /// The join handle of the thread executing the handshake relay
    thread_handle: Option<JoinHandle<HandshakeManagerError>>,
}

impl HandshakeJobRelay {
    /// Create a new job relay
    pub fn new(
        thread_pool: Arc<ThreadPool>,
        handshake_cache: SharedHandshakeCache<OrderIdentifier>,
        job_channel: Receiver<HandshakeExecutionJob>,
        network_channel: UnboundedSender<GossipOutbound>,
        global_state: RelayerState,
        cancel: CancelChannel,
    ) -> Result<Self, HandshakeManagerError> {
        let thread_handle = thread::Builder::new()
            .name("handshake-job-relay".to_string())
            .spawn(move || {
                Self::execution_loop(
                    thread_pool,
                    handshake_cache,
                    job_channel,
                    network_channel,
                    global_state,
                    cancel,
                )
            })
            .map_err(|err| HandshakeManagerError::SetupError(err.to_string()))?;

        Ok(HandshakeJobRelay {
            thread_handle: Some(thread_handle),
        })
    }

    /// Consumes the join handle that the executor operates on, leaving `None` in its
    /// place. This means that this method may only be called once
    pub fn join_handle(&mut self) -> JoinHandle<HandshakeManagerError> {
        self.thread_handle.take().unwrap()
    }

    /// The main execution loop, listens on the channel and forwards jobs to the handshake manager
    fn execution_loop(
        thread_pool: Arc<ThreadPool>,
        handshake_cache: SharedHandshakeCache<OrderIdentifier>,
        job_channel: Receiver<HandshakeExecutionJob>,
        network_channel: UnboundedSender<GossipOutbound>,
        global_state: RelayerState,
        cancel: CancelChannel,
    ) -> HandshakeManagerError {
        loop {
            // Check if the coordinator has cancelled the handshake manager
            if !cancel.is_empty() {
                return HandshakeManagerError::Cancelled("received cancel signal".to_string());
            }

            // Wait for the next message and forward to the thread pool
            let job = job_channel.recv().unwrap();
            let state_clone = global_state.clone();
            let cache_clone = handshake_cache.clone();
            let channel_clone = network_channel.clone();

            thread_pool.install(move || {
                if let Err(err) = HandshakeManager::handle_handshake_job(
                    job,
                    state_clone,
                    cache_clone,
                    channel_clone,
                ) {
                    println!("Error handling handshake job: {}", err);
                }
            })
        }
    }
}
