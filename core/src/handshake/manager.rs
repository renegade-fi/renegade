//! The handshake module handles the execution of handshakes from negotiating
//! a pair of orders to match, all the way through settling any resulting match

use circuits::{
    mpc::SharedFabric, mpc_circuits::r#match::compute_match, types::order::Order, Allocate, Open,
};
use crossbeam::channel::Receiver;
use futures::executor::block_on;
use integration_helpers::mpc_network::mocks::PartyIDBeaverSource;
use mpc_ristretto::{fabric::AuthenticatedMpcFabric, network::QuicTwoPartyNet};
use portpicker::pick_unused_port;
use rand::{distributions::WeightedIndex, prelude::Distribution, rngs::OsRng, seq::SliceRandom};
use rayon::ThreadPool;
use std::{
    cell::RefCell,
    rc::Rc,
    sync::Arc,
    thread::{self, JoinHandle},
    time::Duration,
};
use tokio::{runtime::Builder as TokioBuilder, sync::mpsc::UnboundedSender};
use uuid::Uuid;

use crate::{
    api::{
        cluster_management::ClusterManagementMessage,
        gossip::{ConnectionRole, GossipOutbound, GossipRequest, GossipResponse, PubsubMessage},
        handshake::HandshakeMessage,
    },
    gossip::types::WrappedPeerId,
    state::RelayerState,
    CancelChannel,
};

use super::{
    error::HandshakeManagerError,
    handshake_cache::SharedHandshakeCache,
    jobs::HandshakeExecutionJob,
    state::{HandshakeStateIndex, State},
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
        handshake_state_index: HandshakeStateIndex,
        global_state: RelayerState,
        network_channel: UnboundedSender<GossipOutbound>,
    ) {
        let managed_orders = global_state.get_managed_order_ids();
        let my_order = managed_orders
            .choose(&mut rand::thread_rng())
            .unwrap()
            .to_owned();

        // Send a handshake message to the given peer_id
        // Panic if channel closed, no way to recover
        let request_id = Uuid::new_v4();
        network_channel
            .send(GossipOutbound::Request {
                peer_id,
                message: GossipRequest::Handshake {
                    request_id,
                    message: HandshakeMessage::InitiateMatch {
                        peer_id: *global_state.read_peer_id(),
                        sender_order: my_order.0,
                    },
                },
            })
            .unwrap();

        handshake_state_index.new_handshake(request_id, my_order.0, my_order.1);
    }

    /// Handle a handshake message from the peer
    pub fn handle_handshake_job(
        job: HandshakeExecutionJob,
        handshake_state_index: HandshakeStateIndex,
        global_state: RelayerState,
        handshake_cache: SharedHandshakeCache<OrderIdentifier>,
        network_channel: UnboundedSender<GossipOutbound>,
    ) -> Result<(), HandshakeManagerError> {
        match job {
            HandshakeExecutionJob::ProcessHandshakeMessage {
                request_id,
                peer_id,
                message,
                response_channel,
            } => {
                // Get a response for the message and forward it to the network
                let resp = Self::handle_handshake_message(
                    request_id,
                    message,
                    handshake_state_index,
                    global_state,
                    handshake_cache,
                    network_channel.clone(),
                )?;
                if let Some(response_message) = resp {
                    let outbound_request = if let Some(channel) = response_channel {
                        GossipOutbound::Response {
                            channel,
                            message: GossipResponse::Handshake {
                                request_id,
                                message: response_message,
                            },
                        }
                    } else {
                        GossipOutbound::Request {
                            peer_id,
                            message: GossipRequest::Handshake {
                                request_id,
                                message: response_message,
                            },
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

            HandshakeExecutionJob::MpcNetSetup {
                request_id,
                party_id,
                net,
            } => {
                // Place the handshake in the execution state
                handshake_state_index.in_progress(&request_id);

                // Fetch the local handshake state to get an order for the MPC
                let order_state =
                    handshake_state_index
                        .get_state(&request_id)
                        .ok_or_else(|| {
                            HandshakeManagerError::InvalidRequest(format!(
                                "request_id: {:?}",
                                request_id
                            ))
                        })?;

                let local_order = {
                    if let State::MatchInProgress { local_order, .. } = order_state.state {
                        Some(local_order)
                    } else {
                        None
                    }
                }
                .ok_or_else(|| {
                    HandshakeManagerError::InvalidRequest(format!("request_id: {}", request_id))
                })?;

                // Build a tokio runtime in the current thread for the MPC to run inside of
                // This is necessary to allow quinn access to a Tokio reactor at runtime
                let tid = thread::current().id();
                let tokio_runtime = TokioBuilder::new_multi_thread()
                    .thread_name(format!("handshake-mpc-{:?}", tid))
                    .enable_io()
                    .enable_time()
                    .build()
                    .map_err(|err| HandshakeManagerError::SetupError(err.to_string()))?;

                // Wrap the current thread's execution in a Tokio blocking thread
                let join_handle = tokio_runtime
                    .spawn_blocking(move || Self::execute_match_mpc(party_id, local_order, net));

                block_on(join_handle)
                    .unwrap()
                    .map_err(|err| HandshakeManagerError::SetupError(err.to_string()))?;

                // Record the match in the cache
                Self::record_completed_match(
                    request_id,
                    handshake_state_index,
                    handshake_cache,
                    global_state,
                    network_channel,
                )
            }
        }
    }

    /// Respond to a handshake request from a peer
    ///
    /// Returns an optional response; none if no response is to be sent
    /// The caller should handle forwarding the response onto the network
    pub fn handle_handshake_message(
        request_id: Uuid,
        message: HandshakeMessage,
        handshake_state_index: HandshakeStateIndex,
        global_state: RelayerState,
        handshake_cache: SharedHandshakeCache<OrderIdentifier>,
        network_channel: UnboundedSender<GossipOutbound>,
    ) -> Result<Option<HandshakeMessage>, HandshakeManagerError> {
        match message {
            // ACK does not need to be handled
            HandshakeMessage::Ack => Ok(None),

            // A peer has requested a match, find an order that has not already been matched with theirs
            // and propose it back to the peer
            HandshakeMessage::InitiateMatch {
                sender_order: peer_order,
                ..
            } => {
                let mut proposed_order = None;
                {
                    let locked_handshake_cache = handshake_cache
                        .read()
                        .expect("handshake_cache lock poisoned");
                    for (order_id, order) in global_state.get_managed_order_ids().iter() {
                        if !locked_handshake_cache.contains(*order_id, peer_order) {
                            proposed_order = Some((*order_id, order.clone()));
                            break;
                        }
                    }
                } // locked_handshake_cache released

                // Update the state machine for a newly created handshake
                if let Some((order_id, order)) = proposed_order.clone() {
                    handshake_state_index
                        .new_handshake_with_peer_order(request_id, peer_order, order_id, order)
                }

                // Send the message and unwrap the result; the only error type possible
                // is that the channel is closed, so panic the thread in that case
                Ok(Some(HandshakeMessage::ProposeMatchCandidate {
                    peer_id: *global_state.read_peer_id(),
                    sender_order: proposed_order.map(|(order_id, _)| order_id),
                    peer_order,
                }))
            }

            // A peer has responded to the local node's InitiateMatch message with a proposed match pair.
            // Check that their proposal has not already been matched and then signal to begin the match
            HandshakeMessage::ProposeMatchCandidate {
                peer_id,
                peer_order: my_order,
                sender_order,
                ..
            } => {
                // If sender_order is None, the peer has no order to match with ours
                if let Some(peer_order) = sender_order {
                    // Now that the peer has negotiated an order to match, update the state machine
                    handshake_state_index.update_peer_order_id(&request_id, peer_order)?;

                    let previously_matched = {
                        let locked_handshake_cache = handshake_cache
                            .read()
                            .expect("handshake_cache lock poisoned");
                        locked_handshake_cache.contains(my_order, peer_order)
                    }; // locked_handshake_cache released

                    if previously_matched {
                        handshake_state_index.completed(&request_id);
                    }

                    // Choose a random open port to receive the connection on
                    // the peer port can be a dummy value as the local node will take the role
                    // of listener in the connection setup
                    let local_port = pick_unused_port().expect("all ports taken");
                    network_channel
                        .send(GossipOutbound::BrokerMpcNet {
                            request_id,
                            peer_id,
                            peer_port: 0,
                            local_port,
                            local_role: ConnectionRole::Listener,
                        })
                        .map_err(|err| HandshakeManagerError::SendMessage(err.to_string()))?;

                    Ok(Some(HandshakeMessage::ExecuteMatch {
                        peer_id: *global_state.read_peer_id(),
                        port: local_port,
                        previously_matched,
                        order1: my_order,
                        order2: peer_order,
                    }))
                } else {
                    Ok(None)
                }
            }

            HandshakeMessage::ExecuteMatch {
                peer_id,
                port,
                order1,
                order2,
                ..
            } => {
                // Cache the result of a handshake
                handshake_cache
                    .write()
                    .expect("handshake_cache lock poisoned")
                    .push(order1, order2);

                // Choose a local port to execute the handshake on
                let local_port = pick_unused_port().expect("all ports used");
                network_channel
                    .send(GossipOutbound::BrokerMpcNet {
                        request_id,
                        peer_id,
                        peer_port: port,
                        local_port,
                        local_role: ConnectionRole::Dialer,
                    })
                    .map_err(|err| HandshakeManagerError::SendMessage(err.to_string()))?;

                // Send back the message as an ack
                Ok(Some(HandshakeMessage::Ack))
            }
        }
    }

    /// Execute the match MPC over the provisioned QUIC stream
    fn execute_match_mpc(
        party_id: u64,
        local_order: Order,
        mut mpc_net: QuicTwoPartyNet,
    ) -> Result<(), HandshakeManagerError> {
        println!("Matching order...\n");
        // Connect the network
        block_on(mpc_net.connect())
            .map_err(|err| HandshakeManagerError::MpcNetwork(err.to_string()))?;

        // Build a fabric
        // TODO: Replace the dummy beaver source
        let beaver_source = PartyIDBeaverSource::new(party_id);
        let fabric = AuthenticatedMpcFabric::new_with_network(
            party_id,
            Rc::new(RefCell::new(mpc_net)),
            Rc::new(RefCell::new(beaver_source)),
        );
        let shared_fabric = SharedFabric::new(fabric);

        let shared_order1 = local_order
            .allocate(0 /* owning_party */, shared_fabric.clone())
            .map_err(|err| HandshakeManagerError::MpcNetwork(err.to_string()))?;
        let shared_order2 = local_order
            .allocate(1 /* owning_party */, shared_fabric.clone())
            .map_err(|err| HandshakeManagerError::MpcNetwork(err.to_string()))?;

        let match_res = compute_match(&shared_order1, &shared_order2, shared_fabric)
            .map_err(|err| HandshakeManagerError::MpcNetwork(err.to_string()))?
            .open_and_authenticate()
            .map_err(|err| HandshakeManagerError::MpcNetwork(err.to_string()))?;

        println!("Got MPC res: {:?}", match_res);
        Ok(())
    }

    /// Record a match as completed in the various state objects
    fn record_completed_match(
        request_id: Uuid,
        handshake_state_index: HandshakeStateIndex,
        handshake_cache: SharedHandshakeCache<OrderIdentifier>,
        global_state: RelayerState,
        network_channel: UnboundedSender<GossipOutbound>,
    ) -> Result<(), HandshakeManagerError> {
        // Get the order IDs from the state machine
        if let State::MatchInProgress {
            local_order_id,
            peer_order_id,
            ..
        } = handshake_state_index
            .get_state(&request_id)
            .ok_or_else(|| {
                HandshakeManagerError::InvalidRequest(format!("request_id {:?}", request_id))
            })?
            .state
        {
            // Cache the order pair as completed
            handshake_cache
                .write()
                .expect("handshake_cache lock poiseoned")
                .push(local_order_id, peer_order_id);

            // Write to global state for debugging
            global_state
                .write_matched_order_pairs()
                .push((local_order_id, peer_order_id));

            // Update the state of the handshake in the completed state
            handshake_state_index.completed(&request_id);

            // Send a message to cluster peers indicating the handshake has finished
            let locked_cluster_id = global_state.read_cluster_id();
            network_channel
                .send(GossipOutbound::Pubsub {
                    topic: locked_cluster_id.get_management_topic(),
                    message: PubsubMessage::new_cluster_management_unsigned(
                        locked_cluster_id.clone(),
                        ClusterManagementMessage::CacheSync(local_order_id, peer_order_id),
                    ),
                })
                .map_err(|err| HandshakeManagerError::SendMessage(err.to_string()))?;
        }

        Ok(())
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
        handshake_state_index: HandshakeStateIndex,
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
                    handshake_state_index,
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
        handshake_state_index: HandshakeStateIndex,
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
                let handshake_state_copy = handshake_state_index.clone();
                let state_copy = global_state.clone();
                thread_pool.install(move || {
                    HandshakeManager::perform_handshake(
                        selected_peer,
                        handshake_state_copy,
                        state_copy,
                        sender_copy,
                    );
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
        handshake_state_index: HandshakeStateIndex,
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
                    handshake_state_index,
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
        handshake_state_index: HandshakeStateIndex,
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
            let handshake_state_clone = handshake_state_index.clone();
            let state_clone = global_state.clone();
            let cache_clone = handshake_cache.clone();
            let channel_clone = network_channel.clone();

            thread_pool.install(move || {
                if let Err(err) = HandshakeManager::handle_handshake_job(
                    job,
                    handshake_state_clone,
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
