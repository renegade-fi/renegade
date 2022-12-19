//! The handshake module handles the execution of handshakes from negotiating
//! a pair of orders to match, all the way through settling any resulting match

use circuits::types::{
    balance::Balance,
    fee::Fee,
    order::{Order, OrderSide},
};
use crossbeam::channel::Receiver;
use crypto::hash::poseidon_hash_default_params;

use portpicker::pick_unused_port;
use rand::{
    distributions::WeightedIndex, prelude::Distribution, rngs::OsRng, seq::IteratorRandom,
    thread_rng, RngCore,
};
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
        gossip::{ConnectionRole, GossipOutbound, GossipRequest, GossipResponse, PubsubMessage},
        handshake::HandshakeMessage,
    },
    gossip::types::WrappedPeerId,
    state::RelayerState,
    system_bus::SystemBus,
    types::{SystemBusMessage, HANDSHAKE_STATUS_TOPIC},
    CancelChannel,
};

use super::{
    error::HandshakeManagerError,
    handshake_cache::SharedHandshakeCache,
    jobs::HandshakeExecutionJob,
    state::HandshakeStateIndex,
    types::{HashOutput, OrderIdentifier},
};

/// The default priority of a newly added node in the handshake priority list
pub const DEFAULT_HANDSHAKE_PRIORITY: u32 = 10;
/// The amount of time to mark an order pair as invisible for; giving the peer
/// time to complete a match on this pair
pub(super) const HANDSHAKE_INVISIBILITY_WINDOW_MS: u64 = 120_000; // 2 minutes
/// The size of the LRU handshake cache
pub(super) const HANDSHAKE_CACHE_SIZE: usize = 500;
/// How frequently a new handshake is initiated from the local peer
pub(super) const HANDSHAKE_INTERVAL_MS: u64 = 2_000; // 2 seconds
/// Number of nanoseconds in a millisecond, for convenienc
const NANOS_PER_MILLI: u64 = 1_000_000;

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
        handshake_cache: SharedHandshakeCache<OrderIdentifier>,
        global_state: RelayerState,
        network_channel: UnboundedSender<GossipOutbound>,
    ) -> Result<(), HandshakeManagerError> {
        if let Some((order_id, order, balance, fee)) = Self::choose_order_balance_fee(
            None, /* peer_order */
            handshake_cache,
            &global_state,
        ) {
            // Hash the balance, order, fee, and wallet randomness
            // TODO: Replace the randomness here with true wallet-specific randomness
            let mut rng = thread_rng();
            let randomness = rng.next_u64();

            let order_hash = HashOutput(poseidon_hash_default_params(&order));
            let balance_hash = HashOutput(poseidon_hash_default_params(&balance));
            let fee_hash = HashOutput(poseidon_hash_default_params(&fee));
            let randomness_hash = HashOutput(poseidon_hash_default_params(vec![randomness]));

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
                            sender_order: order_id,
                            order_hash,
                            balance_hash,
                            fee_hash,
                            randomness_hash,
                        },
                    },
                })
                .map_err(|err| HandshakeManagerError::SendMessage(err.to_string()))?;

            handshake_state_index.new_handshake(
                request_id,
                order_id,
                order,
                balance,
                fee,
                order_hash,
                balance_hash,
                fee_hash,
                randomness_hash,
            );
        }

        Ok(())
    }

    /// Handle a handshake message from the peer
    pub fn handle_handshake_job(
        job: HandshakeExecutionJob,
        handshake_state_index: HandshakeStateIndex,
        global_state: RelayerState,
        handshake_cache: SharedHandshakeCache<OrderIdentifier>,
        network_channel: UnboundedSender<GossipOutbound>,
        system_bus: SystemBus<SystemBusMessage>,
    ) -> Result<(), HandshakeManagerError> {
        match job {
            // Indicates that a peer has sent a message during the course of a handshake
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

            // A peer has completed a match on the given order pair; cache this match pair as completed
            // and do not schedule the pair going forward
            HandshakeExecutionJob::CacheEntry { order1, order2 } => {
                handshake_cache
                    .write()
                    .expect("handshake_cache lock poisoned")
                    .mark_completed(order1, order2);

                Ok(())
            }

            // A peer has initiated a match on the given order pair; place this order pair in an invisibility
            // window, i.e. do not initiate matches on this pair
            HandshakeExecutionJob::PeerMatchInProgress { order1, order2 } => {
                handshake_cache
                    .write()
                    .expect("handshake_cache lock poisoned")
                    .mark_invisible(
                        order1,
                        order2,
                        Duration::from_millis(HANDSHAKE_INVISIBILITY_WINDOW_MS),
                    );

                Ok(())
            }

            // Indicates that the network manager has setup a network connection for a handshake to execute over
            // the local peer should connect and go forward with the MPC
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

                // Publish an internal event signalling that a match is beginning
                system_bus.publish(
                    HANDSHAKE_STATUS_TOPIC.to_string(),
                    SystemBusMessage::HandshakeInProgress {
                        local_order_id: order_state.local_order_id,
                        peer_order_id: order_state.peer_order_id,
                    },
                );

                // Run the MPC match process
                Self::execute_match(party_id, order_state, net)?;

                // Record the match in the cache
                Self::record_completed_match(
                    request_id,
                    handshake_state_index,
                    handshake_cache,
                    global_state,
                    network_channel,
                    system_bus,
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
                order_hash: peer_order_hash,
                balance_hash: peer_balance_hash,
                fee_hash: peer_fee_hash,
                randomness_hash: peer_randomness_hash,
                ..
            } => {
                if let Some((order_id, order, balance, fee)) =
                    Self::choose_order_balance_fee(Some(peer_order), handshake_cache, &global_state)
                {
                    // Hash the balance, order, fee, and wallet randomness
                    // TODO: Replace the randomness here with true wallet-specific randomness
                    let mut rng = thread_rng();
                    let randomness = rng.next_u64();

                    let order_hash = HashOutput(poseidon_hash_default_params(&order));
                    let balance_hash = HashOutput(poseidon_hash_default_params(&balance));
                    let fee_hash = HashOutput(poseidon_hash_default_params(&fee));
                    let randomness_hash =
                        HashOutput(poseidon_hash_default_params(vec![randomness]));

                    // Add the new handshake to the state machine index
                    handshake_state_index.new_handshake_with_peer_info(
                        request_id,
                        peer_order,
                        order_id,
                        order,
                        balance,
                        fee,
                        order_hash,
                        balance_hash,
                        fee_hash,
                        randomness_hash,
                        peer_order_hash,
                        peer_balance_hash,
                        peer_fee_hash,
                        peer_randomness_hash,
                    );

                    // Send a pubsub message indicating intent to match on the given order pair
                    let cluster_id = { global_state.read_cluster_id().clone() };
                    network_channel
                        .send(GossipOutbound::Pubsub {
                            topic: cluster_id.get_management_topic(),
                            message: PubsubMessage::new_cluster_management_unsigned(
                                cluster_id,
                                ClusterManagementMessage::MatchInProgress(order_id, peer_order),
                            ),
                        })
                        .map_err(|err| HandshakeManagerError::SendMessage(err.to_string()))?;

                    // Respond with the selected order pair
                    Ok(Some(HandshakeMessage::ProposeMatchCandidate {
                        peer_id: *global_state.read_peer_id(),
                        peer_order,
                        sender_order: Some(order_id),
                        order_hash: Some(order_hash),
                        balance_hash: Some(balance_hash),
                        fee_hash: Some(fee_hash),
                        randomness_hash: Some(randomness_hash),
                    }))
                } else {
                    // Send an explicit empty message back so that the remote peer may cache their order as being
                    // already cached with all of the local peer's orders
                    Ok(Some(HandshakeMessage::ProposeMatchCandidate {
                        peer_id: *global_state.read_peer_id(),
                        peer_order,
                        sender_order: None,
                        order_hash: None,
                        balance_hash: None,
                        fee_hash: None,
                        randomness_hash: None,
                    }))
                }
            }

            // A peer has responded to the local node's InitiateMatch message with a proposed match pair.
            // Check that their proposal has not already been matched and then signal to begin the match
            HandshakeMessage::ProposeMatchCandidate {
                peer_id,
                peer_order: my_order,
                sender_order,
                order_hash: peer_order_hash,
                balance_hash: peer_balance_hash,
                fee_hash: peer_fee_hash,
                randomness_hash: peer_randomness_hash,
            } => {
                // If sender_order is None, the peer has no order to match with ours
                if let Some(peer_order) = sender_order {
                    // Now that the peer has negotiated an order to match, update the state machine
                    handshake_state_index.update_peer_info(
                        &request_id,
                        peer_order,
                        peer_order_hash.unwrap(),
                        peer_balance_hash.unwrap(),
                        peer_fee_hash.unwrap(),
                        peer_randomness_hash.unwrap(),
                    )?;

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

                    // Send a pubsub message indicating intent to match on the given order pair
                    let cluster_id = { global_state.read_cluster_id().clone() };
                    network_channel
                        .send(GossipOutbound::Pubsub {
                            topic: cluster_id.get_management_topic(),
                            message: PubsubMessage::new_cluster_management_unsigned(
                                cluster_id,
                                ClusterManagementMessage::MatchInProgress(my_order, peer_order),
                            ),
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
                    .mark_completed(order1, order2);

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

    /// Chooses an order, balance, and fee to match against
    ///
    /// The `peer_order` field is optional; for a peer initiating a handshake; the peer will not know
    /// the peer's proposed order, so it should just choose an order randomly
    fn choose_order_balance_fee(
        peer_order: Option<OrderIdentifier>,
        handshake_cache: SharedHandshakeCache<OrderIdentifier>,
        global_state: &RelayerState,
    ) -> Option<(OrderIdentifier, Order, Balance, Fee)> {
        let mut rng = thread_rng();
        let mut proposed_order = None;

        let selected_wallet = {
            let locked_wallets = global_state.read_managed_wallets();
            let locked_handshake_cache = handshake_cache
                .read()
                .expect("handshake_cache lock poisoned");

            // TODO: This choice gives single orders in a wallet a higher chance of being chosen than
            // one with many peer-orders in the wallet, fix this.
            // Choose a random wallet
            let random_wallet_id = *locked_wallets.keys().choose(&mut rng)?;

            // Choose an order in that wallet
            for (order_id, order) in locked_wallets.get(&random_wallet_id).unwrap().orders.iter() {
                if peer_order.is_none()
                    || !locked_handshake_cache.contains(*order_id, peer_order.unwrap())
                {
                    proposed_order = Some((*order_id, order.clone()));
                    break;
                }
            }

            random_wallet_id
        }; // locked_wallets, locked_handshake_cache released

        // Find a balance and fee for this chosen order
        let (order_id, order) = proposed_order?;
        let (balance, fee) = Self::get_balance_and_fee(&order, selected_wallet, global_state)?;

        Some((order_id, order, balance, fee))
    }

    /// Find a balance and fee for the given order
    fn get_balance_and_fee(
        order: &Order,
        wallet_id: Uuid,
        global_state: &RelayerState,
    ) -> Option<(Balance, Fee)> {
        let locked_wallets = global_state.read_managed_wallets();
        let selected_wallet = locked_wallets.get(&wallet_id)?;

        // The mint the local party will be spending
        let order_mint = match order.side {
            OrderSide::Buy => order.quote_mint,
            OrderSide::Sell => order.base_mint,
        };

        // The maximum quantity of the mint that the local party will be spending
        let order_amount = match order.side {
            OrderSide::Buy => order.amount * order.price,
            OrderSide::Sell => order.amount,
        };

        let balance = selected_wallet.balances.get(&order_mint)?;
        if balance.amount < order_amount {
            return None;
        }

        // Choose the first fee for simplicity
        let fee = selected_wallet.fees.get(0 /* index */)?;

        Some((balance.clone(), fee.clone()))
    }

    /// Record a match as completed in the various state objects
    fn record_completed_match(
        request_id: Uuid,
        handshake_state_index: HandshakeStateIndex,
        handshake_cache: SharedHandshakeCache<OrderIdentifier>,
        global_state: RelayerState,
        network_channel: UnboundedSender<GossipOutbound>,
        system_bus: SystemBus<SystemBusMessage>,
    ) -> Result<(), HandshakeManagerError> {
        // Get the order IDs from the state machine
        let state = handshake_state_index
            .get_state(&request_id)
            .ok_or_else(|| {
                HandshakeManagerError::InvalidRequest(format!("request_id {:?}", request_id))
            })?;

        // Cache the order pair as completed
        handshake_cache
            .write()
            .expect("handshake_cache lock poiseoned")
            .mark_completed(state.local_order_id, state.peer_order_id);

        // Write to global state for debugging
        global_state
            .write_matched_order_pairs()
            .push((state.local_order_id, state.peer_order_id));

        // Update the state of the handshake in the completed state
        handshake_state_index.completed(&request_id);

        // Send a message to cluster peers indicating that the local peer has completed a match
        // Cluster peers should cache the matched order pair as completed and not initiate matches
        // on this pair going forward
        let locked_cluster_id = global_state.read_cluster_id();
        network_channel
            .send(GossipOutbound::Pubsub {
                topic: locked_cluster_id.get_management_topic(),
                message: PubsubMessage::new_cluster_management_unsigned(
                    locked_cluster_id.clone(),
                    ClusterManagementMessage::CacheSync(state.local_order_id, state.peer_order_id),
                ),
            })
            .map_err(|err| HandshakeManagerError::SendMessage(err.to_string()))?;

        // Publish an internal event indicating that the handshake has completed
        system_bus.publish(
            HANDSHAKE_STATUS_TOPIC.to_string(),
            SystemBusMessage::HandshakeCompleted {
                local_order_id: state.local_order_id,
                peer_order_id: state.peer_order_id,
            },
        );

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
        handshake_cache: SharedHandshakeCache<OrderIdentifier>,
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
                    handshake_cache,
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
        handshake_cache: SharedHandshakeCache<OrderIdentifier>,
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
                let handshake_cache_copy = handshake_cache.clone();
                let handshake_state_copy = handshake_state_index.clone();
                let state_copy = global_state.clone();
                thread_pool.install(move || {
                    if let Err(err) = HandshakeManager::perform_handshake(
                        selected_peer,
                        handshake_state_copy,
                        handshake_cache_copy,
                        state_copy,
                        sender_copy,
                    ) {
                        println!("Error in handshake thread pool: {:?}", err.to_string());
                    }
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
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        thread_pool: Arc<ThreadPool>,
        handshake_cache: SharedHandshakeCache<OrderIdentifier>,
        handshake_state_index: HandshakeStateIndex,
        job_channel: Receiver<HandshakeExecutionJob>,
        network_channel: UnboundedSender<GossipOutbound>,
        global_state: RelayerState,
        system_bus: SystemBus<SystemBusMessage>,
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
                    system_bus,
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
    #[allow(clippy::too_many_arguments)]
    fn execution_loop(
        thread_pool: Arc<ThreadPool>,
        handshake_cache: SharedHandshakeCache<OrderIdentifier>,
        handshake_state_index: HandshakeStateIndex,
        job_channel: Receiver<HandshakeExecutionJob>,
        network_channel: UnboundedSender<GossipOutbound>,
        global_state: RelayerState,
        system_bus: SystemBus<SystemBusMessage>,
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
            let bus_clone = system_bus.clone();

            thread_pool.install(move || {
                if let Err(err) = HandshakeManager::handle_handshake_job(
                    job,
                    handshake_state_clone,
                    state_clone,
                    cache_clone,
                    channel_clone,
                    bus_clone,
                ) {
                    println!("Error handling handshake job: {}", err);
                }
            })
        }
    }
}
