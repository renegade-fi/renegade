//! The handshake module handles the execution of handshakes from negotiating
//! a pair of orders to match, all the way through settling any resulting match

use circuits::types::{
    balance::Balance,
    fee::Fee,
    order::{Order, OrderSide},
};
use crossbeam::channel::{Receiver, Sender};
use crypto::hash::poseidon_hash_default_params;

use portpicker::pick_unused_port;
use rand::{distributions::WeightedIndex, prelude::Distribution, rngs::OsRng, thread_rng, RngCore};
use rayon::{ThreadPool, ThreadPoolBuilder};
use std::{
    sync::{Arc, RwLock},
    thread::{self, JoinHandle},
    time::Duration,
};
use tokio::sync::mpsc::UnboundedSender;
use tracing::log;
use uuid::Uuid;

use crate::{
    api::{
        cluster_management::ClusterManagementMessage,
        gossip::{
            ConnectionRole, GossipOutbound, GossipRequest, GossipResponse, ManagerControlDirective,
            PubsubMessage,
        },
        handshake::HandshakeMessage,
    },
    gossip::types::WrappedPeerId,
    state::{OrderIdentifier, RelayerState},
    system_bus::SystemBus,
    types::{SystemBusMessage, HANDSHAKE_STATUS_TOPIC},
    CancelChannel,
};

use super::{
    error::HandshakeManagerError,
    handshake_cache::{HandshakeCache, SharedHandshakeCache},
    jobs::HandshakeExecutionJob,
    state::HandshakeStateIndex,
    types::HashOutput,
    worker::HandshakeManagerConfig,
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
/// Number of nanoseconds in a millisecond, for convenience
const NANOS_PER_MILLI: u64 = 1_000_000;
/// The number of threads executing handshakes
const HANDSHAKE_EXECUTOR_N_THREADS: usize = 8;

/// Manages requests to handshake from a peer and sends outbound requests to initiate
/// a handshake
pub struct HandshakeManager {
    /// The config on the handshake manager
    pub config: HandshakeManagerConfig,
    /// The executor, ownership is taken by the controlling thread when started
    pub executor: Option<HandshakeExecutor>,
    /// The join handle for the executor thread
    pub executor_handle: Option<JoinHandle<HandshakeManagerError>>,
    /// The scheduler, ownership is taken by the controlling thread when started
    pub scheduler: Option<HandshakeScheduler>,
    /// The join handle for the scheduler thread
    pub scheduler_handle: Option<JoinHandle<HandshakeManagerError>>,
}

/// Manages the threaded execution of the handshake protocol
#[derive(Clone)]
pub struct HandshakeExecutor {
    /// The cache used to mark order pairs as already matched
    handshake_cache: SharedHandshakeCache<OrderIdentifier>,
    /// Stores the state of existing handshake executions
    handshake_state_index: HandshakeStateIndex,
    /// The thread pool backing the execution
    thread_pool: Arc<ThreadPool>,
    /// The channel on which other workers enqueue jobs for the protocol executor
    job_channel: Receiver<HandshakeExecutionJob>,
    /// The channel on which the handshake executor may forward requests to the network
    network_channel: UnboundedSender<GossipOutbound>,
    /// The global relayer state
    global_state: RelayerState,
    /// The system bus used to publish internal broadcast messages
    system_bus: SystemBus<SystemBusMessage>,
    /// The channel on which the coordinator thread may cancel handshake execution
    cancel: Option<CancelChannel>,
}

impl HandshakeExecutor {
    /// Create a new protocol executor
    pub fn new(
        job_channel: Receiver<HandshakeExecutionJob>,
        network_channel: UnboundedSender<GossipOutbound>,
        global_state: RelayerState,
        system_bus: SystemBus<SystemBusMessage>,
        cancel: CancelChannel,
    ) -> Result<Self, HandshakeManagerError> {
        // Build the thread pool, cache, and state index
        let thread_pool = ThreadPoolBuilder::new()
            .num_threads(HANDSHAKE_EXECUTOR_N_THREADS)
            .build()
            .map_err(|err| HandshakeManagerError::SetupError(err.to_string()))?;

        let handshake_cache = Arc::new(RwLock::new(HandshakeCache::new(HANDSHAKE_CACHE_SIZE)));
        let handshake_state_index = HandshakeStateIndex::new();

        Ok(Self {
            thread_pool: Arc::new(thread_pool),
            handshake_cache,
            handshake_state_index,
            job_channel,
            network_channel,
            global_state,
            system_bus,
            cancel: Some(cancel),
        })
    }

    /// The main loop: dequeues jobs and forwards them to the thread pool
    pub fn execution_loop(mut self) -> HandshakeManagerError {
        let cancel = self.cancel.take().unwrap();

        loop {
            // Check if the coordinator has cancelled the handshake manager
            if !cancel.is_empty() {
                return HandshakeManagerError::Cancelled("received cancel signal".to_string());
            }

            // Wait for the next message and forward to the thread pool
            let job = self.job_channel.recv().unwrap();

            // After blocking, check again for a cancel signal
            if !cancel.is_empty() {
                return HandshakeManagerError::Cancelled("received cancel signal".to_string());
            }

            // Otherwise, install the job into the thread pool
            let self_clone = self.clone();
            self.thread_pool.spawn(move || {
                if let Err(e) = self_clone.handle_handshake_job(job) {
                    log::info!("error executing handshake: {e}")
                }
            });
        }
    }
}

/// Main event handler implementations; each of these methods are run inside the threadpool
impl HandshakeExecutor {
    /// Handle a handshake message from the peer
    pub fn handle_handshake_job(
        &self,
        job: HandshakeExecutionJob,
    ) -> Result<(), HandshakeManagerError> {
        match job {
            // The timer thread has scheduled an outbound handshake
            HandshakeExecutionJob::PerformHandshake { peer } => self.perform_handshake(peer),

            // Indicates that a peer has sent a message during the course of a handshake
            HandshakeExecutionJob::ProcessHandshakeMessage {
                request_id,
                peer_id,
                message,
                response_channel,
            } => {
                // Get a response for the message and forward it to the network
                let resp = self.handle_handshake_message(request_id, message)?;
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

                    self.network_channel
                        .send(outbound_request)
                        .map_err(|err| HandshakeManagerError::SendMessage(err.to_string()))?;
                }

                Ok(())
            }

            // A peer has completed a match on the given order pair; cache this match pair as completed
            // and do not schedule the pair going forward
            HandshakeExecutionJob::CacheEntry { order1, order2 } => {
                self.handshake_cache
                    .write()
                    .expect("handshake_cache lock poisoned")
                    .mark_completed(order1, order2);

                Ok(())
            }

            // A peer has initiated a match on the given order pair; place this order pair in an invisibility
            // window, i.e. do not initiate matches on this pair
            HandshakeExecutionJob::PeerMatchInProgress { order1, order2 } => {
                self.handshake_cache
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
                self.handshake_state_index.in_progress(&request_id);

                // Fetch the local handshake state to get an order for the MPC
                let order_state = self
                    .handshake_state_index
                    .get_state(&request_id)
                    .ok_or_else(|| {
                        HandshakeManagerError::InvalidRequest(format!(
                            "request_id: {:?}",
                            request_id
                        ))
                    })?;

                // Publish an internal event signalling that a match is beginning
                self.system_bus.publish(
                    HANDSHAKE_STATUS_TOPIC.to_string(),
                    SystemBusMessage::HandshakeInProgress {
                        local_order_id: order_state.local_order_id,
                        peer_order_id: order_state.peer_order_id,
                    },
                );

                // Run the MPC match process
                Self::execute_match(party_id, order_state, net)?;

                // Record the match in the cache
                self.record_completed_match(request_id)
            }
        }
    }

    /// Perform a handshake with a peer
    pub fn perform_handshake(&self, peer_id: WrappedPeerId) -> Result<(), HandshakeManagerError> {
        if let Some((order_id, order, balance, fee)) =
            self.choose_order_balance_fee(None /* peer_order */)
        {
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
            self.network_channel
                .send(GossipOutbound::Request {
                    peer_id,
                    message: GossipRequest::Handshake {
                        request_id,
                        message: HandshakeMessage::InitiateMatch {
                            peer_id: self.global_state.local_peer_id(),
                            sender_order: order_id,
                            order_hash,
                            balance_hash,
                            fee_hash,
                            randomness_hash,
                        },
                    },
                })
                .map_err(|err| HandshakeManagerError::SendMessage(err.to_string()))?;

            self.handshake_state_index.new_handshake(
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

    /// Respond to a handshake request from a peer
    ///
    /// Returns an optional response; none if no response is to be sent
    /// The caller should handle forwarding the response onto the network
    pub fn handle_handshake_message(
        &self,
        request_id: Uuid,
        message: HandshakeMessage,
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
                    self.choose_order_balance_fee(Some(peer_order))
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
                    self.handshake_state_index.new_handshake_with_peer_info(
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
                    let cluster_id = { self.global_state.local_cluster_id.clone() };
                    self.network_channel
                        .send(GossipOutbound::Pubsub {
                            topic: cluster_id.get_management_topic(),
                            message: PubsubMessage::ClusterManagement {
                                cluster_id,
                                message: ClusterManagementMessage::MatchInProgress(
                                    order_id, peer_order,
                                ),
                            },
                        })
                        .map_err(|err| HandshakeManagerError::SendMessage(err.to_string()))?;

                    // Respond with the selected order pair
                    Ok(Some(HandshakeMessage::ProposeMatchCandidate {
                        peer_id: self.global_state.local_peer_id(),
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
                        peer_id: self.global_state.local_peer_id(),
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
                    self.handshake_state_index.update_peer_info(
                        &request_id,
                        peer_order,
                        peer_order_hash.unwrap(),
                        peer_balance_hash.unwrap(),
                        peer_fee_hash.unwrap(),
                        peer_randomness_hash.unwrap(),
                    )?;

                    let previously_matched = {
                        let locked_handshake_cache = self
                            .handshake_cache
                            .read()
                            .expect("handshake_cache lock poisoned");
                        locked_handshake_cache.contains(my_order, peer_order)
                    }; // locked_handshake_cache released

                    if previously_matched {
                        self.handshake_state_index.completed(&request_id);
                    }

                    // Choose a random open port to receive the connection on
                    // the peer port can be a dummy value as the local node will take the role
                    // of listener in the connection setup
                    let local_port = pick_unused_port().expect("all ports taken");
                    self.network_channel
                        .send(GossipOutbound::ManagementMessage(
                            ManagerControlDirective::BrokerMpcNet {
                                request_id,
                                peer_id,
                                peer_port: 0,
                                local_port,
                                local_role: ConnectionRole::Listener,
                            },
                        ))
                        .map_err(|err| HandshakeManagerError::SendMessage(err.to_string()))?;

                    // Send a pubsub message indicating intent to match on the given order pair
                    let cluster_id = { self.global_state.local_cluster_id.clone() };
                    self.network_channel
                        .send(GossipOutbound::Pubsub {
                            topic: cluster_id.get_management_topic(),
                            message: PubsubMessage::ClusterManagement {
                                cluster_id,
                                message: ClusterManagementMessage::MatchInProgress(
                                    my_order, peer_order,
                                ),
                            },
                        })
                        .map_err(|err| HandshakeManagerError::SendMessage(err.to_string()))?;

                    Ok(Some(HandshakeMessage::ExecuteMatch {
                        peer_id: self.global_state.local_peer_id(),
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
                self.handshake_cache
                    .write()
                    .expect("handshake_cache lock poisoned")
                    .mark_completed(order1, order2);

                // Choose a local port to execute the handshake on
                let local_port = pick_unused_port().expect("all ports used");
                self.network_channel
                    .send(GossipOutbound::ManagementMessage(
                        ManagerControlDirective::BrokerMpcNet {
                            request_id,
                            peer_id,
                            peer_port: port,
                            local_port,
                            local_role: ConnectionRole::Dialer,
                        },
                    ))
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
        &self,
        peer_order: Option<OrderIdentifier>,
    ) -> Option<(OrderIdentifier, Order, Balance, Fee)> {
        let mut rng = thread_rng();
        let mut proposed_order = None;

        let selected_wallet = {
            let locked_wallets = self.global_state.read_wallet_index();
            let locked_handshake_cache = self
                .handshake_cache
                .read()
                .expect("handshake_cache lock poisoned");

            // TODO: This choice gives single orders in a wallet a higher chance of being chosen than
            // one with many peer-orders in the wallet, fix this.
            // Choose a random wallet
            let selected_wallet = locked_wallets.get_random_wallet(&mut rng);

            // Choose an order in that wallet
            for (order_id, order) in selected_wallet.orders.iter() {
                if peer_order.is_none()
                    || !locked_handshake_cache.contains(*order_id, peer_order.unwrap())
                {
                    proposed_order = Some((*order_id, order.clone()));
                    break;
                }
            }

            selected_wallet.wallet_id
        }; // locked_wallets, locked_handshake_cache released

        // Find a balance and fee for this chosen order
        let (order_id, order) = proposed_order?;
        let (balance, fee) = self.get_balance_and_fee(&order, selected_wallet)?;

        Some((order_id, order, balance, fee))
    }

    /// Find a balance and fee for the given order
    ///
    /// TODO: Remove this in favor of the method implemented in the state primitive
    fn get_balance_and_fee(&self, order: &Order, wallet_id: Uuid) -> Option<(Balance, Fee)> {
        let locked_wallets = self.global_state.read_wallet_index();
        let selected_wallet = locked_wallets.read_wallet(&wallet_id)?;

        // The mint the local party will be spending
        let order_mint = match order.side {
            OrderSide::Buy => order.quote_mint,
            OrderSide::Sell => order.base_mint,
        };

        // The maximum quantity of the mint that the local party will be spending
        let order_amount = match order.side {
            OrderSide::Buy => {
                let res_amount = (order.amount as f64) * order.price.to_f64();
                res_amount as u64
            }
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
    fn record_completed_match(&self, request_id: Uuid) -> Result<(), HandshakeManagerError> {
        // Get the order IDs from the state machine
        let state = self
            .handshake_state_index
            .get_state(&request_id)
            .ok_or_else(|| {
                HandshakeManagerError::InvalidRequest(format!("request_id {:?}", request_id))
            })?;

        // Cache the order pair as completed
        self.handshake_cache
            .write()
            .expect("handshake_cache lock poisoned")
            .mark_completed(state.local_order_id, state.peer_order_id);

        // Write to global state for debugging
        self.global_state
            .mark_order_pair_matched(state.local_order_id, state.peer_order_id);

        // Update the state of the handshake in the completed state
        self.handshake_state_index.completed(&request_id);

        // Send a message to cluster peers indicating that the local peer has completed a match
        // Cluster peers should cache the matched order pair as completed and not initiate matches
        // on this pair going forward
        let locked_cluster_id = self.global_state.local_cluster_id.clone();
        self.network_channel
            .send(GossipOutbound::Pubsub {
                topic: locked_cluster_id.get_management_topic(),
                message: PubsubMessage::ClusterManagement {
                    cluster_id: locked_cluster_id,
                    message: ClusterManagementMessage::CacheSync(
                        state.local_order_id,
                        state.peer_order_id,
                    ),
                },
            })
            .map_err(|err| HandshakeManagerError::SendMessage(err.to_string()))?;

        // Publish an internal event indicating that the handshake has completed
        self.system_bus.publish(
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
#[derive(Clone)]
pub struct HandshakeScheduler {
    /// The sender to enqueue jobs on
    job_sender: Sender<HandshakeExecutionJob>,
    /// A copy of the relayer-global state
    global_state: RelayerState,
    /// The cancel channel to receive cancel signals on
    cancel: Receiver<()>,
}

impl HandshakeScheduler {
    /// Construct a new timer
    pub fn new(
        job_sender: Sender<HandshakeExecutionJob>,
        global_state: RelayerState,
        cancel: CancelChannel,
    ) -> Self {
        Self {
            job_sender,
            global_state,
            cancel,
        }
    }

    /// The execution loop of the timer, periodically enqueues handshake jobs
    pub fn execution_loop(self) -> HandshakeManagerError {
        let mut rng = OsRng {};
        let interval_seconds = HANDSHAKE_INTERVAL_MS / 1000;
        let interval_nanos = (HANDSHAKE_INTERVAL_MS % 1000 * NANOS_PER_MILLI) as u32;

        let refresh_interval = Duration::new(interval_seconds, interval_nanos);

        // Enqueue handshakes periodically
        loop {
            // Sample a peer to handshake with
            let random_peer = {
                let locked_priorities = self.global_state.read_handshake_priorities();
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
                if let Err(e) = self
                    .job_sender
                    .send(HandshakeExecutionJob::PerformHandshake {
                        peer: selected_peer,
                    })
                    .map_err(|err| HandshakeManagerError::SendMessage(err.to_string()))
                {
                    return e;
                }
            }

            // Check for a cancel signal before sleeping and after
            if !self.cancel.is_empty() {
                return HandshakeManagerError::Cancelled("received cancel signal".to_string());
            }

            thread::sleep(refresh_interval);
            if !self.cancel.is_empty() {
                return HandshakeManagerError::Cancelled("received cancel signal".to_string());
            }
        }
    }
}
