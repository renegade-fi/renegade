//! The handshake module handles the execution of handshakes from negotiating
//! a pair of orders to match, all the way through settling any resulting match

use circuits::types::{
    balance::Balance,
    fee::Fee,
    order::{Order, OrderSide},
};
use crossbeam::channel::{Receiver, Sender};

use libp2p::request_response::ResponseChannel;
use portpicker::pick_unused_port;
use rand::thread_rng;
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
            AuthenticatedGossipResponse, ConnectionRole, GossipOutbound, GossipRequest,
            GossipResponse, ManagerControlDirective, PubsubMessage,
        },
        handshake::{HandshakeMessage, MatchRejectionReason},
    },
    gossip::types::WrappedPeerId,
    state::{NetworkOrderState, OrderIdentifier, RelayerState},
    system_bus::SystemBus,
    types::{SystemBusMessage, HANDSHAKE_STATUS_TOPIC},
    CancelChannel,
};

use super::{
    error::HandshakeManagerError,
    handshake_cache::{HandshakeCache, SharedHandshakeCache},
    jobs::HandshakeExecutionJob,
    state::HandshakeStateIndex,
    worker::HandshakeManagerConfig,
};

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
            HandshakeExecutionJob::PerformHandshake { order } => self.perform_handshake(order),

            // Indicates that a peer has sent a message during the course of a handshake
            HandshakeExecutionJob::ProcessHandshakeMessage {
                request_id,
                message,
                response_channel,
                ..
            } => self.handle_handshake_message(request_id, message, response_channel),

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

                // Mark the handshake cache entry as invisible to avoid re-scheduling
                self.handshake_cache
                    .write()
                    .expect("handshake_cache lock poisoned")
                    .mark_invisible(
                        order_state.local_order_id,
                        order_state.peer_order_id,
                        Duration::from_millis(HANDSHAKE_INVISIBILITY_WINDOW_MS),
                    );

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
    pub fn perform_handshake(
        &self,
        peer_order_id: OrderIdentifier,
    ) -> Result<(), HandshakeManagerError> {
        if let Some((local_order_id, order, balance, fee)) =
            self.choose_order_balance_fee(peer_order_id)
        {
            // Choose a peer to match this order with
            let managing_peer = self.global_state.get_peer_managing_order(&peer_order_id);
            if managing_peer.is_none() {
                // TODO: Lower the order priority for this order
                return Ok(());
            }

            // Send a handshake message to the given peer_id
            // Panic if channel closed, no way to recover
            let request_id = Uuid::new_v4();
            self.network_channel
                .send(GossipOutbound::Request {
                    peer_id: managing_peer.unwrap(),
                    message: GossipRequest::Handshake {
                        request_id,
                        message: HandshakeMessage::ProposeMatchCandidate {
                            peer_id: self.global_state.local_peer_id(),
                            sender_order: local_order_id,
                            peer_order: peer_order_id,
                        },
                    },
                })
                .map_err(|err| HandshakeManagerError::SendMessage(err.to_string()))?;

            self.handshake_state_index.new_handshake(
                request_id,
                peer_order_id,
                local_order_id,
                order,
                balance,
                fee,
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
        response_channel: Option<ResponseChannel<AuthenticatedGossipResponse>>,
    ) -> Result<(), HandshakeManagerError> {
        match message {
            // ACK does not need to be handled
            HandshakeMessage::Ack => Ok(()),

            // A peer initiates a handshake by proposing a pair of orders to match, the local node should
            // decide whether to proceed with the match
            HandshakeMessage::ProposeMatchCandidate {
                peer_id,
                peer_order: my_order,
                sender_order,
            } => self.handle_propose_match_candidate(
                request_id,
                peer_id,
                my_order,
                sender_order,
                response_channel.unwrap(),
            ),

            // A peer has rejected a proposed match candidate, this can happen for a number of reasons, enumerated
            // by the `reason` field in the message
            HandshakeMessage::RejectMatchCandidate {
                peer_order,
                sender_order,
                reason,
                ..
            } => {
                self.handle_proposal_rejection(peer_order, sender_order, reason);
                Ok(())
            }

            // The response to ProposeMatchCandidate, indicating whether the peers should initiate an MPC; if the
            // responding peer has the proposed order pair cached it will indicate so and the two peers will abandon
            // the handshake
            HandshakeMessage::ExecuteMatch {
                peer_id,
                port,
                order1,
                order2,
                ..
            } => self.handle_execute_match(
                request_id,
                peer_id,
                port,
                order1,
                order2,
                response_channel,
            ),
        }
    }

    /// Handles a message sent from a peer in response to an InitiateMatch message from the local peer
    /// The remote peer's response should contain a proposed candidate to match against
    ///
    /// The local peer first checks that this pair has not been matched, and then proceeds to broker an
    /// MPC network for it
    #[allow(clippy::too_many_arguments)]
    fn handle_propose_match_candidate(
        &self,
        request_id: Uuid,
        peer_id: WrappedPeerId,
        my_order: OrderIdentifier,
        sender_order: OrderIdentifier,
        response_channel: ResponseChannel<AuthenticatedGossipResponse>,
    ) -> Result<(), HandshakeManagerError> {
        // Only accept the proposed order pair if the peer's order has already been verified by
        // the local node
        let peer_order_info = self
            .global_state
            .read_order_book()
            .get_order_info(&sender_order);
        if peer_order_info.is_none()
            || peer_order_info.unwrap().state != NetworkOrderState::Verified
        {
            return self.reject_match_proposal(
                request_id,
                sender_order,
                my_order,
                MatchRejectionReason::NoValidityProof,
                response_channel,
            );
        }

        // Find the order, along with a balance and fee to accompany the match
        if let Some((order, balance, fee)) = self.global_state.get_order_balance_fee(&my_order) {
            // Add an entry to the handshake state index
            self.handshake_state_index.new_handshake(
                request_id,
                sender_order,
                my_order,
                order,
                balance,
                fee,
            );

            // Check if the order pair has previously been matched, if so notify the peer and
            // terminate the handshake
            let previously_matched = {
                let locked_handshake_cache = self
                    .handshake_cache
                    .read()
                    .expect("handshake_cache lock poisoned");
                locked_handshake_cache.contains(my_order, sender_order)
            }; // locked_handshake_cache released

            if previously_matched {
                return self.reject_match_proposal(
                    request_id,
                    sender_order,
                    my_order,
                    MatchRejectionReason::Cached,
                    response_channel,
                );
            }

            // If the order pair has not been previously matched; broker an MPC connection
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
            // Cluster peers will then avoid scheduling this match until the match either completes, or
            // the cache entry's invisibility window times out
            let cluster_id = { self.global_state.local_cluster_id.clone() };
            self.network_channel
                .send(GossipOutbound::Pubsub {
                    topic: cluster_id.get_management_topic(),
                    message: PubsubMessage::ClusterManagement {
                        cluster_id,
                        message: ClusterManagementMessage::MatchInProgress(my_order, sender_order),
                    },
                })
                .map_err(|err| HandshakeManagerError::SendMessage(err.to_string()))?;

            let resp = HandshakeMessage::ExecuteMatch {
                peer_id: self.global_state.local_peer_id(),
                port: local_port,
                previously_matched,
                order1: my_order,
                order2: sender_order,
            };
            self.send_request_response(request_id, peer_id, resp, Some(response_channel))?;
        } else {
            log::debug!("match proposed on unknown order")
        }

        Ok(())
    }

    /// Reject a proposed match candidate for the specified reason
    fn reject_match_proposal(
        &self,
        request_id: Uuid,
        peer_order: OrderIdentifier,
        local_order: OrderIdentifier,
        reason: MatchRejectionReason,
        response_channel: ResponseChannel<AuthenticatedGossipResponse>,
    ) -> Result<(), HandshakeManagerError> {
        let message = HandshakeMessage::RejectMatchCandidate {
            peer_id: self.global_state.local_peer_id,
            peer_order,
            sender_order: local_order,
            reason,
        };

        self.network_channel
            .send(GossipOutbound::Response {
                channel: response_channel,
                message: GossipResponse::Handshake {
                    request_id,
                    message,
                },
            })
            .map_err(|err| HandshakeManagerError::SendMessage(err.to_string()))
    }

    /// Handles a rejected match proposal, possibly updating the cache for a missing entry
    fn handle_proposal_rejection(
        &self,
        my_order: OrderIdentifier,
        sender_order: OrderIdentifier,
        reason: MatchRejectionReason,
    ) {
        if let MatchRejectionReason::Cached = reason {
            // Update the local cache
            self.handshake_cache
                .write()
                .expect("handshake_cache lock poisoned")
                .mark_completed(my_order, sender_order)
        }
    }

    /// Handles the flow of executing a match after both parties have agreed on an order
    /// pair to attempt a match with
    fn handle_execute_match(
        &self,
        request_id: Uuid,
        peer_id: WrappedPeerId,
        port: u16,
        order1: OrderIdentifier,
        order2: OrderIdentifier,
        response_channel: Option<ResponseChannel<AuthenticatedGossipResponse>>,
    ) -> Result<(), HandshakeManagerError> {
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

        // Send back an ack
        self.send_request_response(request_id, peer_id, HandshakeMessage::Ack, response_channel)
    }

    /// Sends a request or response depending on whether the response channel is None
    ///
    /// We send messages this way to naturally fit them into the libp2p request/response messaging
    /// protocol, which mandates that requests and responses be paired, otherwise connections are liable
    /// to be assumed "dead" and dropped
    fn send_request_response(
        &self,
        request_id: Uuid,
        peer_id: WrappedPeerId,
        response: HandshakeMessage,
        response_channel: Option<ResponseChannel<AuthenticatedGossipResponse>>,
    ) -> Result<(), HandshakeManagerError> {
        let outbound_request = if let Some(channel) = response_channel {
            GossipOutbound::Response {
                channel,
                message: GossipResponse::Handshake {
                    request_id,
                    message: response,
                },
            }
        } else {
            GossipOutbound::Request {
                peer_id,
                message: GossipRequest::Handshake {
                    request_id,
                    message: response,
                },
            }
        };

        self.network_channel
            .send(outbound_request)
            .map_err(|err| HandshakeManagerError::SendMessage(err.to_string()))
    }

    /// Chooses an order, balance, and fee to match against
    ///
    /// The `peer_order` field is optional; for a peer initiating a handshake; the peer will not know
    /// the peer's proposed order, so it should just choose an order randomly
    fn choose_order_balance_fee(
        &self,
        peer_order: OrderIdentifier,
    ) -> Option<(OrderIdentifier, Order, Balance, Fee)> {
        let mut rng = thread_rng();
        let mut proposed_order = None;

        let selected_wallet = {
            let locked_wallets = self.global_state.read_wallet_index();
            if locked_wallets.is_empty() {
                return None;
            }

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
                if !locked_handshake_cache.contains(*order_id, peer_order) {
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
        let interval_seconds = HANDSHAKE_INTERVAL_MS / 1000;
        let interval_nanos = (HANDSHAKE_INTERVAL_MS % 1000 * NANOS_PER_MILLI) as u32;

        let refresh_interval = Duration::new(interval_seconds, interval_nanos);

        // Enqueue handshakes periodically
        loop {
            // Enqueue a job to handshake with the randomly selected peer
            if let Some(order) = self.global_state.choose_handshake_order() {
                if let Err(e) = self
                    .job_sender
                    .send(HandshakeExecutionJob::PerformHandshake { order })
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
