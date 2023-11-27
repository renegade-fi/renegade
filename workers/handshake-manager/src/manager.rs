//! The handshake module handles the execution of handshakes from negotiating
//! a pair of orders to match, all the way through settling any resulting match
mod internal_engine;
pub mod r#match;
mod price_agreement;

use circuit_types::{fixed_point::FixedPoint, order::Order};
use common::{
    default_wrapper::{DefaultOption, DefaultWrapper},
    new_async_shared,
    types::{
        chain_id::ChainId,
        gossip::WrappedPeerId,
        handshake::{ConnectionRole, HandshakeResult, HandshakeState},
        network_order::NetworkOrderState,
        proof_bundles::OrderValidityProofBundle,
        tasks::TaskIdentifier,
        token::Token,
        wallet::OrderIdentifier,
        CancelChannel,
    },
};
use constants::HANDSHAKE_STATUS_TOPIC;
use crossbeam::channel::Sender as CrossbeamSender;
use external_api::bus_message::SystemBusMessage;
use futures::executor::block_on;
use gossip_api::{
    cluster_management::ClusterManagementMessage,
    gossip::{
        AuthenticatedGossipResponse, GossipOutbound, GossipRequest, GossipResponse,
        ManagerControlDirective, PubsubMessage,
    },
    handshake::{HandshakeMessage, MatchRejectionReason, PriceVector},
};
use job_types::{
    handshake_manager::HandshakeExecutionJob, price_reporter::PriceReporterManagerJob,
    proof_manager::ProofManagerJob,
};
use libp2p::request_response::ResponseChannel;
use portpicker::pick_unused_port;
use starknet_client::client::StarknetClient;
use state::RelayerState;
use std::{
    convert::TryInto,
    thread::JoinHandle,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use system_bus::SystemBus;
use task_driver::{driver::TaskDriver, settle_match::SettleMatchTask};
use tokio::sync::mpsc::{UnboundedReceiver as TokioReceiver, UnboundedSender as TokioSender};
use tracing::log;
use uuid::Uuid;

pub(super) use price_agreement::init_price_streams;

use super::{
    error::HandshakeManagerError,
    handshake_cache::{HandshakeCache, SharedHandshakeCache},
    state::HandshakeStateIndex,
    worker::HandshakeManagerConfig,
};

// -------------
// | Constants |
// -------------

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
pub(super) const HANDSHAKE_EXECUTOR_N_THREADS: usize = 8;

/// Error message emitted when a wallet cannot be looked up in the global state
pub(super) const ERR_NO_WALLET: &str = "wallet not found in state";
/// Error message emitted when an order cannot be found in the global state
pub(super) const ERR_NO_ORDER: &str = "order not found in state";
/// Error message emitted when price data cannot be found for a token pair
const ERR_NO_PRICE_DATA: &str = "no price data found for token pair";

// -----------
// | Helpers |
// -----------

/// Get the current unix timestamp in milliseconds since the epoch
fn get_timestamp_millis() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis().try_into().unwrap()
}

// ------------------------
// | Manager and Executor |
// ------------------------

/// Manages requests to handshake from a peer and sends outbound requests to
/// initiate a handshake
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
    /// The chain that the local node targets
    chain_id: ChainId,
    /// The cache used to mark order pairs as already matched
    pub(super) handshake_cache: SharedHandshakeCache<OrderIdentifier>,
    /// Stores the state of existing handshake executions
    pub(super) handshake_state_index: HandshakeStateIndex,
    /// The channel on which other workers enqueue jobs for the protocol
    /// executor
    pub(super) job_channel: DefaultOption<TokioReceiver<HandshakeExecutionJob>>,
    /// The channel on which the handshake executor may forward requests to the
    /// network
    pub(super) network_channel: TokioSender<GossipOutbound>,
    /// The pricer reporter's work queue, used for fetching price reports
    pub(super) price_reporter_job_queue: TokioSender<PriceReporterManagerJob>,
    /// A Starknet client used for interacting with the contract
    pub(super) starknet_client: StarknetClient,
    /// The channel on which to send proof manager jobs
    pub(super) proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    /// The global relayer state
    pub(super) global_state: RelayerState,
    /// The task driver, used to manage long-running async tasks
    pub(super) task_driver: TaskDriver,
    /// The system bus used to publish internal broadcast messages
    pub(super) system_bus: SystemBus<SystemBusMessage>,
    /// The channel on which the coordinator thread may cancel handshake
    /// execution
    pub(super) cancel: CancelChannel,
}

impl HandshakeExecutor {
    /// Create a new protocol executor
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        job_channel: TokioReceiver<HandshakeExecutionJob>,
        network_channel: TokioSender<GossipOutbound>,
        price_reporter_job_queue: TokioSender<PriceReporterManagerJob>,
        starknet_client: StarknetClient,
        proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
        global_state: RelayerState,
        task_driver: TaskDriver,
        system_bus: SystemBus<SystemBusMessage>,
        cancel: CancelChannel,
    ) -> Result<Self, HandshakeManagerError> {
        // Build the handshake cache and state machine structures
        let handshake_cache = new_async_shared(HandshakeCache::new(HANDSHAKE_CACHE_SIZE));
        let handshake_state_index = HandshakeStateIndex::new(global_state.clone());

        Ok(Self {
            chain_id,
            handshake_cache,
            handshake_state_index,
            job_channel: DefaultWrapper::new(Some(job_channel)),
            network_channel,
            price_reporter_job_queue,
            starknet_client,
            proof_manager_work_queue,
            global_state,
            task_driver,
            system_bus,
            cancel,
        })
    }

    /// The main loop: dequeues jobs and forwards them to the thread pool
    pub async fn execution_loop(mut self) -> HandshakeManagerError {
        let mut job_channel = self.job_channel.take().unwrap();

        loop {
            // Await the next job from the scheduler or elsewhere
            tokio::select! {
                Some(job) = job_channel.recv() => {
                    let self_clone = self.clone();
                    tokio::task::spawn(async move {
                        if let Err(e) = self_clone.handle_handshake_job(job).await {
                            log::info!("error executing handshake: {e}")
                        }
                    });
                },

                // Await cancellation by the coordinator
                _ = self.cancel.changed() => {
                    log::info!("Handshake manager received cancel signal, shutting down...");
                    return HandshakeManagerError::Cancelled("received cancel signal".to_string());
                }
            }
        }
    }
}

/// Main event handler implementations; each of these methods are run inside the
/// threadpool
impl HandshakeExecutor {
    /// Handle a handshake message from the peer
    pub async fn handle_handshake_job(
        &self,
        job: HandshakeExecutionJob,
    ) -> Result<(), HandshakeManagerError> {
        match job {
            // The timer thread has scheduled an outbound handshake
            HandshakeExecutionJob::PerformHandshake { order } => {
                self.perform_handshake(order).await
            },

            // An order has been updated, the executor should run the internal engine on the
            // new order to check for matches
            HandshakeExecutionJob::InternalMatchingEngine { order } => {
                // Spawn a blocking thread to handle matches
                let self_clone = self.clone();
                tokio::task::spawn_blocking(move || {
                    block_on(self_clone.run_internal_matching_engine(order))
                })
                .await
                .unwrap() // JoinError
            },

            // Indicates that a peer has sent a message during the course of a handshake
            HandshakeExecutionJob::ProcessHandshakeMessage {
                request_id,
                message,
                response_channel,
                ..
            } => self.handle_handshake_message(request_id, message, response_channel).await,

            // A peer has completed a match on the given order pair; cache this match pair as
            // completed and do not schedule the pair going forward
            HandshakeExecutionJob::CacheEntry { order1, order2 } => {
                self.handshake_cache.write().await.mark_completed(order1, order2);

                Ok(())
            },

            // A peer has initiated a match on the given order pair; place this order pair in an
            // invisibility window, i.e. do not initiate matches on this pair
            HandshakeExecutionJob::PeerMatchInProgress { order1, order2 } => {
                self.handshake_cache.write().await.mark_invisible(
                    order1,
                    order2,
                    Duration::from_millis(HANDSHAKE_INVISIBILITY_WINDOW_MS),
                );

                Ok(())
            },

            // Indicates that the network manager has setup a network connection for a handshake to
            // execute over the local peer should connect and go forward with the MPC
            HandshakeExecutionJob::MpcNetSetup { request_id, party_id, net } => {
                // Fetch the local handshake state to get an order for the MPC
                let order_state =
                    self.handshake_state_index.get_state(&request_id).await.ok_or_else(|| {
                        HandshakeManagerError::InvalidRequest(format!(
                            "request_id: {:?}",
                            request_id
                        ))
                    })?;

                // Mark the handshake cache entry as invisible to avoid re-scheduling
                self.handshake_cache.write().await.mark_invisible(
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
                        timestamp: get_timestamp_millis(),
                    },
                );

                // Fetch the validity proofs of the party
                let (party0_proof, party1_proof) = {
                    let locked_order_book = self.global_state.read_order_book().await;
                    let local_validity_proof = locked_order_book
                        .get_validity_proofs(&order_state.local_order_id)
                        .await
                        .unwrap();
                    let remote_validity_proof = locked_order_book
                        .get_validity_proofs(&order_state.peer_order_id)
                        .await
                        .unwrap();

                    match order_state.role {
                        ConnectionRole::Dialer => (local_validity_proof, remote_validity_proof),
                        ConnectionRole::Listener => (remote_validity_proof, local_validity_proof),
                    }
                }; // locked_order_book released

                // Run the MPC match process
                let self_clone = self.clone();
                let proof0_clone = party0_proof.clone();
                let proof1_clone = party1_proof.clone();
                let res = tokio::task::spawn_blocking(move || {
                    block_on(self_clone.execute_match(
                        request_id,
                        party_id,
                        proof0_clone,
                        proof1_clone,
                        net,
                    ))
                })
                .await
                .unwrap()?;

                // Record the match in the cache
                self.record_completed_match(request_id).await?;

                if res.is_nontrivial() {
                    self.submit_match(party0_proof, party1_proof, order_state, res).await;
                }
                Ok(())
            },

            // Indicates that in-flight MPCs on the given nullifier should be terminated
            HandshakeExecutionJob::MpcShootdown { nullifier } => {
                self.handshake_state_index.shootdown_nullifier(nullifier).await
            },
        }
    }

    // ----------------
    // | Job Handlers |
    // ----------------

    /// Perform a handshake with a peer
    pub async fn perform_handshake(
        &self,
        peer_order_id: OrderIdentifier,
    ) -> Result<(), HandshakeManagerError> {
        if let Some(local_order_id) = self.choose_match_proposal(peer_order_id).await {
            // Choose a peer to match this order with
            let managing_peer = self.global_state.get_peer_managing_order(&peer_order_id).await;
            if managing_peer.is_none() {
                // TODO: Lower the order priority for this order
                return Ok(());
            }

            // Send a handshake message to the given peer_id
            // Panic if channel closed, no way to recover
            let request_id = Uuid::new_v4();
            let price_vector = self.fetch_price_vector().await?;
            self.network_channel
                .send(GossipOutbound::Request {
                    peer_id: managing_peer.unwrap(),
                    message: GossipRequest::Handshake {
                        request_id,
                        message: HandshakeMessage::ProposeMatchCandidate {
                            peer_id: self.global_state.local_peer_id(),
                            sender_order: local_order_id,
                            peer_order: peer_order_id,
                            price_vector: price_vector.clone(),
                        },
                    },
                })
                .map_err(|err| HandshakeManagerError::SendMessage(err.to_string()))?;

            // Determine the execution price for the new order
            let order =
                self.global_state.get_order(&local_order_id).await.ok_or_else(|| {
                    HandshakeManagerError::StateNotFound(ERR_NO_WALLET.to_string())
                })?;
            let (base, quote) = self.token_pair_for_order(&order);

            let execution_price = price_vector
                    .find_pair(&base, &quote)
                    .ok_or_else(|| {
                        HandshakeManagerError::NoPriceData(ERR_NO_PRICE_DATA.to_string())
                    })? /* (base, quote, price) */
                    .2;

            self.handshake_state_index
                .new_handshake(
                    request_id,
                    ConnectionRole::Dialer,
                    peer_order_id,
                    local_order_id,
                    FixedPoint::from_f64_round_down(execution_price),
                )
                .await?;
        }

        Ok(())
    }

    /// Respond to a handshake request from a peer
    pub async fn handle_handshake_message(
        &self,
        request_id: Uuid,
        message: HandshakeMessage,
        response_channel: Option<ResponseChannel<AuthenticatedGossipResponse>>,
    ) -> Result<(), HandshakeManagerError> {
        match message {
            // ACK does not need to be handled
            HandshakeMessage::Ack => Ok(()),

            // A peer initiates a handshake by proposing a pair of orders to match, the local node
            // should decide whether to proceed with the match
            HandshakeMessage::ProposeMatchCandidate {
                peer_id,
                peer_order: my_order,
                sender_order,
                price_vector,
            } => {
                self.handle_propose_match_candidate(
                    request_id,
                    peer_id,
                    my_order,
                    sender_order,
                    price_vector,
                    response_channel.unwrap(),
                )
                .await
            },

            // A peer has rejected a proposed match candidate, this can happen for a number of
            // reasons, enumerated by the `reason` field in the message
            HandshakeMessage::RejectMatchCandidate { peer_order, sender_order, reason, .. } => {
                self.handle_proposal_rejection(peer_order, sender_order, reason).await;
                Ok(())
            },

            // The response to ProposeMatchCandidate, indicating whether the peers should initiate
            // an MPC; if the responding peer has the proposed order pair cached it will
            // indicate so and the two peers will abandon the handshake
            HandshakeMessage::AcceptMatchCandidate { peer_id, port, order1, order2, .. } => {
                self.handle_execute_match(
                    request_id,
                    peer_id,
                    port,
                    order1,
                    order2,
                    response_channel,
                )
                .await
            },
        }
    }

    /// Handles a message sent from a peer in response to an InitiateMatch
    /// message from the local peer The remote peer's response should
    /// contain a proposed candidate to match against
    ///
    /// The local peer first checks that this pair has not been matched, and
    /// then proceeds to broker an MPC network for it
    #[allow(clippy::too_many_arguments)]
    async fn handle_propose_match_candidate(
        &self,
        request_id: Uuid,
        peer_id: WrappedPeerId,
        my_order: OrderIdentifier,
        sender_order: OrderIdentifier,
        price_vector: PriceVector,
        response_channel: ResponseChannel<AuthenticatedGossipResponse>,
    ) -> Result<(), HandshakeManagerError> {
        // Only accept the proposed order pair if the peer's order has already been
        // verified by the local node
        let peer_order_info =
            self.global_state.read_order_book().await.get_order_info(&sender_order).await;
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

        // Do not accept handshakes on local orders that we don't have
        // validity proof or witness for
        if !self.global_state.read_order_book().await.order_ready_for_handshake(&my_order).await {
            return self.reject_match_proposal(
                request_id,
                sender_order,
                my_order,
                MatchRejectionReason::LocalOrderNotReady,
                response_channel,
            );
        }

        // Verify that the proposed prices are valid by the price agreement logic
        let execution_price = self.validate_price_vector(&price_vector, &my_order).await?;
        if execution_price.is_none() {
            return self.reject_match_proposal(
                request_id,
                sender_order,
                my_order,
                MatchRejectionReason::NoPriceAgreement,
                response_channel,
            );
        }
        let execution_price = execution_price
            .unwrap() /* (base, quote, price) */
            .2;

        // Add an entry to the handshake state index
        self.handshake_state_index
            .new_handshake(
                request_id,
                ConnectionRole::Listener,
                sender_order,
                my_order,
                FixedPoint::from_f64_round_down(execution_price),
            )
            .await?;

        // Check if the order pair has previously been matched, if so notify the peer
        // and terminate the handshake
        let previously_matched = {
            let locked_handshake_cache = self.handshake_cache.read().await;
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
            .send(GossipOutbound::ManagementMessage(ManagerControlDirective::BrokerMpcNet {
                request_id,
                peer_id,
                peer_port: 0,
                local_port,
                local_role: ConnectionRole::Listener,
            }))
            .map_err(|err| HandshakeManagerError::SendMessage(err.to_string()))?;

        // Send a pubsub message indicating intent to match on the given order pair
        // Cluster peers will then avoid scheduling this match until the match either
        // completes, or the cache entry's invisibility window times out
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

        let resp = HandshakeMessage::AcceptMatchCandidate {
            peer_id: self.global_state.local_peer_id(),
            port: local_port,
            previously_matched,
            order1: my_order,
            order2: sender_order,
        };
        self.send_request_response(request_id, peer_id, resp, Some(response_channel))?;

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
                message: GossipResponse::Handshake { request_id, message },
            })
            .map_err(|err| HandshakeManagerError::SendMessage(err.to_string()))
    }

    /// Handles a rejected match proposal, possibly updating the cache for a
    /// missing entry
    async fn handle_proposal_rejection(
        &self,
        my_order: OrderIdentifier,
        sender_order: OrderIdentifier,
        reason: MatchRejectionReason,
    ) {
        if let MatchRejectionReason::Cached = reason {
            // Update the local cache
            self.handshake_cache.write().await.mark_completed(my_order, sender_order)
        }
    }

    /// Handles the flow of executing a match after both parties have agreed on
    /// an order pair to attempt a match with
    async fn handle_execute_match(
        &self,
        request_id: Uuid,
        peer_id: WrappedPeerId,
        port: u16,
        order1: OrderIdentifier,
        order2: OrderIdentifier,
        response_channel: Option<ResponseChannel<AuthenticatedGossipResponse>>,
    ) -> Result<(), HandshakeManagerError> {
        // Cache the result of a handshake
        self.handshake_cache.write().await.mark_completed(order1, order2);

        // Choose a local port to execute the handshake on
        let local_port = pick_unused_port().expect("all ports used");
        self.network_channel
            .send(GossipOutbound::ManagementMessage(ManagerControlDirective::BrokerMpcNet {
                request_id,
                peer_id,
                peer_port: port,
                local_port,
                local_role: ConnectionRole::Dialer,
            }))
            .map_err(|err| HandshakeManagerError::SendMessage(err.to_string()))?;

        // Send back an ack
        self.send_request_response(request_id, peer_id, HandshakeMessage::Ack, response_channel)
    }

    // -----------
    // | Helpers |
    // -----------

    /// Converts the token pair of the given order to one that price
    /// data can be found for
    ///
    /// This involves both converting the address into an Eth mainnet analog
    /// and casting this to a `Token`
    fn token_pair_for_order(&self, order: &Order) -> (Token, Token) {
        match self.chain_id {
            ChainId::AlphaGoerli | ChainId::Devnet => (
                Token::from_addr_biguint(&order.base_mint),
                Token::from_addr_biguint(&order.quote_mint),
            ),
            ChainId::Katana => (
                Token::from_katana_addr_biguint(&order.base_mint),
                Token::from_katana_addr_biguint(&order.quote_mint),
            ),
            _ => todo!("Implement price remapping for {:?}", self.chain_id),
        }
    }

    /// Sends a request or response depending on whether the response channel is
    /// None
    ///
    /// We send messages this way to naturally fit them into the libp2p
    /// request/response messaging protocol, which mandates that requests
    /// and responses be paired, otherwise connections are liable
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
                message: GossipResponse::Handshake { request_id, message: response },
            }
        } else {
            GossipOutbound::Request {
                peer_id,
                message: GossipRequest::Handshake { request_id, message: response },
            }
        };

        self.network_channel
            .send(outbound_request)
            .map_err(|err| HandshakeManagerError::SendMessage(err.to_string()))
    }

    /// Chooses an order to match against a remote order
    async fn choose_match_proposal(&self, peer_order: OrderIdentifier) -> Option<OrderIdentifier> {
        let locked_handshake_cache = self.handshake_cache.read().await;
        let local_verified_orders =
            self.global_state.read_order_book().await.get_local_scheduleable_orders().await;

        // Choose an order that isn't cached
        for order_id in local_verified_orders.iter() {
            if !locked_handshake_cache.contains(*order_id, peer_order) {
                return Some(*order_id);
            }
        }

        None
    }

    /// Record a match as completed in the various state objects
    async fn record_completed_match(&self, request_id: Uuid) -> Result<(), HandshakeManagerError> {
        // Get the order IDs from the state machine
        let state = self.handshake_state_index.get_state(&request_id).await.ok_or_else(|| {
            HandshakeManagerError::InvalidRequest(format!("request_id {:?}", request_id))
        })?;

        // Cache the order pair as completed
        self.handshake_cache
            .write()
            .await
            .mark_completed(state.local_order_id, state.peer_order_id);

        // Write to global state for debugging
        self.global_state.mark_order_pair_matched(state.local_order_id, state.peer_order_id).await;

        // Update the state of the handshake in the completed state
        self.handshake_state_index.completed(&request_id).await;

        // Send a message to cluster peers indicating that the local peer has completed
        // a match Cluster peers should cache the matched order pair as
        // completed and not initiate matches on this pair going forward
        let cluster_id = self.global_state.local_cluster_id.clone();
        self.network_channel
            .send(GossipOutbound::Pubsub {
                topic: cluster_id.get_management_topic(),
                message: PubsubMessage::ClusterManagement {
                    cluster_id,
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
                timestamp: get_timestamp_millis(),
            },
        );

        Ok(())
    }

    /// Helper to spawn a task in the task driver that submits a match and
    /// settles its result
    async fn submit_match(
        &self,
        party0_proof: OrderValidityProofBundle,
        party1_proof: OrderValidityProofBundle,
        handshake_state: HandshakeState,
        match_res: Box<HandshakeResult>,
    ) -> TaskIdentifier {
        // Submit the match to the contract
        let task = SettleMatchTask::new(
            handshake_state,
            match_res,
            party0_proof,
            party1_proof,
            self.starknet_client.clone(),
            self.network_channel.clone(),
            self.global_state.clone(),
            self.proof_manager_work_queue.clone(),
        )
        .await;
        self.task_driver.start_task(task).await.0
    }
}

/// Implements a timer that periodically enqueues jobs to the threadpool that
/// tell the manager to send outbound handshake requests
#[derive(Clone)]
pub struct HandshakeScheduler {
    /// The UnboundedSender to enqueue jobs on
    job_sender: TokioSender<HandshakeExecutionJob>,
    /// A copy of the relayer-global state
    global_state: RelayerState,
    /// The cancel channel to receive cancel signals on
    cancel: CancelChannel,
}

impl HandshakeScheduler {
    /// Construct a new timer
    pub fn new(
        job_sender: TokioSender<HandshakeExecutionJob>,
        global_state: RelayerState,
        cancel: CancelChannel,
    ) -> Self {
        Self { job_sender, global_state, cancel }
    }

    /// The execution loop of the timer, periodically enqueues handshake jobs
    pub async fn execution_loop(mut self) -> HandshakeManagerError {
        let interval_seconds = HANDSHAKE_INTERVAL_MS / 1000;
        let interval_nanos = (HANDSHAKE_INTERVAL_MS % 1000 * NANOS_PER_MILLI) as u32;

        let refresh_interval = Duration::new(interval_seconds, interval_nanos);

        loop {
            tokio::select! {
                // Enqueue handshakes periodically according to a timer
                _ = tokio::time::sleep(refresh_interval) => {
                    // Enqueue a job to handshake with the randomly selected peer
                    if let Some(order) = self.global_state.choose_handshake_order().await {
                        if let Err(e) = self
                            .job_sender
                            .send(HandshakeExecutionJob::PerformHandshake { order })
                            .map_err(|err| HandshakeManagerError::SendMessage(err.to_string()))
                        {
                            return e;
                        }
                    }
                },

                _ = self.cancel.changed() => {
                    log::info!("Handshake manager cancelled, winding down");
                    return HandshakeManagerError::Cancelled("received cancel signal".to_string());
                }
            }
        }
    }
}
