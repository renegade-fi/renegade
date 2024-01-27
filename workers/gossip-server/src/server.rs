//! The gossip server manages the general gossip network interaction of a single
//! p2p node
//!
//! This file groups logic for creating the server as well as the central
//! dispatch/execution loop of the workers

use arbitrum_client::client::ArbitrumClient;
use common::{
    default_wrapper::DefaultWrapper,
    new_async_shared,
    types::{gossip::WrappedPeerId, CancelChannel},
    AsyncShared,
};
use gossip_api::{
    cluster_management::{ClusterJoinMessage, ClusterManagementMessage},
    gossip::{
        GossipOutbound, GossipRequest, GossipResponse, ManagerControlDirective, PubsubMessage,
    },
    heartbeat::BootstrapRequest,
};
use job_types::gossip_server::GossipServerJob;
use lru::LruCache;
use statev2::State;
use std::{
    num::NonZeroUsize,
    thread::{self, Builder, JoinHandle},
    time::Duration,
};
use tokio::sync::mpsc::{UnboundedReceiver as TokioReceiver, UnboundedSender as TokioSender};
use tracing::log;

use super::{
    errors::GossipError,
    heartbeat::{
        HeartbeatTimer, CLUSTER_HEARTBEAT_INTERVAL_MS, EXPIRY_CACHE_SIZE, HEARTBEAT_INTERVAL_MS,
    },
    worker::GossipServerConfig,
};

/// The number of threads backing the gossip executor's thread pool
pub(super) const GOSSIP_EXECUTOR_N_THREADS: usize = 5;
/// The number of threads backing the blocking thread pool of the executor
pub(super) const GOSSIP_EXECUTOR_N_BLOCKING_THREADS: usize = 5;
/// The amount of time to wait for the node to find peers before sending
/// pubsub messages associated with setup
const PUBSUB_WARMUP_TIME_MS: u64 = 5_000; // 5 seconds

/// Type alias for a shared LRU cache
pub(super) type SharedLRUCache = AsyncShared<LruCache<WrappedPeerId, u64>>;

/// The server type that manages interactions with the gossip network
pub struct GossipServer {
    /// The config for the Gossip Server
    pub(super) config: GossipServerConfig,
    /// The protocol executor, handles request/response for the gossip protocol
    pub(super) protocol_executor_handle: Option<JoinHandle<GossipError>>,
}

impl GossipServer {
    /// Get a reference to the global state
    pub fn state(&self) -> &State {
        &self.config.global_state
    }

    /// Bootstraps the local node into the network by syncing state with known
    /// bootstrap peers and then advertising the local node's presence to the
    /// cluster
    pub(super) async fn bootstrap_into_network(&self) -> Result<(), GossipError> {
        // Bootstrap into the network in two steps:
        //  1. Forward all bootstrap addresses to the network manager so it may dial
        //     them
        //  2. Send bootstrap requests to all bootstrapping peers
        //  3. Send heartbeats to all peers for state sync
        // Wait until all peers have been indexed before sending requests to give async
        // network manager time to index the peers in the case that these
        // messages are processed concurrently

        // 1. Forward bootstrap addresses to the network manager
        for (peer_id, peer_addr) in self.config.bootstrap_servers.iter() {
            self.config
                .network_sender
                .send(GossipOutbound::ManagementMessage(ManagerControlDirective::NewAddr {
                    peer_id: *peer_id,
                    address: peer_addr.clone(),
                }))
                .map_err(|err| GossipError::SendMessage(err.to_string()))?;
        }

        // 2. Send bootstrap requests to all known peers
        let my_id = self.config.local_peer_id;
        let my_info = self.state().get_peer_info(&my_id)?.unwrap();
        let req = BootstrapRequest { peer_info: my_info };
        for (peer_id, _) in self.config.bootstrap_servers.iter() {
            self.config
                .network_sender
                .send(GossipOutbound::Request {
                    peer_id: *peer_id,
                    message: GossipRequest::Bootstrap(req.clone()),
                })
                .map_err(|err| GossipError::SendMessage(err.to_string()))?;
        }

        // 3. Send heartbeats to all known peers to sync state
        let peer_ids = self.state().get_all_peers_ids(false /* include_self */)?;
        for peer in peer_ids.into_iter() {
            self.config
                .job_sender
                .send(GossipServerJob::ExecuteHeartbeat(peer))
                .map_err(|err| GossipError::SendMessage(err.to_string()))?;
        }

        // Finally,
        self.warmup_then_join_cluster().await
    }

    /// Enqueues a pubsub message to join the local peer's cluster, then spawns
    /// a timer that allows the network manager to warm up pubsub
    /// connections
    ///
    /// Once this timer expires, the timer thread enqueues a management
    /// directive in the network manager to release buffered pubsub messages
    /// onto the network.
    ///
    /// This is done to allow the network manager to gossip about network
    /// structure and graft a pubsub mesh before attempting to publish
    async fn warmup_then_join_cluster(&self) -> Result<(), GossipError> {
        // Send a pubsub message indicating that the local peer has joined the cluster;
        // this message will be buffered by the network manager until the warmup
        // period is complete
        let my_id = self.config.local_peer_id;
        let peer_info = self.state().get_peer_info(&my_id)?.unwrap();
        let message_body = ClusterJoinMessage {
            peer_id: self.config.local_peer_id,
            peer_info,
            addr: self.config.local_addr.clone(),
        };

        self.config
            .network_sender
            .send(GossipOutbound::Pubsub {
                topic: self.config.cluster_id.get_management_topic(),
                message: PubsubMessage::ClusterManagement {
                    cluster_id: self.config.cluster_id.clone(),
                    message: ClusterManagementMessage::Join(message_body),
                },
            })
            .map_err(|err| GossipError::SendMessage(err.to_string()))?;

        // Copy items so they may be moved into the spawned thread
        let network_sender_copy = self.config.network_sender.clone();
        // Spawn a thread to wait on a timeout and then signal to the network manager
        // that it may flush the pubsub buffer
        Builder::new()
            .name("gossip-warmup-timer".to_string())
            .spawn(move || {
                // Wait for the network to warmup
                thread::sleep(Duration::from_millis(PUBSUB_WARMUP_TIME_MS));
                network_sender_copy
                    .send(GossipOutbound::ManagementMessage(
                        ManagerControlDirective::GossipWarmupComplete,
                    ))
                    .unwrap();
            })
            .map_err(|err| GossipError::ServerSetup(err.to_string()))?;

        Ok(())
    }
}

// ---------------------
// | Protocol Executor |
// ---------------------

/// Executes the heartbeat protocols
#[derive(Clone)]
pub struct GossipProtocolExecutor {
    /// The peer expiry cache holds peers in an invisibility window so that when
    /// a peer is expired, it cannot be incorrectly re-discovered for some
    /// time, until its expiry has had time to propagate
    pub(super) peer_expiry_cache: SharedLRUCache,
    /// The channel on which to receive jobs
    pub(super) job_receiver: DefaultWrapper<Option<TokioReceiver<GossipServerJob>>>,
    /// The channel to send outbound network requests on
    pub(super) network_channel: TokioSender<GossipOutbound>,
    /// The global state of the relayer
    pub(super) global_state: State,
    /// A copy of the config passed to the worker
    pub(super) config: GossipServerConfig,
    /// The channel that the coordinator thread uses to cancel gossip execution
    pub(super) cancel_channel: CancelChannel,
}

impl GossipProtocolExecutor {
    /// Creates a new executor
    pub fn new(
        network_channel: TokioSender<GossipOutbound>,
        job_receiver: TokioReceiver<GossipServerJob>,
        global_state: State,
        config: GossipServerConfig,
        cancel_channel: CancelChannel,
    ) -> Result<Self, GossipError> {
        // Tracks recently expired peers and blocks them from being re-registered
        // until the state has synced. Maps peer_id to expiry time
        let peer_expiry_cache: SharedLRUCache =
            new_async_shared(LruCache::new(NonZeroUsize::new(EXPIRY_CACHE_SIZE).unwrap()));

        Ok(Self {
            peer_expiry_cache,
            job_receiver: DefaultWrapper::new(Some(job_receiver)),
            network_channel,
            global_state,
            config,
            cancel_channel,
        })
    }

    /// Shorthand to fetch the arbitrum client from the config
    pub(super) fn arbitrum_client(&self) -> &ArbitrumClient {
        &self.config.arbitrum_client
    }

    /// Runs the executor loop
    pub async fn execution_loop(
        mut self,
        job_sender: TokioSender<GossipServerJob>,
    ) -> Result<(), GossipError> {
        log::info!("Starting executor loop for heartbeat protocol executor...");

        // Start a timer to enqueue outbound heartbeats
        HeartbeatTimer::new(
            job_sender,
            CLUSTER_HEARTBEAT_INTERVAL_MS,
            HEARTBEAT_INTERVAL_MS,
            self.global_state.clone(),
        );

        // We check for cancels both before receiving a job (so that we don't sleep
        // after cancellation) and after a receiving a job (so that we avoid
        // unnecessary work)
        let mut job_receiver = self.job_receiver.take().unwrap();
        loop {
            tokio::select! {
                // Await the next job
                Some(job) = job_receiver.recv() => {
                    let self_clone = self.clone();
                    #[allow(clippy::redundant_async_block)]
                    tokio::spawn(async move {
                        if let Err(e) = self_clone.handle_job(job).await {
                            log::error!("error handling gossip server job: {e}");
                        }}
                    );
                },

                // Await a cancel signal from the coordinator
                _ = self.cancel_channel.changed() => {
                    log::info!("Gossip server cancelled, shutting down...");
                    return Err(GossipError::Cancelled("server cancelled".to_string()));
                }
            }
        }
    }

    /// The main dispatch method for handling jobs
    async fn handle_job(&self, job: GossipServerJob) -> Result<(), GossipError> {
        match job {
            GossipServerJob::Bootstrap(req, response_channel) => {
                // Add the bootstrapping peer to the index
                self.add_new_peers(vec![req.peer_info]).await.map(|_| ())?;

                // Send a heartbeat response for simplicity
                let heartbeat_resp = GossipResponse::Heartbeat(self.build_heartbeat()?);
                self.network_channel
                    .send(GossipOutbound::Response {
                        channel: response_channel,
                        message: heartbeat_resp,
                    })
                    .map_err(|err| GossipError::SendMessage(err.to_string()))?;
            },
            GossipServerJob::ExecuteHeartbeat(peer_id) => self.send_heartbeat(peer_id).await?,
            GossipServerJob::HandleHeartbeatReq { message, channel, .. } => {
                // Respond on the channel given in the request
                let heartbeat_resp = GossipResponse::Heartbeat(self.build_heartbeat()?);
                let res = self
                    .network_channel
                    .send(GossipOutbound::Response { channel, message: heartbeat_resp })
                    .map_err(|err| GossipError::SendMessage(err.to_string()));

                // Merge newly discovered peers into local state
                self.merge_state_from_message(message).await.and(res)?
            },
            GossipServerJob::HandleHeartbeatResp { peer_id, message } => {
                self.record_heartbeat(peer_id).await?;
                self.merge_state_from_message(message).await?;
            },
            GossipServerJob::Cluster(..) => todo!("use raft join/leave protocol instead"),
            GossipServerJob::OrderBookManagement(management_message) => {
                self.handle_order_book_management_job(management_message).await?;
            },
            GossipServerJob::WalletUpdate { .. } => {
                todo!("move this into raft-based consensus");
            },
        };

        Ok(())
    }
}
