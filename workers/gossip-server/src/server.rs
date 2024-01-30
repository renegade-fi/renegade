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
    pubsub::PubsubMessage,
    request_response::{heartbeat::BootstrapRequest, GossipRequest, GossipResponse},
};
use job_types::{
    gossip_server::{GossipServerJob, GossipServerQueue, GossipServerReceiver},
    network_manager::{NetworkManagerControlSignal, NetworkManagerJob, NetworkManagerQueue},
};
use lru::LruCache;
use state::State;
use std::{
    num::NonZeroUsize,
    thread::{self, Builder, JoinHandle},
    time::Duration,
};
use tracing::log;
use util::err_str;

use crate::peer_discovery::{
    heartbeat::{CLUSTER_HEARTBEAT_INTERVAL_MS, EXPIRY_CACHE_SIZE, HEARTBEAT_INTERVAL_MS},
    heartbeat_timer::HeartbeatTimer,
};

use super::{errors::GossipError, worker::GossipServerConfig};

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
    pub fn bootstrap_into_network(&self) -> Result<(), GossipError> {
        // Bootstrap into the network in two steps:
        //  1. Forward all bootstrap addresses to the network manager so it may dial
        //     them
        //  2. Send bootstrap requests to all bootstrapping peers
        //  3. Send heartbeats to all peers for state sync
        // Wait until all peers have been indexed before sending requests to give async
        // network manager time to index the peers in the case that these
        // messages are processed concurrently

        // 1. Forward bootstrap addresses to the network manager
        for (peer_id, address) in self.config.bootstrap_servers.iter().cloned() {
            let cmd = NetworkManagerControlSignal::NewAddr { peer_id, address };
            let job = NetworkManagerJob::internal(cmd);

            self.config.network_sender.send(job).map_err(err_str!(GossipError::SendMessage))?;
        }

        // 2. Send bootstrap requests to all known peers
        let my_id = self.config.local_peer_id;
        let my_info = self.state().get_peer_info(&my_id)?.unwrap();
        let req = GossipRequest::Bootstrap(BootstrapRequest { peer_info: my_info });
        for (peer_id, _) in self.config.bootstrap_servers.iter() {
            let req = NetworkManagerJob::request(*peer_id, req.clone());
            self.config.network_sender.send(req).map_err(err_str!(GossipError::SendMessage))?;
        }

        // 3. Send heartbeats to all known peers to sync state
        let peer_ids = self.state().get_all_peers_ids(false /* include_self */)?;
        for peer in peer_ids.into_iter() {
            self.config
                .job_sender
                .send(GossipServerJob::ExecuteHeartbeat(peer))
                .map_err(err_str!(GossipError::SendMessage))?;
        }

        // Finally, warmup the network then send a cluster join message
        self.warmup_then_join_cluster()
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
    fn warmup_then_join_cluster(&self) -> Result<(), GossipError> {
        // TODO: Send a raft join message to peers, possibly via pubsub

        // Copy items so they may be moved into the spawned thread
        let network_sender_copy = self.config.network_sender.clone();
        // Spawn a thread to wait on a timeout and then signal to the network manager
        // that it may flush the pubsub buffer
        Builder::new()
            .name("gossip-warmup-timer".to_string())
            .spawn(move || {
                // Wait for the network to warmup
                thread::sleep(Duration::from_millis(PUBSUB_WARMUP_TIME_MS));
                let cmd =
                    NetworkManagerJob::internal(NetworkManagerControlSignal::GossipWarmupComplete);
                network_sender_copy.send(cmd).unwrap();
            })
            .map_err(err_str!(GossipError::ServerSetup))?;

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
    pub peer_expiry_cache: SharedLRUCache,
    /// The channel on which to receive jobs
    pub job_receiver: DefaultWrapper<Option<GossipServerReceiver>>,
    /// The channel to send outbound network requests on
    pub network_channel: NetworkManagerQueue,
    /// The global state of the relayer
    pub global_state: State,
    /// A copy of the config passed to the worker
    pub config: GossipServerConfig,
    /// The channel that the coordinator thread uses to cancel gossip execution
    pub cancel_channel: CancelChannel,
}

impl GossipProtocolExecutor {
    /// Creates a new executor
    pub fn new(
        network_channel: NetworkManagerQueue,
        job_receiver: GossipServerReceiver,
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
        job_sender: GossipServerQueue,
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
            GossipServerJob::ExecuteHeartbeat(peer_id) => self.send_heartbeat(peer_id).await?,
            GossipServerJob::NetworkRequest(peer_id, req, response_chan) => {
                let resp = self.handle_request(peer_id, req).await?;
                let job = NetworkManagerJob::response(resp, response_chan);

                self.network_channel.send(job).map_err(err_str!(GossipError::SendMessage))?;
            },
            GossipServerJob::NetworkResponse(peer_id, resp) => {
                self.handle_response(peer_id, resp).await?
            },
            GossipServerJob::Pubsub(msg) => self.handle_pubsub(msg).await?,
        };

        Ok(())
    }

    /// Handles a gossip request type from a peer
    async fn handle_request(
        &self,
        peer: WrappedPeerId,
        req: GossipRequest,
    ) -> Result<GossipResponse, GossipError> {
        match req {
            GossipRequest::Bootstrap(req) => self.handle_bootstrap_req(req).await,
            GossipRequest::Heartbeat(req) => {
                self.handle_heartbeat(&peer, req)?;
                Ok(GossipResponse::Ack)
            },
            GossipRequest::PeerInfo(req) => self.handle_peer_info_req(req.peer_ids),
            GossipRequest::OrderInfo(req) => self.handle_order_info_request(req.order_ids),
            req => Err(GossipError::UnhandledRequest(format!("{req:?}"))),
        }
    }

    /// Handles a gossip response type from a peer
    async fn handle_response(
        &self,
        peer: WrappedPeerId,
        resp: GossipResponse,
    ) -> Result<(), GossipError> {
        match resp {
            GossipResponse::Heartbeat(resp) => self.handle_heartbeat(&peer, resp),
            GossipResponse::OrderInfo(resp) => {
                self.handle_order_info_response(resp.order_info).await
            },
            GossipResponse::PeerInfo(resp) => self.handle_peer_info_resp(resp.peer_info).await,
            resp => Err(GossipError::UnhandledRequest(format!("{resp:?}"))),
        }
    }

    /// Handles an inbound pubsub message from the network
    async fn handle_pubsub(&self, msg: PubsubMessage) -> Result<(), GossipError> {
        match msg {
            PubsubMessage::Orderbook(msg) => self.handle_orderbook_pubsub(msg).await,
            msg => Err(GossipError::UnhandledRequest(format!("{msg:?}"))),
        }
    }
}
