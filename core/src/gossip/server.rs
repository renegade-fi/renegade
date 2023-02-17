//! The gossip server manages the general gossip network interaction of a single p2p node
//!
//! This file groups logic for creating the server as well as the central dispatch/execution
//! loop of the workers

use std::{
    num::NonZeroUsize,
    sync::{Arc, RwLock},
    thread::{self, Builder, JoinHandle},
    time::Duration,
};

use crossbeam::channel::{Receiver, Sender};
use lru::LruCache;
use rayon::{ThreadPool, ThreadPoolBuilder};
use tokio::sync::mpsc::UnboundedSender;
use tracing::log;

use crate::{
    api::{
        cluster_management::{ClusterJoinMessage, ClusterManagementMessage},
        gossip::{GossipOutbound, GossipResponse, ManagerControlDirective, PubsubMessage},
    },
    state::RelayerState,
};

use super::{
    errors::GossipError,
    heartbeat::{
        HeartbeatTimer, CLUSTER_HEARTBEAT_INTERVAL_MS, EXPIRY_CACHE_SIZE, HEARTBEAT_INTERVAL_MS,
    },
    jobs::GossipServerJob,
    types::WrappedPeerId,
    worker::GossipServerConfig,
};

/// The number of threads backing the gossip executor's thread pool
const GOSSIP_EXECUTOR_N_THREADS: usize = 5;
/// The amount of time to wait for the node to find peers before sending
/// pubsub messages associated with setup
const PUBSUB_WARMUP_TIME_MS: u64 = 5_000; // 5 seconds

/// Type alias for a shared LRU cache
pub(super) type SharedLRUCache = Arc<RwLock<LruCache<WrappedPeerId, u64>>>;

/// The server type that manages interactions with the gossip network
#[derive(Debug)]
pub struct GossipServer {
    /// The config for the Gossip Server
    pub(super) config: GossipServerConfig,
    /// The protocol executor, handles request/response for the gossip protocol
    pub(super) protocol_executor_handle: Option<JoinHandle<GossipError>>,
}

impl GossipServer {
    /// Waits for the local node to warm up in the network (build up
    /// a graph of a few peers), and then publish an event to join the
    /// local cluster
    pub(super) fn warmup_then_join_cluster(
        &self,
        global_state: &RelayerState,
        heartbeat_work_queue: Sender<GossipServerJob>,
    ) -> Result<(), GossipError> {
        // Advertise presence of new, local node by sending a heartbeat to all known peers
        {
            for peer_id in global_state.read_peer_index().get_all_peer_ids().iter() {
                heartbeat_work_queue
                    .send(GossipServerJob::ExecuteHeartbeat(*peer_id))
                    .map_err(|err| GossipError::SendMessage(err.to_string()))?;
            }
        } // known_peers lock released

        // Send a pubsub message indicating that the local peer has joined the cluster; this message
        // will be buffered by the network manager until the warmup period is complete
        let message_body = ClusterJoinMessage {
            peer_id: self.config.local_peer_id,
            peer_info: global_state
                .read_peer_index()
                .read_peer(&self.config.local_peer_id)
                .unwrap()
                .clone(),
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
        // Spawn a thread to wait on a timeout and then signal to the network manager that it
        // may flush the pubsub buffer
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
#[derive(Clone, Debug)]
pub struct GossipProtocolExecutor {
    /// The peer ID of the local node
    pub(super) local_peer_id: WrappedPeerId,
    /// The peer expiry cache holds peers in an invisibility window so that when a peer is
    /// expired, it cannot be incorrectly re-discovered for some time, until its expiry
    /// has had time to propagate
    pub(super) peer_expiry_cache: SharedLRUCache,
    /// The channel on which to receive jobs
    pub(super) job_receiver: Receiver<GossipServerJob>,
    /// The channel to send outbound network requests on
    pub(super) network_channel: UnboundedSender<GossipOutbound>,
    /// The thread pool backing the protocol executor
    pub(super) thread_pool: Arc<ThreadPool>,
    /// The global state of the relayer
    pub(super) global_state: RelayerState,
    /// The channel that the coordinator thread uses to cancel gossip execution
    pub(super) cancel_channel: Option<Receiver<()>>,
}

impl GossipProtocolExecutor {
    /// Creates a new executor
    pub fn new(
        local_peer_id: WrappedPeerId,
        network_channel: UnboundedSender<GossipOutbound>,
        job_receiver: Receiver<GossipServerJob>,
        global_state: RelayerState,
        cancel_channel: Receiver<()>,
    ) -> Result<Self, GossipError> {
        // Tracks recently expired peers and blocks them from being re-registered
        // until the state has synced. Maps peer_id to expiry time
        let peer_expiry_cache: SharedLRUCache = Arc::new(RwLock::new(LruCache::new(
            NonZeroUsize::new(EXPIRY_CACHE_SIZE).unwrap(),
        )));

        // Build a threadpool to execute tasks within
        let thread_pool = ThreadPoolBuilder::new()
            .num_threads(GOSSIP_EXECUTOR_N_THREADS)
            .build()
            .map_err(|err| GossipError::ServerSetup(err.to_string()))?;

        Ok(Self {
            local_peer_id,
            peer_expiry_cache,
            job_receiver,
            network_channel,
            thread_pool: Arc::new(thread_pool),
            global_state,
            cancel_channel: Some(cancel_channel),
        })
    }

    /// Runs the executor loop
    pub fn execution_loop(mut self, job_sender: Sender<GossipServerJob>) -> GossipError {
        log::info!("Starting executor loop for heartbeat protocol executor...");

        // Start a timer to enqueue outbound heartbeats
        HeartbeatTimer::new(
            job_sender,
            CLUSTER_HEARTBEAT_INTERVAL_MS,
            HEARTBEAT_INTERVAL_MS,
            self.global_state.clone(),
        );

        // We check for cancels both before receiving a job (so that we don't sleep after cancellation)
        // and after a receiving a job (so that we avoid unnecessary work)
        let cancel_channel = self.cancel_channel.take().unwrap();
        loop {
            // Check for cancel before sleeping
            if !cancel_channel.is_empty() {
                return GossipError::Cancelled("received cancel signal".to_string());
            }

            // Dequeue the next job
            let job = self.job_receiver.recv().expect("recv should not panic");

            // Check for cancel after receiving job
            if !cancel_channel.is_empty() {
                return GossipError::Cancelled("received cancel signal".to_string());
            }

            // Forward the job to the threadpool
            let self_clone = self.clone();
            self.thread_pool.spawn(move || self_clone.handle_job(job));
        }
    }

    /// The main dispatch method for handling jobs
    fn handle_job(&self, job: GossipServerJob) {
        let res: Result<(), GossipError> = match job {
            GossipServerJob::Bootstrap(_, response_channel) => {
                // Send a heartbeat response for simplicity
                let heartbeat_resp = GossipResponse::Heartbeat(self.build_heartbeat_message());
                self.network_channel
                    .send(GossipOutbound::Response {
                        channel: response_channel,
                        message: heartbeat_resp,
                    })
                    .map_err(|err| GossipError::SendMessage(err.to_string()))
            }
            GossipServerJob::ExecuteHeartbeat(peer_id) => self.send_heartbeat(peer_id),
            GossipServerJob::HandleHeartbeatReq {
                message, channel, ..
            } => {
                // Respond on the channel given in the request
                let heartbeat_resp = GossipResponse::Heartbeat(self.build_heartbeat_message());
                let res = self
                    .network_channel
                    .send(GossipOutbound::Response {
                        channel,
                        message: heartbeat_resp,
                    })
                    .map_err(|err| GossipError::SendMessage(err.to_string()));

                // Merge newly discovered peers into local state
                self.merge_state_from_message(message).and(res)
            }
            GossipServerJob::HandleHeartbeatResp { peer_id, message } => {
                self.record_heartbeat(peer_id);
                self.merge_state_from_message(message)
            }
            GossipServerJob::Cluster(job) => self.handle_cluster_management_job(job),
            GossipServerJob::OrderBookManagement(management_message) => {
                self.handle_order_book_management_job(management_message)
            }
        };

        if let Err(err) = res {
            log::info!(
                "Error in gossip server execution loop: {:?}",
                err.to_string()
            );
        }
    }
}
