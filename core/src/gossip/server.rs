//! The gossip server manages the general gossip network interaction of a single p2p node
//!
//! This file groups logic for creating the server as well as the central dispatch/execution
//! loop of the workers

use std::{
    sync::{Arc, RwLock},
    thread::{self, JoinHandle},
    time::Duration,
};

use crossbeam::channel::{Receiver, Sender};
use lru::LruCache;
use tokio::sync::mpsc::UnboundedSender;

use crate::{
    api::{
        cluster_management::{ClusterJoinMessage, ClusterManagementMessage},
        gossip::{GossipOutbound, GossipResponse, PubsubMessage},
    },
    state::RelayerState,
    CancelChannel,
};

use super::{
    errors::GossipError,
    heartbeat::{HeartbeatTimer, EXPIRY_CACHE_SIZE, HEARTBEAT_INTERVAL_MS},
    jobs::GossipServerJob,
    types::WrappedPeerId,
    worker::GossipServerConfig,
};

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
    pub(super) protocol_executor: Option<GossipProtocolExecutor>,
}

impl GossipServer {
    /// Waits for the local node to warm up in the network (build up
    /// a graph of a few peers), and then publish an event to join the
    /// local cluster
    pub(super) fn warmup_then_join_cluster(&self) {
        // Copy items so they may be moved into the spawned threadd
        let network_sender_copy = self.config.network_sender.clone();
        let cluster_management_topic = self.config.cluster_id.get_management_topic();

        // Construct the message outside of the thread to avoid messy ownership copies
        // The cluster ID is automatically appended at the network layer
        let message_body = ClusterJoinMessage {
            peer_id: self.config.local_peer_id,
            addr: self.config.local_addr.clone(),
        };
        let message = PubsubMessage::new_cluster_management_unsigned(
            self.config.cluster_id.clone(),
            ClusterManagementMessage::Join(message_body),
        );

        // Spawn a thread that will wait some time until the peer has warmed up into the network
        // and then emit a pubsub even indicating it has joined its cluster
        thread::spawn(move || {
            // Wait for the network to warmup
            thread::sleep(Duration::from_millis(PUBSUB_WARMUP_TIME_MS));

            // Forward the message to the network manager for delivery
            let join_message = GossipOutbound::Pubsub {
                topic: cluster_management_topic,
                message,
            };
            network_sender_copy
                .send(join_message)
                .map_err(|err| GossipError::ServerSetup(err.to_string()))
                .unwrap();
        });
    }
}

/**
 * Gossip protocol main event and dispatch loop
 */

/// Executes the heartbeat protocols
#[derive(Debug)]
pub struct GossipProtocolExecutor {
    /// The handle of the worker thread executing heartbeat jobs
    thread_handle: Option<JoinHandle<GossipError>>,
    /// The timer that enqueues heartbeat jobs periodically for the worker
    heartbeat_timer: HeartbeatTimer,
}

impl GossipProtocolExecutor {
    /// Creates a new executor
    pub fn new(
        local_peer_id: WrappedPeerId,
        network_channel: UnboundedSender<GossipOutbound>,
        job_sender: Sender<GossipServerJob>,
        job_receiver: Receiver<GossipServerJob>,
        global_state: RelayerState,
        cancel_channel: Receiver<()>,
    ) -> Result<Self, GossipError> {
        // Tracks recently expired peers and blocks them from being re-registered
        // until the state has synced. Maps peer_id to expiry time
        let peer_expiry_cache: SharedLRUCache =
            Arc::new(RwLock::new(LruCache::new(EXPIRY_CACHE_SIZE)));
        let state_clone = global_state.clone();

        let thread_handle = {
            thread::Builder::new()
                .name("heartbeat-executor".to_string())
                .spawn(move || {
                    Self::executor_loop(
                        local_peer_id,
                        job_receiver,
                        network_channel,
                        peer_expiry_cache,
                        state_clone,
                        cancel_channel,
                    )
                })
                .map_err(|err| GossipError::ServerSetup(err.to_string()))
        }?;

        let heartbeat_timer = HeartbeatTimer::new(job_sender, HEARTBEAT_INTERVAL_MS, global_state);

        Ok(Self {
            thread_handle: Some(thread_handle),
            heartbeat_timer,
        })
    }

    /// Joins execution of the calling thread to the worker thread
    pub fn join(&mut self) -> Vec<JoinHandle<GossipError>> {
        vec![
            self.thread_handle.take().unwrap(),
            self.heartbeat_timer.join_handle(),
        ]
    }

    /// Runs the executor loop
    fn executor_loop(
        local_peer_id: WrappedPeerId,
        job_receiver: Receiver<GossipServerJob>,
        network_channel: UnboundedSender<GossipOutbound>,
        peer_expiry_cache: SharedLRUCache,
        global_state: RelayerState,
        cancel: CancelChannel,
    ) -> GossipError {
        println!("Starting executor loop for heartbeat protocol executor...");
        // We check for cancels both before receiving a job (so that we don't sleep after cancellation)
        // and after a receiving a job (so that we avoid unnecessary work)
        loop {
            // Check for cancel before sleeping
            if !cancel.is_empty() {
                return GossipError::Cancelled("received cancel signal".to_string());
            }

            // Dequeue the next job
            let job = job_receiver.recv().expect("recv should not panic");

            // Check for cancel after receiving job
            if !cancel.is_empty() {
                return GossipError::Cancelled("received cancel signal".to_string());
            }

            match job {
                GossipServerJob::ExecuteHeartbeat(peer_id) => {
                    Self::send_heartbeat(
                        peer_id,
                        local_peer_id,
                        network_channel.clone(),
                        peer_expiry_cache.clone(),
                        &global_state,
                    );
                }
                GossipServerJob::HandleHeartbeatReq {
                    message, channel, ..
                } => {
                    // Respond on the channel given in the request
                    let heartbeat_resp =
                        GossipResponse::Heartbeat(Self::build_heartbeat_message(&global_state));
                    network_channel
                        .send(GossipOutbound::Response {
                            channel,
                            message: heartbeat_resp,
                        })
                        .unwrap();

                    // Merge newly discovered peers into local state
                    Self::merge_state_from_message(
                        local_peer_id,
                        &message,
                        network_channel.clone(),
                        peer_expiry_cache.clone(),
                        global_state.clone(),
                    )
                }
                GossipServerJob::HandleHeartbeatResp { peer_id, message } => {
                    Self::record_heartbeat(peer_id, global_state.clone());
                    Self::merge_state_from_message(
                        local_peer_id,
                        &message,
                        network_channel.clone(),
                        peer_expiry_cache.clone(),
                        global_state.clone(),
                    )
                }
                GossipServerJob::Cluster(job) => {
                    if let Err(err) = Self::handle_cluster_management_job(
                        job,
                        network_channel.clone(),
                        &global_state,
                    ) {
                        return err;
                    }
                }
            }
        }
    }
}
