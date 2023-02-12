//! The gossip server manages the general gossip network interaction of a single p2p node
//!
//! This file groups logic for creating the server as well as the central dispatch/execution
//! loop of the workers

use std::{
    num::NonZeroUsize,
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
        gossip::{GossipOutbound, GossipResponse, ManagerControlDirective, PubsubMessage},
    },
    state::RelayerState,
    CancelChannel,
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
                message: PubsubMessage::new_cluster_management_unsigned(
                    self.config.cluster_id.clone(),
                    ClusterManagementMessage::Join(message_body),
                ),
            })
            .map_err(|err| GossipError::SendMessage(err.to_string()))?;

        // Copy items so they may be moved into the spawned thread
        let network_sender_copy = self.config.network_sender.clone();
        // Spawn a thread to wait on a timeout and then signal to the network manager that it
        // may flush the pubsub buffer
        thread::spawn(move || {
            // Wait for the network to warmup
            thread::sleep(Duration::from_millis(PUBSUB_WARMUP_TIME_MS));
            network_sender_copy
                .send(GossipOutbound::ManagementMessage(
                    ManagerControlDirective::GossipWarmupComplete,
                ))
                .unwrap()
        });

        Ok(())
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
        let peer_expiry_cache: SharedLRUCache = Arc::new(RwLock::new(LruCache::new(
            NonZeroUsize::new(EXPIRY_CACHE_SIZE).unwrap(),
        )));
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

        let heartbeat_timer = HeartbeatTimer::new(
            job_sender,
            CLUSTER_HEARTBEAT_INTERVAL_MS,
            HEARTBEAT_INTERVAL_MS,
            global_state,
        );

        Ok(Self {
            thread_handle: Some(thread_handle),
            heartbeat_timer,
        })
    }

    /// Joins execution of the calling thread to the worker thread
    pub fn join(&mut self) -> Vec<JoinHandle<GossipError>> {
        let mut handles = vec![self.thread_handle.take().unwrap()];
        handles.append(&mut self.heartbeat_timer.join_handle());
        handles
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

            let res = match job {
                GossipServerJob::Bootstrap(_, response_channel) => {
                    // Send a heartbeat response for simplicity
                    let heartbeat_resp =
                        GossipResponse::Heartbeat(Self::build_heartbeat_message(&global_state));
                    network_channel
                        .send(GossipOutbound::Response {
                            channel: response_channel,
                            message: heartbeat_resp,
                        })
                        .map_err(|err| GossipError::SendMessage(err.to_string()))
                }
                GossipServerJob::ExecuteHeartbeat(peer_id) => Self::send_heartbeat(
                    peer_id,
                    local_peer_id,
                    network_channel.clone(),
                    peer_expiry_cache.clone(),
                    &global_state,
                ),
                GossipServerJob::HandleHeartbeatReq {
                    message, channel, ..
                } => {
                    // Respond on the channel given in the request
                    let heartbeat_resp =
                        GossipResponse::Heartbeat(Self::build_heartbeat_message(&global_state));
                    let res = network_channel
                        .send(GossipOutbound::Response {
                            channel,
                            message: heartbeat_resp,
                        })
                        .map_err(|err| GossipError::SendMessage(err.to_string()));

                    // Merge newly discovered peers into local state
                    Self::merge_state_from_message(
                        message,
                        network_channel.clone(),
                        peer_expiry_cache.clone(),
                        global_state.clone(),
                    )
                    .and(res)
                }
                GossipServerJob::HandleHeartbeatResp { peer_id, message } => {
                    Self::record_heartbeat(peer_id, global_state.clone());
                    Self::merge_state_from_message(
                        message,
                        network_channel.clone(),
                        peer_expiry_cache.clone(),
                        global_state.clone(),
                    )
                }
                GossipServerJob::Cluster(job) => {
                    Self::handle_cluster_management_job(job, network_channel.clone(), &global_state)
                }
            };

            if let Err(err) = res {
                println!(
                    "Error in gossip server execution loop: {:?}",
                    err.to_string()
                );
            }
        }
    }
}
