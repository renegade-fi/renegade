//! Groups the logic behind the gossip protocol specification
use crossbeam::channel::{Receiver, Sender};
use lru::LruCache;
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::mpsc::UnboundedSender;

use crate::{
    api::{
        gossip::{GossipOutbound, GossipRequest, GossipResponse},
        hearbeat::HeartbeatMessage,
    },
    gossip::types::{PeerInfo, WrappedPeerId},
    state::RelayerState,
    CancelChannel,
};

use super::{errors::GossipError, jobs::HeartbeatExecutorJob};

/**
 * Constants
 */

/// Nanoseconds in a millisecond, as an unsigned 64bit integer
const NANOS_PER_MILLI: u64 = 1_000_000;
/// The interval at which to send heartbeats to known peers
const HEARTBEAT_INTERVAL_MS: u64 = 3000; // 3 seconds
/// The amount of time without a successful heartbeat before the local
/// relayer should assume its peer has failed
const HEARTBEAT_FAILURE_MS: u64 = 10000; // 10 seconds
/// The minimum amount of time between a peer's expiry and when it can be
/// added back to the peer info
const EXPIRY_INVISIBILITY_WINDOW_MS: u64 = 10_000; // 10 seconds
/// The size of the peer expiry cache to keep around
const EXPIRY_CACHE_SIZE: usize = 100;

/**
 * Helpers
 */

/// Returns the current unix timestamp in seconds, represented as u64
fn get_current_time_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("negative timestamp")
        .as_secs()
}

/**
 * Heartbeat protocol execution and implementation
 */

/// Type aliases for shared objects
type SharedLRUCache = Arc<RwLock<LruCache<WrappedPeerId, u64>>>;

/// Executes the heartbeat protocols
#[derive(Debug)]
pub struct HeartbeatProtocolExecutor {
    /// The handle of the worker thread executing heartbeat jobs
    thread_handle: Option<JoinHandle<GossipError>>,
    /// The timer that enqueues heartbeat jobs periodically for the worker
    heartbeat_timer: HeartbeatTimer,
}

impl HeartbeatProtocolExecutor {
    /// Creates a new executor
    pub fn new(
        local_peer_id: WrappedPeerId,
        network_channel: UnboundedSender<GossipOutbound>,
        job_sender: Sender<HeartbeatExecutorJob>,
        job_receiver: Receiver<HeartbeatExecutorJob>,
        global_state: RelayerState,
        cancel_channel: Receiver<()>,
    ) -> Result<Self, GossipError> {
        // Tracks recently expired peers and blocks them from being re-registered
        // until the state has synced. Maps peer_id to expiry time
        let peer_expiry_cache: SharedLRUCache =
            Arc::new(RwLock::new(LruCache::new(EXPIRY_CACHE_SIZE)));

        let thread_handle = {
            thread::Builder::new()
                .name("heartbeat-executor".to_string())
                .spawn(move || {
                    Self::executor_loop(
                        local_peer_id,
                        job_receiver,
                        network_channel,
                        peer_expiry_cache,
                        global_state,
                        cancel_channel,
                    )
                })
                .map_err(|err| GossipError::ServerSetupError(err.to_string()))
        }?;

        let heartbeat_timer = HeartbeatTimer::new(job_sender, HEARTBEAT_INTERVAL_MS);

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
        job_receiver: Receiver<HeartbeatExecutorJob>,
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
                HeartbeatExecutorJob::ExecuteHeartbeats => {
                    Self::send_heartbeats(
                        local_peer_id,
                        network_channel.clone(),
                        peer_expiry_cache.clone(),
                        global_state.clone(),
                    );
                }
                HeartbeatExecutorJob::HandleHeartbeatReq {
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
                    Self::merge_peers_from_message(
                        local_peer_id,
                        &message,
                        network_channel.clone(),
                        peer_expiry_cache.clone(),
                        global_state.clone(),
                    )
                }
                HeartbeatExecutorJob::HandleHeartbeatResp { peer_id, message } => {
                    Self::record_heartbeat(peer_id, global_state.clone());
                    Self::merge_peers_from_message(
                        local_peer_id,
                        &message,
                        network_channel.clone(),
                        peer_expiry_cache.clone(),
                        global_state.clone(),
                    )
                }
            }
        }
    }

    /// Records a successful heartbeat
    fn record_heartbeat(peer_id: WrappedPeerId, global_state: RelayerState) {
        if let Some(peer_info) = global_state.write_known_peers().get_mut(&peer_id) {
            peer_info.successful_heartbeat();
        }
    }

    /// Sync the replication state when a heartbeat is received
    /// Effectively:
    ///  For each wallet that the local relayer manages:
    ///      1. Check if the peer sent a replication list for this wallet
    ///      2. Add any new peers from that list to the local state
    fn merge_peers_from_message(
        local_peer_id: WrappedPeerId,
        message: &HeartbeatMessage,
        network_channel: UnboundedSender<GossipOutbound>,
        peer_expiry_cache: SharedLRUCache,
        global_state: RelayerState,
    ) {
        // Loop over locally replicated wallets, check for new peers in each wallet
        // We break this down into two phases, in the first phase, the local peer determines which
        // wallets it must merge in order to receive updated replicas.
        // In the second phase, the node escalates its read locks to write locks so that it can make
        // the appropriate merges.
        //
        // We do this because in the steady state we update the replicas list infrequently, but the
        // heartbeat operation happens quite frequently. Therefore, most requests do not *need* to
        // acquire a write lock.
        let mut wallets_to_merge = Vec::new();
        {
            let locked_wallets = global_state.read_managed_wallets();
            for (wallet_id, wallet_info) in locked_wallets.iter() {
                match message.managed_wallets.get(wallet_id) {
                    // Peer does not replicate this wallet
                    None => {
                        continue;
                    }

                    Some(incoming_metadata) => {
                        // If the replicas of this wallet stored locally are not a superset of
                        // those in this message, mark the wallet for merge in step 2
                        if !wallet_info
                            .metadata
                            .replicas
                            .is_superset(&incoming_metadata.replicas)
                        {
                            wallets_to_merge.push(*wallet_id);
                        }
                    }
                }
            }
        } // locked_wallets released

        // Avoid acquiring unecessary write locks if possible
        if wallets_to_merge.is_empty() {
            return;
        }

        // Update all wallets that were determined to be out of date
        let mut locked_wallets = global_state.write_managed_wallets();
        let mut locked_peers = global_state.write_known_peers();
        let mut locked_expiry_cache = peer_expiry_cache.write().unwrap();

        for wallet in wallets_to_merge {
            let local_replicas = &mut locked_wallets
                .get_mut(&wallet)
                .expect("missing wallet ID")
                .metadata
                .replicas;
            let message_replicas = &message
                .managed_wallets
                .get(&wallet)
                .expect("missing wallet ID")
                .replicas;

            Self::merge_replicas_for_wallet(
                local_peer_id,
                local_replicas,
                message_replicas,
                &mut locked_peers,
                &message.known_peers,
                network_channel.clone(),
                &mut locked_expiry_cache,
            )
        }
    }

    /// Merges the replicating peers for a given wallet
    /// The typing of the arguments implies that the values passed in are already
    /// locked by the caller
    fn merge_replicas_for_wallet(
        local_peer_id: WrappedPeerId,
        known_replicas: &mut HashSet<WrappedPeerId>,
        new_replicas: &HashSet<WrappedPeerId>,
        known_peer_info: &mut HashMap<WrappedPeerId, PeerInfo>,
        new_replica_peer_info: &HashMap<String, PeerInfo>,
        network_channel: UnboundedSender<GossipOutbound>,
        peer_expiry_cache: &mut LruCache<WrappedPeerId, u64>,
    ) {
        let now = get_current_time_seconds();

        // Loop over replicas that the peer knows about for this wallet
        for replica in new_replicas.iter() {
            // Skip local peer and peers already known
            if *replica == local_peer_id || known_replicas.contains(replica) {
                continue;
            }

            // Do not add new peers that have been recently expired. It is possibly they have
            // not expired on the other peer, in which case we may receive heartbeats containing
            // peers that have already expired
            if let Some(expired_at) = peer_expiry_cache.get(replica) {
                if now - *expired_at <= EXPIRY_INVISIBILITY_WINDOW_MS / 1000 {
                    continue;
                }
            }

            // Add new peer to globally maintained peer info map
            if let Some(replica_info) = new_replica_peer_info.get(&replica.to_string()) {
                // Copy the peer info and record a dummy heartbeat to prevent immediate expiration
                let mut peer_info_copy = replica_info.clone();
                peer_info_copy.successful_heartbeat();

                if !known_peer_info.contains_key(replica) {
                    known_peer_info.insert(*replica, peer_info_copy);

                    // Register the newly discovered peer with the network manager
                    // so that we can dial it on outbound heartbeats
                    network_channel
                        .send(GossipOutbound::NewAddr {
                            peer_id: *replica,
                            address: replica_info.get_addr(),
                        })
                        .unwrap();
                }
            } else {
                // Ignore this peer if peer_info was not sent for it,
                // this is effectively useless to the local relayer without peer_info
                continue;
            }

            // Add new peer as a replica of the wallet in the wallet's metadata
            known_replicas.insert(*replica);
        }
    }

    /// Sends heartbeat message to peers to exchange network information and ensure liveness
    fn send_heartbeats(
        local_peer_id: WrappedPeerId,
        network_channel: UnboundedSender<GossipOutbound>,
        peer_expiry_cache: SharedLRUCache,
        global_state: RelayerState,
    ) {
        // Send heartbeat requests
        let heartbeat_message =
            GossipRequest::Heartbeat(Self::build_heartbeat_message(&global_state));

        {
            let locked_peers = global_state.read_known_peers();
            println!(
                "\n\nSending heartbeats, I know {} peers...",
                locked_peers.len() - 1
            );
            for (peer_id, _) in locked_peers.iter() {
                if *peer_id == local_peer_id {
                    continue;
                }

                network_channel
                    .send(GossipOutbound::Request {
                        peer_id: *peer_id,
                        message: heartbeat_message.clone(),
                    })
                    .unwrap();
            }
        } // state locks released

        Self::expire_peers(local_peer_id, peer_expiry_cache, global_state);
    }

    /// Expires peers that have timed out due to consecutive failed heartbeats
    fn expire_peers(
        local_peer_id: WrappedPeerId,
        peer_expiry_cache: SharedLRUCache,
        global_state: RelayerState,
    ) {
        let now = get_current_time_seconds();
        let mut peers_to_expire = Vec::new();
        {
            for (peer_id, peer_info) in global_state.read_known_peers().iter() {
                if *peer_id == local_peer_id {
                    continue;
                }

                if now - peer_info.get_last_heartbeat() >= HEARTBEAT_FAILURE_MS / 1000 {
                    peers_to_expire.push(*peer_id);
                }
            }
        } // state locks releaseds

        // Short cct to avoid acquiring locks if not necessary
        if peers_to_expire.is_empty() {
            return;
        }

        let mut locked_peer_info = global_state.write_known_peers();
        let mut locked_expiry_cache = peer_expiry_cache.write().unwrap();

        // Acquire a write lock and update peer info
        for peer in peers_to_expire.iter() {
            locked_peer_info.remove(peer);
            locked_expiry_cache.put(*peer, now);
        }
    }

    /// Constructs a heartbeat message from local state
    fn build_heartbeat_message(global_state: &RelayerState) -> HeartbeatMessage {
        // Deref to remove lock guard then reference to borrow
        HeartbeatMessage::from(global_state)
    }
}

/// HeartbeatTimer handles the process of enqueuing jobs to perform
/// a heartbeat on regular intervals
#[derive(Debug)]
struct HeartbeatTimer {
    /// The join handle of the thread executing the timer
    thread_handle: Option<JoinHandle<GossipError>>,
}

impl HeartbeatTimer {
    /// Constructor
    pub fn new(job_queue: Sender<HeartbeatExecutorJob>, interval_ms: u64) -> Self {
        // Narrowing cast is okay, precision is not important here
        let duration_seconds = interval_ms / 1000;
        let duration_nanos = (interval_ms % 1000 * NANOS_PER_MILLI) as u32;
        let wait_period = Duration::new(duration_seconds, duration_nanos);

        // Begin the timing loop
        let thread_handle = thread::Builder::new()
            .name("heartbeat-timer".to_string())
            .spawn(move || Self::execution_loop(job_queue, wait_period))
            .unwrap();

        Self {
            thread_handle: Some(thread_handle),
        }
    }

    /// Joins the calling thread's execution to the execution of the HeartbeatTimer
    pub fn join_handle(&mut self) -> JoinHandle<GossipError> {
        self.thread_handle.take().unwrap()
    }

    /// Main timing loop
    fn execution_loop(
        job_queue: Sender<HeartbeatExecutorJob>,
        wait_period: Duration,
    ) -> GossipError {
        loop {
            if let Err(err) = job_queue.send(HeartbeatExecutorJob::ExecuteHeartbeats) {
                return GossipError::TimerFailed(err.to_string());
            }
            thread::sleep(wait_period);
        }
    }
}
