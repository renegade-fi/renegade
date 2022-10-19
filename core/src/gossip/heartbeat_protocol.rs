// Groups the logic behind the gossip protocol specification
use crossbeam::channel::{Receiver, Sender};
use libp2p::request_response::ResponseChannel;
use lru::LruCache;
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::mpsc::UnboundedSender;

use crate::{
    gossip::{
        api::{GossipOutbound, GossipRequest, GossipResponse, HeartbeatMessage},
        types::{PeerInfo, WrappedPeerId},
    },
    state::{GlobalRelayerState, RelayerState},
};

/**
 * Constants
 */

// Nanoseconds in a millisecond, as an unsigned 64bit integer
const NANOS_PER_MILLI: u64 = 1_000_000;

// The interval at which to send heartbeats to known peers
const HEARTBEAT_INTERVAL_MS: u64 = 3000; // 3 seconds

// The amount of time without a successful heartbeat before the local
// relayer should assume its peer has failed
const HEARTBEAT_FAILURE_MS: u64 = 10000; // 10 seconds

// The minimum amount of time between a peer's expiry and when it can be
// added back to the peer info
const EXPIRY_INVISIBILITY_WINDOW_MS: u64 = 10_000; // 10 seconds
const EXPIRY_CACHE_SIZE: usize = 100;

/**
 * Helpers
 */

// Returns the current unix timestamp in seconds, represented as u64
fn get_current_time_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("negative timestamp")
        .as_secs()
}

/**
 * Heartbeat protocol execution and implementation
 */

// Job types
pub enum HeartbeatExecutorJob {
    ExecuteHeartbeats,
    HandleHeartbeatReq {
        peer_id: WrappedPeerId,
        message: HeartbeatMessage,
        channel: ResponseChannel<GossipResponse>,
    },
    HandleHeartbeatResp {
        peer_id: WrappedPeerId,
        message: HeartbeatMessage,
    },
}

// Type aliases for shared objects
type SharedLRUCache = Arc<RwLock<LruCache<WrappedPeerId, u64>>>;

// Executes the heartbeat protocols
pub struct HeartbeatProtocolExecutor {
    // The handle of the worker thread executing heartbeat jobs
    thread_handle: thread::JoinHandle<()>,
    // The timer that enqueues heartbeat jobs periodically for the worker
    heartbeat_timer: HeartbeatTimer,
}

impl HeartbeatProtocolExecutor {
    // Creates a new executor
    pub fn new(
        local_peer_id: WrappedPeerId,
        network_channel: UnboundedSender<GossipOutbound>,
        job_sender: Sender<HeartbeatExecutorJob>,
        job_receiver: Receiver<HeartbeatExecutorJob>,
        global_state: GlobalRelayerState,
    ) -> Self {
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
                    );
                })
                .unwrap()
        };

        let heartbeat_timer = HeartbeatTimer::new(job_sender, HEARTBEAT_INTERVAL_MS);

        Self {
            thread_handle,
            heartbeat_timer,
        }
    }

    // Joins execution of the calling thread to the worker thread
    pub fn join(self) -> thread::Result<()> {
        self.heartbeat_timer.join()?;
        self.thread_handle.join()
    }

    // Runs the executor loop
    fn executor_loop(
        local_peer_id: WrappedPeerId,
        job_receiver: Receiver<HeartbeatExecutorJob>,
        network_channel: UnboundedSender<GossipOutbound>,
        peer_expiry_cache: SharedLRUCache,
        global_state: GlobalRelayerState,
    ) {
        println!("Starting executor loop for heartbeat protocol executor...");
        loop {
            let job = job_receiver.recv().expect("recv should not panic");
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
                    let heartbeat_resp = GossipResponse::Heartbeat(Self::build_heartbeat_message(
                        global_state.clone(),
                    ));
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

    // Records a successful heartbeat
    fn record_heartbeat(peer_id: WrappedPeerId, global_state: GlobalRelayerState) {
        let mut locked_state = global_state.write().unwrap();
        if let Some(peer_info) = locked_state.known_peers.get_mut(&peer_id) {
            peer_info.successful_heartbeat();
        }
    }

    // Sync the replication state when a heartbeat is received
    // Effectively:
    //  For each wallet that the local relayer manages:
    //      1. Check if the peer sent a replication list for this wallet
    //      2. Add any new peers from that list to the local state
    fn merge_peers_from_message(
        local_peer_id: WrappedPeerId,
        message: &HeartbeatMessage,
        network_channel: UnboundedSender<GossipOutbound>,
        peer_expiry_cache: SharedLRUCache,
        global_state: GlobalRelayerState,
    ) {
        let mut locked_state = global_state.write().unwrap();
        let mut locked_expiry_cache = peer_expiry_cache.write().unwrap();

        // Loop over locally replicated wallets, check for new peers in each wallet
        for (wallet_id, _) in locked_state.managed_wallets.clone().iter() {
            match message.managed_wallets.get(wallet_id) {
                // Peer does not replicate this wallet
                None => {
                    println!("Skipping, peer doesn't contain wallet");
                    continue;
                }

                // Peer replicates this wallet, add any unknown replicas to local state
                Some(wallet_metadata) => {
                    Self::merge_replicas_for_wallet(
                        *wallet_id,
                        local_peer_id,
                        &wallet_metadata.replicas,
                        &message.known_peers,
                        network_channel.clone(),
                        &mut locked_expiry_cache,
                        &mut locked_state,
                    );
                }
            }
        }
    }

    // Merges the replicating peers for a given wallet
    // The typing of the arguments implies that the values passed in are already
    // locked by the caller
    fn merge_replicas_for_wallet(
        wallet_id: uuid::Uuid,
        local_peer_id: WrappedPeerId,
        replicas_from_peer: &Vec<WrappedPeerId>,
        replica_info_from_peer: &HashMap<String, PeerInfo>,
        network_channel: UnboundedSender<GossipOutbound>,
        peer_expiry_cache: &mut LruCache<WrappedPeerId, u64>,
        global_state: &mut RelayerState,
    ) {
        let now = get_current_time_seconds();

        // Loop over replicas that the peer knows about for this wallet
        for replica in replicas_from_peer {
            // Skip local peer and peers already known
            if *replica == local_peer_id || global_state.known_peers.contains_key(replica) {
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
            if let Some(replica_info) = replica_info_from_peer.get(&replica.to_string()) {
                // Copy the peer info and record a dummy heartbeat to prevent immediate expiration
                let mut peer_info_copy = replica_info.clone();
                peer_info_copy.successful_heartbeat();

                global_state.known_peers.insert(*replica, peer_info_copy);

                // Register the newly discovered peer with the network manager
                // so that we can dial it on outbound heartbeats
                network_channel
                    .send(GossipOutbound::NewAddr {
                        peer_id: *replica,
                        address: replica_info.get_addr(),
                    })
                    .unwrap();
            } else {
                // Ignore this peer if peer_info was not sent for it,
                // this is effectively useless to the local relayer without peer_info
                continue;
            }

            // Add new peer as a replica of the wallet in the wallet's metadata
            global_state
                .managed_wallets
                .get_mut(&wallet_id)
                .expect("")
                .metadata
                .replicas
                .push(*replica);
        }
    }

    // Sends heartbeat message to peers to exchange network information and ensure liveness
    fn send_heartbeats(
        local_peer_id: WrappedPeerId,
        network_channel: UnboundedSender<GossipOutbound>,
        peer_expiry_cache: SharedLRUCache,
        global_state: GlobalRelayerState,
    ) {
        // Send heartbeat requests
        let heartbeat_message =
            GossipRequest::Heartbeat(Self::build_heartbeat_message(global_state.clone()));

        {
            let locked_state = global_state.read().unwrap();
            println!(
                "\n\nSending heartbeats, I know {} peers...",
                locked_state.known_peers.len() - 1
            );
            for (peer_id, _) in locked_state.known_peers.iter() {
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
        } // locked_peer_info releases its read lock here

        Self::expire_peers(local_peer_id, peer_expiry_cache, global_state);
    }

    // Expires peers that have timed out due to consecutive failed heartbeats
    fn expire_peers(
        local_peer_id: WrappedPeerId,
        peer_expiry_cache: SharedLRUCache,
        global_state: GlobalRelayerState,
    ) {
        let now = get_current_time_seconds();
        let mut peers_to_expire = Vec::new();
        {
            let locked_state = global_state.read().unwrap();
            for (peer_id, peer_info) in locked_state.known_peers.iter() {
                if *peer_id == local_peer_id {
                    continue;
                }

                if now - peer_info.get_last_heartbeat() >= HEARTBEAT_FAILURE_MS / 1000 {
                    peers_to_expire.push(*peer_id);
                }
            }
        } // locked_peer_info releases read lock

        // Short cct to avoid acquiring locks if not necessary
        if peers_to_expire.is_empty() {
            return;
        }

        let mut locked_state = global_state.write().unwrap();
        let mut locked_expiry_cache = peer_expiry_cache.write().unwrap();

        // Acquire a write lock and update peer info
        for peer in peers_to_expire.iter() {
            locked_state.known_peers.remove(peer);
            locked_expiry_cache.put(*peer, now);
        }
    }

    // Constructs a heartbeat message from local state
    fn build_heartbeat_message(global_state: GlobalRelayerState) -> HeartbeatMessage {
        // Deref to remove lock guard then reference to borrow
        let locked_state = global_state.read().unwrap();
        HeartbeatMessage::from(&*locked_state)
    }
}

/**
 * HeartbeatTimer handles the process of enqueuing jobs to perform
 * a heartbeat on regular intervals
 */
struct HeartbeatTimer {
    thread_handle: thread::JoinHandle<()>,
}

impl HeartbeatTimer {
    // Constructor
    pub fn new(job_queue: Sender<HeartbeatExecutorJob>, interval_ms: u64) -> Self {
        // Narrowing cast is okay, precision is not important here
        let duration_seconds = interval_ms / 1000;
        let duration_nanos = (interval_ms % 1000 * NANOS_PER_MILLI) as u32;
        let wait_period = Duration::new(duration_seconds, duration_nanos);

        // Begin the timing loop
        let thread_handle = thread::Builder::new()
            .name("heartbeat-timer".to_string())
            .spawn(move || {
                Self::execution_loop(job_queue, wait_period);
            })
            .unwrap();

        Self { thread_handle }
    }

    // Joins the calling thread's execution to the execution of the HeartbeatTimer
    pub fn join(self) -> thread::Result<()> {
        self.thread_handle.join()
    }

    // Main timing loop
    fn execution_loop(job_queue: Sender<HeartbeatExecutorJob>, wait_period: Duration) {
        loop {
            job_queue
                .send(HeartbeatExecutorJob::ExecuteHeartbeats)
                .unwrap();
            thread::sleep(wait_period);
        }
    }
}
