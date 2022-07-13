
// Groups the logic behind the gossip protocol specification
use crate::{
    gossip::{api::HeartbeatMessage},
};
use crossbeam::{channel::{
    Sender,
    Receiver, 
}};
use libp2p::{
    request_response::ResponseChannel,
    PeerId, 
};
use lru::{
    LruCache
};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH}, 
    thread
};
use tokio::sync::mpsc::{
    error::SendError,
    UnboundedSender,
};

use crate::gossip::{
    api::{GossipMessage, GossipOutbound},
    types::PeerInfo
};


/**
 * Constants
 */

// Nanoseconds in a millisecond, as an unsigned 64bit integer
const NANOS_PER_MILLI: u64 = 1_000_000;

// The interval at which to send heartbeats to known peers
const HEARTBEAT_INTERVAL_MS: u64 = 3000;  // 3 seconds

// The amount of time without a successful heartbeat before the local 
// relayer should assume its peer has failed
const HEARTBEAT_FAILURE_MS: u64 = 10000;  // 10 seconds

// The minimum amount of time between a peer's expiry and when it can be
// added back to the peer info
const EXPIRY_INVISIBILITY_WINDOW_MS: u64 = 10_000;  // 10 seconds
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
    HandleHeartbeatReq{ 
        peer_id: PeerId, 
        message: HeartbeatMessage, 
        channel: ResponseChannel<GossipMessage> 
    },
    HandleHeartbeatResp{ peer_id: PeerId, message: HeartbeatMessage },
}

// Type aliases for shared objects
type SharedPeerInfo = Arc<RwLock<HashMap<PeerId, PeerInfo>>>;
type SharedLRUCache = Arc<RwLock<LruCache<PeerId, u64>>>;

// Executes the heartbeat protocols
pub struct HeartbeatProtocolExecutor {
    // The handle of the worker thread executing heartbeat jobs
    thread_handle: thread::JoinHandle<()>,
    // The timer that enqueues heartbeat jobs periodically for the worker
    heartbeat_timer: HeartbeatTimer
}

impl HeartbeatProtocolExecutor {
    // Creates a new executor
    pub fn new(
        local_peer_id: PeerId,
        peer_info: SharedPeerInfo,
        network_channel: UnboundedSender<GossipOutbound>,
        job_sender: Sender<HeartbeatExecutorJob>,
        job_receiver: Receiver<HeartbeatExecutorJob>
    ) -> Self { 
        // Tracks recently expired peers and blocks them from being re-registered
        // until the state has synced. Maps peer_id to expiry time
        let peer_expiry_cache: SharedLRUCache = Arc::new(
            RwLock::new(
                LruCache::new(EXPIRY_CACHE_SIZE)
            )
        );

        let thread_handle = {
            thread::Builder::new()
                .name("heartbeat-executor".to_string())
                .spawn(move || { 
                    Self::executor_loop(
                        local_peer_id,
                        peer_info,
                        job_receiver,
                        network_channel,
                        peer_expiry_cache,
                    );
                })
                .unwrap()
        };

        let heartbeat_timer = HeartbeatTimer::new(job_sender, HEARTBEAT_INTERVAL_MS);

        Self { thread_handle, heartbeat_timer }
    }

    // Joins execution of the calling thread to the worker thread
    pub fn join(self) -> thread::Result<()> {
        self.heartbeat_timer.join();
        self.thread_handle.join()
    }

    // Runs the executor loop 
    fn executor_loop(
        local_peer_id: PeerId,
        peer_info: SharedPeerInfo,
        job_receiver: Receiver<HeartbeatExecutorJob>,
        network_channel: UnboundedSender<GossipOutbound>,
        peer_expiry_cache: SharedLRUCache
    ) {
        println!("Starting executor loop for heartbeat protocol executor...");
        loop {
            let job = job_receiver.recv().expect("recv should not panic");
            match job {
                HeartbeatExecutorJob::ExecuteHeartbeats => {
                    Self::send_heartbeats(
                        local_peer_id, 
                        peer_info.clone(), 
                        network_channel.clone(),
                        peer_expiry_cache.clone()
                    );
                },
                HeartbeatExecutorJob::HandleHeartbeatReq { message, channel, .. } => {
                    if let Ok(peers) = message.get_known_peers() {
                        Self::merge_peers(
                            local_peer_id, 
                            peers, 
                            peer_info.clone(), 
                            network_channel.clone(),
                            peer_expiry_cache.clone()
                        );
                    } else {
                        println!("Could not parse peers from heartbeat request...");
                    }

                    // Respond on the channel given in the request
                    let message = Self::build_heartbeat_message(peer_info.clone());
                    network_channel.send(
                        GossipOutbound::Response { channel, message }
                    );
                },
                HeartbeatExecutorJob::HandleHeartbeatResp { peer_id, message } => {
                    Self::record_heartbeat(peer_id, peer_info.clone());
                    if let Ok(peers) = message.get_known_peers() {
                        Self::merge_peers(
                            local_peer_id, 
                            peers, 
                            peer_info.clone(), 
                            network_channel.clone(),
                            peer_expiry_cache.clone()
                        )
                    } else {
                        println!("Could not parse peers from heartbeat response...")
                    }
                }
            }
        }
    }

    // Records a successful heartbeat
    fn record_heartbeat(peer_id: PeerId, peer_info: SharedPeerInfo) {
        let mut locked_peer_info = peer_info.write().unwrap();
        if let Some(peer) = locked_peer_info.get_mut(&peer_id) {
            peer.successful_heartbeat();
        }
    }

    // Merges the peers from a heartbeat into the set of already known peers
    fn merge_peers(
        local_peer_id: PeerId,
        new_peers: Vec<PeerInfo>, 
        peer_info: SharedPeerInfo,
        network_channel: UnboundedSender<GossipOutbound>,
        peer_expiry_cache: SharedLRUCache
    ) {
        let now = get_current_time_seconds();
        let mut locked_peer_info = peer_info.write().unwrap();
        let mut locked_expiry_cache = peer_expiry_cache.write().unwrap();
        for peer in new_peers.iter() {
            if peer.get_peer_id() == local_peer_id || locked_peer_info.contains_key(&peer.get_peer_id()) {
                continue;
            } 
            
            // Do not add new peers that have been recently expired. It is possibly they have
            // not expired on the other peer, in which case we may receive heartbeats containing
            // peers that have already expired
            if let Some(expired_at) = locked_expiry_cache.get(&peer.get_peer_id()) {
                if now - *expired_at <= EXPIRY_INVISIBILITY_WINDOW_MS * 1000 {
                    continue;
                }
            }

            locked_peer_info.insert(peer.get_peer_id(), peer.clone());
            network_channel.send(
                GossipOutbound::NewAddr { 
                    peer_id: peer.get_peer_id(), 
                    address:  peer.get_addr()
                }
            );
        }
    }

    // Sends heartbeat message to peers to exchange network information and ensure liveness
    fn send_heartbeats(
        local_peer_id: PeerId,
        peer_info: SharedPeerInfo,
        network_channel: UnboundedSender<GossipOutbound>,
        peer_expiry_cache: SharedLRUCache
    ) -> Result<(), SendError<GossipOutbound>> {
        // Send heartbeat requests
        let heartbeat_message = Self::build_heartbeat_message(peer_info.clone());
        {
            let locked_peer_info = peer_info.read().unwrap();
            println!("\n\nSending heartbeats, I know {} peers...", locked_peer_info.len() - 1);
            for (peer_id, _) in locked_peer_info.iter() {
                if *peer_id == local_peer_id {
                    continue;
                }

                network_channel.send(
                    GossipOutbound::Request { peer_id: *peer_id, message: heartbeat_message.clone() }
                );
            }
        } // locked_peer_info releases its read lock here

        Self::expire_peers(local_peer_id, peer_info, peer_expiry_cache);
        Ok(())
    }

    // Expires peers that have timed out due to consecutive failed heartbeats
    fn expire_peers(
        local_peer_id: PeerId,
        peer_info: SharedPeerInfo,
        peer_expiry_cache: SharedLRUCache
    ) {
        println!("Evaluating peers to expire...");
        let now = get_current_time_seconds();
        let mut peers_to_expire = Vec::new();
        {
            let locked_peer_info = peer_info.read().unwrap();
            for (peer_id, peer_info) in locked_peer_info.iter() {
                if *peer_id == local_peer_id {
                    continue;
                }

                if now - peer_info.get_last_heartbeat() >= HEARTBEAT_FAILURE_MS / 1000 {
                    println!("Expiring peer: {}", peer_id);
                    peers_to_expire.push(*peer_id);
                }
            }
        } // locked_peer_info releases read lock 

        // Short cct to avoid acquiring locks
        if peers_to_expire.is_empty() {
            return
        }

        let mut locked_peer_info = peer_info.write().unwrap();
        let mut locked_expiry_cache = peer_expiry_cache.write().unwrap();

        // Acquire a write lock and update peer info
        for peer in peers_to_expire.iter() {
            locked_peer_info.remove(peer);
            locked_expiry_cache.put(*peer, now);
        }
    }

    // Constructs a heartbeat message from local state
    fn build_heartbeat_message(peer_info: SharedPeerInfo) -> GossipMessage {
        let locked_peer_info = peer_info.read().unwrap();
        let mut known_peers: Vec<PeerInfo> = Vec::new();
        for (_, peer_info) in locked_peer_info.iter() {
            known_peers.push(peer_info.clone());
        }

        GossipMessage::Heartbeat(HeartbeatMessage::new(known_peers))
    }

}


/**
 * HeartbeatTimer handles the process of enqueuing jobs to perform
 * a heartbeat on regular intervals
 */
struct HeartbeatTimer {
    thread_handle: thread::JoinHandle<()>
}

impl HeartbeatTimer {
    // Constructor
    pub fn new(
        job_queue: Sender<HeartbeatExecutorJob>,
        interval_ms: u64 
    ) -> Self { 
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
    fn execution_loop(
        job_queue: Sender<HeartbeatExecutorJob>,
        wait_period: Duration,
    ) {
        loop {
            job_queue.send(HeartbeatExecutorJob::ExecuteHeartbeats);
            thread::sleep(wait_period);
        }
    }
}