//! Groups the logic behind the gossip protocol specification
use crossbeam::channel::{Receiver, Sender};
use lru::LruCache;
use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    sync::{Arc, RwLock},
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::mpsc::UnboundedSender;
use uuid::Uuid;

use crate::{
    api::{
        gossip::{GossipOutbound, GossipRequest, GossipResponse},
        hearbeat::HeartbeatMessage,
    },
    gossip::types::{PeerInfo, WrappedPeerId},
    state::{ClusterMetadata, RelayerState, WalletMetadata},
    CancelChannel,
};

use super::{
    errors::GossipError,
    jobs::{ClusterManagementJob, GossipServerJob},
};

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
                .map_err(|err| GossipError::ServerSetupError(err.to_string()))
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
                GossipServerJob::Cluster(job) => {
                    if let Err(err) = Self::handle_cluster_management_job(job, &global_state) {
                        return err;
                    }
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
                    Self::merge_peers_from_message(
                        local_peer_id,
                        &message,
                        network_channel.clone(),
                        peer_expiry_cache.clone(),
                        global_state.clone(),
                    )
                }
                GossipServerJob::HandleHeartbeatResp { peer_id, message } => {
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
    /// TODO: There is probably a cleaner way to do this
    fn merge_peers_from_message(
        local_peer_id: WrappedPeerId,
        message: &HeartbeatMessage,
        network_channel: UnboundedSender<GossipOutbound>,
        peer_expiry_cache: SharedLRUCache,
        global_state: RelayerState,
    ) {
        // Merge wallet information and peer info
        Self::merge_wallets(
            local_peer_id,
            &message.managed_wallets,
            &message.known_peers,
            network_channel.clone(),
            peer_expiry_cache.clone(),
            &global_state,
        );

        // Merge cluster information into the local cluster
        Self::merge_cluster_metadata(
            &message.cluster_metadata,
            &message.known_peers,
            network_channel,
            peer_expiry_cache,
            &global_state,
        )
    }

    /// Merges the wallet information from an incoming heartbeat with the locally
    /// stored wallet information
    ///
    /// In specific, the local peer must update its replicas list for any wallet it manages
    fn merge_wallets(
        local_peer_id: WrappedPeerId,
        peer_wallets: &HashMap<Uuid, WalletMetadata>,
        incoming_peer_info: &HashMap<String, PeerInfo>,
        network_channel: UnboundedSender<GossipOutbound>,
        peer_expiry_cache: SharedLRUCache,
        global_state: &RelayerState,
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
                match peer_wallets.get(wallet_id) {
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

        // Update all wallets that were determined to be missing known peer replicas
        let mut locked_wallets = global_state.write_managed_wallets();
        let mut locked_peers = global_state.write_known_peers();
        let mut locked_expiry_cache = peer_expiry_cache.write().unwrap();

        for wallet in wallets_to_merge {
            let local_replicas = &mut locked_wallets
                .get_mut(&wallet)
                .expect("missing wallet ID")
                .metadata
                .replicas;
            let message_replicas = &peer_wallets
                .get(&wallet)
                .expect("missing wallet ID")
                .replicas;

            Self::merge_replicas_for_wallet(
                local_peer_id,
                local_replicas,
                message_replicas,
                &mut locked_peers,
                incoming_peer_info,
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
        // Loop over replicas that the peer knows about for this wallet
        for replica in new_replicas.iter() {
            // Skip local peer and peers already known
            if *replica == local_peer_id || known_replicas.contains(replica) {
                continue;
            }

            // Add new peer to globally maintained peer info map
            if let Some(replica_info) = new_replica_peer_info.get(&replica.to_string()) {
                // Copy the peer info and record a dummy heartbeat to prevent immediate expiration
                let mut peer_info_copy = replica_info.clone();
                peer_info_copy.successful_heartbeat();

                Self::add_new_peer(
                    *replica,
                    peer_info_copy,
                    known_peer_info,
                    peer_expiry_cache,
                    network_channel.clone(),
                );

                // Add new peer as a replica of the wallet in the wallet's metadata
                known_replicas.insert(*replica);
            }
        }
    }

    /// Merges cluster information from an incoming heartbeat request with the locally
    /// stored wallet information
    fn merge_cluster_metadata(
        incoming_cluster_info: &ClusterMetadata,
        incoming_peer_info: &HashMap<String, PeerInfo>,
        network_channel: UnboundedSender<GossipOutbound>,
        peer_expiry_cache: SharedLRUCache,
        global_state: &RelayerState,
    ) {
        // As in the `merge_wallets` implementation, we avoid acquiring a write lock on any state elements
        // if possible to avoid contention in the common (no updates) case
        {
            let locked_cluster_metadata = global_state.read_cluster_metadata();
            // Short cct if the metadata is for a different cluster or if all peers are already accounted for
            if locked_cluster_metadata.id != incoming_cluster_info.id
                || locked_cluster_metadata
                    .known_members
                    .is_superset(&incoming_cluster_info.known_members)
            {
                return;
            }
        } // locked_cluster_metadata released here

        // Add missing members to cluster metadata
        let mut locked_peer_info = global_state.write_known_peers();
        let mut locked_cluster_metadata = global_state.write_cluster_metadata();
        let mut locked_expiry_cache = peer_expiry_cache.write().unwrap();

        for cluster_peer in incoming_cluster_info.known_members.iter() {
            // Ignore known peers
            if locked_cluster_metadata.has_member(cluster_peer) {
                continue;
            }

            // Ignore new peers when the request does not include peer metadata
            if let Some(new_peer_info) = incoming_peer_info.get(&cluster_peer.to_string()) {
                // Do not add the peer to cluster metadata if indexing the peer fails; this happens
                // if the peer is recently expired and its invisibility window has not elapsed
                if Self::add_new_peer(
                    *cluster_peer,
                    new_peer_info.clone(),
                    &mut locked_peer_info,
                    &mut locked_expiry_cache,
                    network_channel.clone(),
                ) {
                    locked_cluster_metadata.add_member(*cluster_peer);
                }
            }
        }
    }

    /// Index a new peer if:
    ///     1. The peer is not already in the known peers
    ///     2. The peer has not been recently expired by the local party
    /// The second condition is necessary because if we expire a peer, the party
    /// sending a heartbeat may not have expired the faulty peer yet, and may still
    /// send the faulty peer as a known peer. So we exclude thought-to-be-faulty
    /// peers for an "invisibility window"
    ///
    /// Returns a boolean indicating whether the peer is now indexed in the peer info
    /// state. This value may be false if the peer has been recently expired and its
    /// invisibility window has not elapsed
    fn add_new_peer(
        new_peer_id: WrappedPeerId,
        new_peer_info: PeerInfo,
        known_peer_info: &mut HashMap<WrappedPeerId, PeerInfo>,
        peer_expiry_cache: &mut LruCache<WrappedPeerId, u64>,
        network_channel: UnboundedSender<GossipOutbound>,
    ) -> bool {
        let now = get_current_time_seconds();
        if let Some(expired_at) = peer_expiry_cache.get(&new_peer_id) {
            if now - *expired_at <= EXPIRY_INVISIBILITY_WINDOW_MS / 1000 {
                return false;
            }

            // Remove the peer from the expiry cache if its invisibility window has elapsed
            peer_expiry_cache.pop_entry(&new_peer_id);
        }

        if let Entry::Vacant(e) = known_peer_info.entry(new_peer_id) {
            e.insert(new_peer_info.clone());

            // Register the newly discovered peer with the network manager
            // so that we can dial it on outbound heartbeats
            network_channel
                .send(GossipOutbound::NewAddr {
                    peer_id: new_peer_id,
                    address: new_peer_info.get_addr(),
                })
                .unwrap();
        };

        true
    }

    /// Sends heartbeat message to peers to exchange network information and ensure liveness
    fn send_heartbeat(
        recipient_peer_id: WrappedPeerId,
        local_peer_id: WrappedPeerId,
        network_channel: UnboundedSender<GossipOutbound>,
        peer_expiry_cache: SharedLRUCache,
        global_state: &RelayerState,
    ) {
        if recipient_peer_id == local_peer_id {
            return;
        }

        let heartbeat_message =
            GossipRequest::Heartbeat(Self::build_heartbeat_message(global_state));
        network_channel
            .send(GossipOutbound::Request {
                peer_id: recipient_peer_id,
                message: heartbeat_message,
            })
            .unwrap();

        Self::maybe_expire_peer(recipient_peer_id, peer_expiry_cache, global_state);
    }

    /// Expires peers that have timed out due to consecutive failed heartbeats
    fn maybe_expire_peer(
        peer_id: WrappedPeerId,
        peer_expiry_cache: SharedLRUCache,
        global_state: &RelayerState,
    ) {
        let now = get_current_time_seconds();
        {
            let locked_peer_index = global_state.read_known_peers();
            let peer_info = locked_peer_index.get(&peer_id).unwrap();
            if now - peer_info.get_last_heartbeat() < HEARTBEAT_FAILURE_MS / 1000 {
                return;
            }
        }

        // Remove expired peers from global state
        global_state.remove_peers(&[peer_id]);

        // Add peers to expiry cache for the duration of their invisibility window. This ensures that
        // we do not add the expired peer back to the global state until some time has elapsed. Without
        // this check, another peer may send us a heartbeat attesting to the expired peer's liveness,
        // having itself not expired the peer locally.
        let mut locked_expiry_cache = peer_expiry_cache.write().unwrap();
        locked_expiry_cache.put(peer_id, now);
    }

    /// Constructs a heartbeat message from local state
    fn build_heartbeat_message(global_state: &RelayerState) -> HeartbeatMessage {
        HeartbeatMessage::from(global_state)
    }

    /// Handles an incoming cluster management job
    fn handle_cluster_management_job(
        job: ClusterManagementJob,
        global_state: &RelayerState,
    ) -> Result<(), GossipError> {
        match job {
            ClusterManagementJob::ClusterJoinRequest(req) => {
                // The cluster join request is authenticated at the network layer
                // by the `NetworkManager`, so no authentication needs to be done.
                // Simply update the local peer info to reflect the new node's membership
                {
                    let mut locked_peers = global_state.write_known_peers();
                    let mut locked_cluster_metadata = global_state.write_cluster_metadata();

                    // Insert the new peer into the cluster metadata and peer metadata
                    locked_cluster_metadata.add_member(req.peer_id);
                    locked_peers
                        .entry(req.peer_id)
                        .or_insert_with(|| PeerInfo::new(req.peer_id, req.cluster_id, req.addr));
                }
            }
        }

        Ok(())
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
    pub fn new(
        job_queue: Sender<GossipServerJob>,
        interval_ms: u64,
        global_state: RelayerState,
    ) -> Self {
        // Narrowing cast is okay, precision is not important here
        let duration_seconds = interval_ms / 1000;
        let duration_nanos = (interval_ms % 1000 * NANOS_PER_MILLI) as u32;
        let wait_period = Duration::new(duration_seconds, duration_nanos);

        // Begin the timing loop
        let thread_handle = thread::Builder::new()
            .name("heartbeat-timer".to_string())
            .spawn(move || Self::execution_loop(job_queue, wait_period, global_state))
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
        job_queue: Sender<GossipServerJob>,
        wait_period: Duration,
        global_state: RelayerState,
    ) -> GossipError {
        loop {
            {
                // Log the state if in debug mode
                global_state.print_screen();

                // Enqueue a heartbeat job for each known peer
                for peer_id in global_state.read_known_peers().keys() {
                    // Do not heartbeat with self
                    if peer_id.eq(&global_state.read_peer_id()) {
                        continue;
                    }

                    if let Err(err) = job_queue.send(GossipServerJob::ExecuteHeartbeat(*peer_id)) {
                        return GossipError::TimerFailed(err.to_string());
                    }
                }
            }
            thread::sleep(wait_period);
        }
    }
}
