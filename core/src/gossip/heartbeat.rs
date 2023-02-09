//! Groups gossip server logic for the heartbeat protocol

use std::{
    collections::HashMap,
    str::FromStr,
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crossbeam::channel::Sender;
use tokio::sync::mpsc::UnboundedSender;

use crate::{
    api::{
        cluster_management::ClusterAuthRequest,
        gossip::{GossipOutbound, GossipRequest},
        heartbeat::HeartbeatMessage,
    },
    state::{
        wallet::{WalletIdentifier, WalletMetadata},
        ClusterMetadata, RelayerState,
    },
};

use super::{
    errors::GossipError,
    jobs::GossipServerJob,
    server::{GossipProtocolExecutor, SharedLRUCache},
    types::{ClusterId, PeerInfo, WrappedPeerId},
};

/**
 * Constants
 */

/// Nanoseconds in a millisecond, as an unsigned 64bit integer
pub(super) const NANOS_PER_MILLI: u64 = 1_000_000;
/// The interval at which to send heartbeats to non-cluster known peers
pub(super) const HEARTBEAT_INTERVAL_MS: u64 = 10_000; // 10 seconds
/// The interval at which to send heartbeats to cluster peer
pub(super) const CLUSTER_HEARTBEAT_INTERVAL_MS: u64 = 3_000; // 3 seconds
/// The amount of time without a successful heartbeat before the local
/// relayer should assume its peer has failed; for non-cluster peers
pub(super) const HEARTBEAT_FAILURE_MS: u64 = 20_000; // 20 seconds
/// The amount of time without a successful heartbeat before the local
/// relayer should assume its peer has failed; for cluster peers
pub(super) const CLUSTER_HEARTBEAT_FAILURE_MS: u64 = 7_000; // 7 seconds
/// The minimum amount of time between a peer's expiry and when it can be
/// added back to the peer info
pub(super) const EXPIRY_INVISIBILITY_WINDOW_MS: u64 = 30_000; // 30 seconds
/// The size of the peer expiry cache to keep around
pub(super) const EXPIRY_CACHE_SIZE: usize = 100;

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

/// Heartbeat implementation of the protocol executor
impl GossipProtocolExecutor {
    /// Records a successful heartbeat
    pub(super) fn record_heartbeat(peer_id: WrappedPeerId, global_state: RelayerState) {
        if let Some(peer_info) = global_state.read_known_peers().get(&peer_id) {
            peer_info.successful_heartbeat();
        }
    }

    /// Sync the replication state when a heartbeat is received
    /// Effectively:
    ///  For each wallet that the local relayer manages:
    ///      1. Check if the peer sent a replication list for this wallet
    ///      2. Add any new peers from that list to the local state
    /// TODO: There is probably a cleaner way to do this
    pub(super) fn merge_state_from_message(
        message: HeartbeatMessage,
        network_channel: UnboundedSender<GossipOutbound>,
        peer_expiry_cache: SharedLRUCache,
        global_state: RelayerState,
    ) -> Result<(), GossipError> {
        // Peer info is deserialized as a mapping keyed with strings instead of WrappedPeerId
        // Convert the keys to WrappedPeerIds before merging the state for easy comparison
        let mut incoming_peer_info: HashMap<WrappedPeerId, PeerInfo> = HashMap::new();
        for (str_peer_id, peer_info) in message.known_peers.clone().into_iter() {
            let peer_id = WrappedPeerId::from_str(&str_peer_id)
                .map_err(|err| GossipError::Parse(err.to_string()))?;
            incoming_peer_info.insert(peer_id, peer_info);
        }

        // Merge the peer info first
        Self::merge_peer_index(
            &incoming_peer_info,
            network_channel.clone(),
            peer_expiry_cache,
            &global_state,
        )?;

        // Merge wallet information and peer info
        Self::merge_wallets(message.managed_wallets, &global_state);

        // Merge cluster information into the local cluster
        Self::merge_cluster_metadata(&message.cluster_metadata, network_channel, &global_state)
    }

    /// Merges the list of known peers from an incoming heartbeat with the local
    /// peer index
    fn merge_peer_index(
        incoming_peer_info: &HashMap<WrappedPeerId, PeerInfo>,
        network_channel: UnboundedSender<GossipOutbound>,
        peer_expiry_cache: SharedLRUCache,
        global_state: &RelayerState,
    ) -> Result<(), GossipError> {
        // Acquire only a read lock to determine if the local peer index is out of date. If so, upgrade to
        // a write lock and update the local index
        let mut peers_to_add = Vec::new();
        {
            let locked_peer_info = global_state.read_known_peers();
            for peer_id in incoming_peer_info.keys() {
                if !locked_peer_info.contains_key(peer_id) {
                    peers_to_add.push(*peer_id);
                }
            }
        } // locked_peer_info released

        // Acquire a write lock if there are new peers to merge from the message
        if peers_to_add.is_empty() {
            return Ok(());
        }

        Self::add_new_peers(
            &peers_to_add,
            incoming_peer_info,
            global_state.read_cluster_id().clone(),
            global_state,
            peer_expiry_cache,
            network_channel,
        )?;

        Ok(())
    }

    /// Merges the wallet information from an incoming heartbeat with the locally
    /// stored wallet information
    ///
    /// In specific, the local peer must update its replicas list for any wallet it manages
    fn merge_wallets(
        peer_wallets: HashMap<WalletIdentifier, WalletMetadata>,
        global_state: &RelayerState,
    ) {
        let locked_wallets = global_state.read_wallet_index();
        let locked_peers = global_state.read_known_peers();
        for (wallet_id, mut wallet_info) in peer_wallets.into_iter() {
            // Filter out any replicas that we don't have peer info for
            // This may happen for a multitude of reasons; one reason is that the local node
            // has expired a peer, but the remote node has not
            //
            // In this case, we leave the expired peer in the invisibility window, waiting for
            // the expired peer to expire on all other cluster peers
            wallet_info
                .replicas
                .retain(|replica| locked_peers.contains_key(replica));

            // Merge with the local copy of the wallet
            locked_wallets.merge_metadata(&wallet_id, &wallet_info)
        }
    }

    /// Merges cluster information from an incoming heartbeat request with the locally
    /// stored wallet information
    fn merge_cluster_metadata(
        incoming_cluster_info: &ClusterMetadata,
        network_channel: UnboundedSender<GossipOutbound>,
        global_state: &RelayerState,
    ) -> Result<(), GossipError> {
        // Skip merge if the cluster message is not from a peer in the local node's cluster
        {
            if incoming_cluster_info.id != *global_state.read_cluster_id() {
                return Ok(());
            }
        } // cluster_id lock released

        // As in the `merge_wallets` implementation, we avoid acquiring a write lock on any state elements
        // if possible to avoid contention in the common (no updates) case
        let mut peers_to_add = Vec::new();
        {
            let locked_cluster_metadata = global_state.read_cluster_metadata();
            for peer in incoming_cluster_info.known_members.iter() {
                if !locked_cluster_metadata.has_member(peer) {
                    peers_to_add.push(*peer)
                }
            }
        } // locked_cluster_metadata released here

        // Request cluster authentication for each new cluster peer
        let auth_request = GossipRequest::ClusterAuth(ClusterAuthRequest {
            cluster_id: global_state.read_cluster_id().clone(),
        });

        for peer in peers_to_add.into_iter() {
            network_channel
                .send(GossipOutbound::Request {
                    peer_id: peer,
                    message: auth_request.clone(),
                })
                .map_err(|err| GossipError::SendMessage(err.to_string()))?;
        }

        Ok(())
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
    fn add_new_peers(
        new_peer_ids: &[WrappedPeerId],
        new_peer_info: &HashMap<WrappedPeerId, PeerInfo>,
        local_cluster_id: ClusterId,
        global_state: &RelayerState,
        peer_expiry_cache: SharedLRUCache,
        network_channel: UnboundedSender<GossipOutbound>,
    ) -> Result<bool, GossipError> {
        // Filter out peers that are in their expiry window
        // or those that are missing peer info
        let now = get_current_time_seconds();
        let filtered_peers = {
            let mut locked_expiry_cache = peer_expiry_cache
                .write()
                .expect("peer_expiry_cache lock poisoned");

            new_peer_ids
                .iter()
                .filter(|peer_id| {
                    if let Some(expired_at) = locked_expiry_cache.get(*peer_id) {
                        if now - *expired_at <= EXPIRY_INVISIBILITY_WINDOW_MS / 1000 {
                            return false;
                        }

                        // Remove the peer from the expiry cache if its invisibility window has elapsed
                        locked_expiry_cache.pop_entry(*peer_id);
                    }

                    // Filter out the peer if the message including it did not attach peer info
                    new_peer_info.contains_key(*peer_id)
                })
                .cloned()
                .collect::<Vec<_>>()
        }; // locked_expiry_cache released

        // Add all filtered peers to the network manager's address table
        Self::add_new_addrs(&filtered_peers, new_peer_info, network_channel.clone())?;

        // We separate out cluster peers from non-cluster peers. Non-cluster peers may be added to the
        // state immediately. Cluster peers must prove their authentication in the cluster by signing
        // a cluster auth message
        let my_cluster_id = { global_state.read_cluster_id().clone() };
        let mut non_cluster_peers = Vec::new();
        let mut cluster_peers = Vec::new();

        for peer in filtered_peers.iter() {
            // Skip if the heartbeat contains no peer info
            if let Some(info) = new_peer_info.get(peer) {
                if info.get_cluster_id() == my_cluster_id {
                    cluster_peers.push(*peer);
                } else {
                    non_cluster_peers.push(*peer);
                }
            }
        }

        // Add the non-cluster peers to the global state
        global_state.add_peers(&non_cluster_peers, new_peer_info);

        // Send cluster auth requests to all peers claiming to be in the local peer's cluster
        for cluster_peer in cluster_peers.iter() {
            network_channel
                .send(GossipOutbound::Request {
                    peer_id: *cluster_peer,
                    message: GossipRequest::ClusterAuth(ClusterAuthRequest {
                        cluster_id: local_cluster_id.clone(),
                    }),
                })
                .map_err(|err| GossipError::SendMessage(err.to_string()))?;
        }

        Ok(true)
    }

    /// Adds new addresses to the address index in the network manager so that they may be dialed on outbound
    fn add_new_addrs(
        peer_ids: &[WrappedPeerId],
        peer_info: &HashMap<WrappedPeerId, PeerInfo>,
        network_channel: UnboundedSender<GossipOutbound>,
    ) -> Result<(), GossipError> {
        for peer in peer_ids.iter() {
            network_channel
                .send(GossipOutbound::NewAddr {
                    peer_id: *peer,
                    address: peer_info.get(peer).unwrap().get_addr(),
                })
                .map_err(|err| GossipError::SendMessage(err.to_string()))?;
        }

        Ok(())
    }

    /// Sends heartbeat message to peers to exchange network information and ensure liveness
    pub(super) fn send_heartbeat(
        recipient_peer_id: WrappedPeerId,
        local_peer_id: WrappedPeerId,
        network_channel: UnboundedSender<GossipOutbound>,
        peer_expiry_cache: SharedLRUCache,
        global_state: &RelayerState,
    ) -> Result<(), GossipError> {
        if recipient_peer_id == local_peer_id {
            return Ok(());
        }

        let heartbeat_message =
            GossipRequest::Heartbeat(Self::build_heartbeat_message(global_state));
        network_channel
            .send(GossipOutbound::Request {
                peer_id: recipient_peer_id,
                message: heartbeat_message,
            })
            .map_err(|err| GossipError::SendMessage(err.to_string()))?;

        Self::maybe_expire_peer(recipient_peer_id, peer_expiry_cache, global_state);
        Ok(())
    }

    /// Expires peers that have timed out due to consecutive failed heartbeats
    fn maybe_expire_peer(
        peer_id: WrappedPeerId,
        peer_expiry_cache: SharedLRUCache,
        global_state: &RelayerState,
    ) {
        let now = get_current_time_seconds();
        {
            let my_cluster_id = global_state.read_cluster_id();
            let locked_peer_index = global_state.read_known_peers();
            let peer_info = locked_peer_index.get(&peer_id).unwrap();

            // Expire cluster peers sooner than non-cluster peers
            let same_cluster = peer_info.get_cluster_id().eq(&my_cluster_id);
            let last_heartbeat = now - peer_info.get_last_heartbeat();

            #[allow(clippy::if_same_then_else)]
            if same_cluster && last_heartbeat < CLUSTER_HEARTBEAT_FAILURE_MS / 1000 {
                return;
            } else if !same_cluster && last_heartbeat < HEARTBEAT_FAILURE_MS / 1000 {
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
    pub(super) fn build_heartbeat_message(global_state: &RelayerState) -> HeartbeatMessage {
        HeartbeatMessage::from(global_state)
    }
}

/// HeartbeatTimer handles the process of enqueuing jobs to perform
/// a heartbeat on regular intervals
#[derive(Debug)]
pub(super) struct HeartbeatTimer {
    /// The join handle of the timing thread for non-cluster peers
    inter_cluster_heartbeat_timer: Option<JoinHandle<GossipError>>,
    /// The join handle of the timing thread for cluster peers
    intra_cluster_heartbeat_timer: Option<JoinHandle<GossipError>>,
}

impl HeartbeatTimer {
    /// Spawns two timers, one for sending intra-cluster heartbeat messages, another for inter-cluster
    /// The interval parameters specify how often the timers should cycle through all peers in their
    /// target list
    pub fn new(
        job_queue: Sender<GossipServerJob>,
        intra_cluster_interval_ms: u64,
        inter_cluster_interval_ms: u64,
        global_state: RelayerState,
    ) -> Self {
        // Narrowing cast is okay, precision is not important here
        let intra_cluster_duration_seconds = intra_cluster_interval_ms / 1000;
        let intra_cluster_duration_nanos =
            (intra_cluster_interval_ms % 1000 * NANOS_PER_MILLI) as u32;
        let intra_cluster_wait_period =
            Duration::new(intra_cluster_duration_seconds, intra_cluster_duration_nanos);

        let inter_cluster_duration_seconds = inter_cluster_interval_ms / 1000;
        let inter_cluster_duration_nanos =
            (inter_cluster_interval_ms % 1000 * NANOS_PER_MILLI) as u32;
        let inter_cluster_wait_period =
            Duration::new(inter_cluster_duration_seconds, inter_cluster_duration_nanos);

        // Begin the timing loops
        let job_queue_clone = job_queue.clone();
        let global_state_clone = global_state.clone();
        let cluster_heartbeat_timer = thread::Builder::new()
            .name("intra-cluster-heartbeat-timer".to_string())
            .spawn(move || {
                Self::intra_cluster_execution_loop(
                    job_queue_clone,
                    intra_cluster_wait_period,
                    global_state_clone,
                )
            })
            .unwrap();

        let inter_cluster_heartbeat_timer = thread::Builder::new()
            .name("non-cluster-heartbeat-timer".to_string())
            .spawn(move || {
                Self::inter_cluster_execution_loop(
                    job_queue,
                    inter_cluster_wait_period,
                    global_state,
                )
            })
            .unwrap();

        Self {
            inter_cluster_heartbeat_timer: Some(inter_cluster_heartbeat_timer),
            intra_cluster_heartbeat_timer: Some(cluster_heartbeat_timer),
        }
    }

    /// Joins the calling thread's execution to the execution of the HeartbeatTimer
    pub fn join_handle(&mut self) -> Vec<JoinHandle<GossipError>> {
        vec![
            self.inter_cluster_heartbeat_timer.take().unwrap(),
            self.intra_cluster_heartbeat_timer.take().unwrap(),
        ]
    }

    /// Main timing loop for heartbeats sent to non-cluster nodes
    ///
    /// We space out the heartbeat requests to give a better traffic pattern. This means that in each
    /// time quantum, one heartbeat is scheduled. We compute the length of a time quantum with respect
    /// to the heartbeat period constant defined above. That is, we specify the interval in between
    /// heartbeats for a given peer, and space out all heartbeats in that interval
    fn inter_cluster_execution_loop(
        job_queue: Sender<GossipServerJob>,
        wait_period: Duration,
        global_state: RelayerState,
    ) -> GossipError {
        let mut peer_index = 0;
        let local_cluster = global_state.read_cluster_id().clone();

        loop {
            let (peer_count, next_peer_id) = {
                // Enqueue a heartbeat job for each known peer
                let peer_info_locked = global_state.read_known_peers();
                let next_peer = peer_info_locked.iter().nth(peer_index);

                // Skip if we have overflowed the list or if the next peer is in the local peer's cluster;
                // a separate timer will enqueue intra-cluster heartbeats at a faster rate
                let mut next_peer_id = None;
                if let Some((peer_id, peer_info)) = next_peer {
                    if peer_info.get_cluster_id() != local_cluster {
                        next_peer_id = Some(*peer_id)
                    }
                }

                (peer_info_locked.len(), next_peer_id)
            }; // peer_info_locked released

            // Enqueue a job to send the heartbeat
            if let Some(peer_id) = next_peer_id {
                if let Err(err) = job_queue.send(GossipServerJob::ExecuteHeartbeat(peer_id)) {
                    return GossipError::TimerFailed(err.to_string());
                }
            }

            // Do not simply (index + 1) % count; this will skip the first few elements if the list of known
            // peers has shrunk since the last iteration
            peer_index += 1;
            if peer_index >= peer_count {
                peer_index = 0;
            }

            // Compute the time quantum to sleep for, may change between loops if peers are added or removed
            let current_time_quantum = wait_period / (peer_count as u32);
            thread::sleep(current_time_quantum);
        }
    }

    /// The main timing loop for heartbeats send to in-cluster peers
    ///
    /// Slightly more readable to break this out into its own method as opposed to
    /// adding more control flow statements above
    fn intra_cluster_execution_loop(
        job_queue: Sender<GossipServerJob>,
        wait_period: Duration,
        global_state: RelayerState,
    ) -> GossipError {
        let mut peer_index = 0;

        loop {
            let (peer_count, next_peer_id) = {
                // Enqueue a heartbeat job for each known peer
                let cluster_metadata_locked = global_state.read_cluster_metadata();
                let next_peer = cluster_metadata_locked
                    .known_members
                    .iter()
                    .nth(peer_index)
                    .cloned();

                // Unwrap the option to deref the
                (cluster_metadata_locked.known_members.len(), next_peer)
            }; // cluster_metadata_locked released

            // Enqueue a job to send the heartbeat
            if let Some(peer_id) = next_peer_id {
                if let Err(err) = job_queue.send(GossipServerJob::ExecuteHeartbeat(peer_id)) {
                    return GossipError::TimerFailed(err.to_string());
                }
            }

            // Do not simply (index + 1) % count; this will skip the first few elements if the list of known
            // peers has shrunk since the last iteration
            peer_index += 1;
            if peer_index >= peer_count {
                peer_index = 0;

                // Log the state if in debug mode once per heartbeat period
                global_state.print_screen();
            }

            // Compute the time quantum to sleep for, may change between loops if peers are added or removed
            let current_time_quantum = wait_period / (peer_count as u32);
            thread::sleep(current_time_quantum);
        }
    }
}
