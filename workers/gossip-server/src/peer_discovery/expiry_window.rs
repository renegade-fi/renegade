//! Defines a windowed buffer that manages the state transitions of peers in the
//! network

use std::{
    collections::HashMap,
    hash::Hash,
    time::{Duration, Instant},
};

use common::{new_async_shared, types::gossip::WrappedPeerId, AsyncShared};
use tokio::sync::{RwLockReadGuard, RwLockWriteGuard};

/// The amount of time other cluster peers are allowed to give liveness
/// attestations for an expiry candidate
pub(crate) const EXPIRY_CANDIDATE_WINDOW_MS: u64 = 15_000; // 15 seconds
/// The minimum amount of time between a peer's expiry and when it can be
/// added back to the peer info
pub(crate) const EXPIRY_INVISIBILITY_WINDOW_MS: u64 = 60_000; // 1 minute

/// A buffer of time windows
#[derive(Clone)]
pub struct TimeWindowBuffer<T: Hash + Eq + PartialEq> {
    /// The set of time windows; maps a key to the time at which it should exit
    /// the buffer
    ///
    /// Thread safe
    pub windows: AsyncShared<HashMap<T, Instant>>,
}

impl<T: Hash + Eq + PartialEq> TimeWindowBuffer<T> {
    /// Constructor
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self { windows: new_async_shared(HashMap::new()) }
    }

    /// Acquire a read lock on the windows
    async fn read_windows(&self) -> RwLockReadGuard<'_, HashMap<T, Instant>> {
        self.windows.read().await
    }

    /// Acquire a write lock on the windows
    async fn write_windows(&self) -> RwLockWriteGuard<'_, HashMap<T, Instant>> {
        self.windows.write().await
    }

    /// Whether or not the given key is present in the buffer
    pub async fn contains(&self, key: &T) -> bool {
        let this = self.read_windows().await;
        this.contains_key(key)
    }

    /// Whether the given key is in its time window still
    pub async fn in_window(&self, key: &T) -> bool {
        let this = self.read_windows().await;
        this.get(key).map_or(false, |expiry_time| *expiry_time > Instant::now())
    }

    /// Check whether the window for a key has expired
    pub async fn is_expired(&self, key: &T) -> bool {
        let this = self.read_windows().await;
        this.get(key).map_or(false, |expiry_time| *expiry_time < Instant::now())
    }

    /// Adds a key to the buffer
    pub async fn add(&self, key: T, dur: Duration) {
        let expiry_time = Instant::now() + dur;
        let mut this = self.write_windows().await;
        this.insert(key, expiry_time);
    }

    /// Remove a key from the buffer
    pub async fn remove(&self, key: T) {
        let mut this = self.write_windows().await;
        this.remove(&key);
    }
}

/// A buffer that contains expiry windows for the nodes in the network
///
/// Within the context of peer expiry, a remote node may be in one of two
/// states:
/// - Expiry Candidate: a cluster peer has been deemed a candidate for expiry,
///   and will be expired if no _other_ cluster peers attest to its liveness.
///   Note that only intra-cluster peers may be in this state, inter-cluster
///   peering is expired immediately. This means that a node from another
///   cluster will be immediately placed in the invisibility window when
///   expired.
/// - Expiry Invisibility: a (possibly non-cluster) peer has been expired, and
///   enters an invisibility window, during which they may not be added back to
///   the network. This allows time for expiry to sync across nodes
///
/// The buffer manages the state transitions of these two windows
#[derive(Clone)]
pub struct PeerExpiryWindows {
    /// The buffer of candidates awaiting expiry or liveness attestation
    pub candidates: TimeWindowBuffer<WrappedPeerId>,
    /// The buffer of peers that have been expired and are in their invisibility
    /// window
    pub invisibility: TimeWindowBuffer<WrappedPeerId>,
}

impl PeerExpiryWindows {
    /// Constructor
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self { candidates: TimeWindowBuffer::new(), invisibility: TimeWindowBuffer::new() }
    }

    /// Get all of the expiry candidates
    pub async fn get_candidates(&self) -> Vec<WrappedPeerId> {
        self.candidates.read_windows().await.keys().cloned().collect()
    }

    /// Check the expiry candidacy of a peer
    pub async fn is_expiry_candidate(&self, peer_id: &WrappedPeerId) -> bool {
        self.candidates.contains(peer_id).await
    }

    /// Whether the peer should be expired
    ///
    /// `true` if the remote peer is in the expiry candidate list and the
    /// timeout has elapsed
    pub async fn should_expire(&self, peer_id: &WrappedPeerId) -> bool {
        self.candidates.is_expired(peer_id).await
    }

    /// Whether either the expiry candidate list or the invisibility window
    /// contains the given peer
    pub async fn contains(&self, peer_id: &WrappedPeerId) -> bool {
        self.candidates.contains(peer_id).await || self.invisibility.contains(peer_id).await
    }

    /// Whether a given peer is invisible
    pub async fn is_invisible(&self, peer_id: &WrappedPeerId) -> bool {
        self.invisibility.in_window(peer_id).await
    }

    /// Add a peer to the expiry candidate list
    async fn add_expiry_candidate(&self, peer_id: WrappedPeerId) {
        let dur = Duration::from_millis(EXPIRY_CANDIDATE_WINDOW_MS);
        self.candidates.add(peer_id, dur).await;
    }

    /// Add a peer to the invisibility window
    async fn mark_invisible(&self, peer_id: WrappedPeerId) {
        let dur = Duration::from_millis(EXPIRY_INVISIBILITY_WINDOW_MS);
        self.invisibility.add(peer_id, dur).await;
    }

    /// Mark a peer as a candidate for expiry
    ///
    /// The candidate is added to both the expiry candidate list and the
    /// invisibility window to prevent the peer from being added back to the
    /// network while multiple nodes may be expiring it
    pub async fn mark_expiry_candidate(&self, peer_id: WrappedPeerId) {
        self.add_expiry_candidate(peer_id).await;
        self.mark_invisible(peer_id).await;
    }

    /// Remove a candidate from the expiry candidate list
    pub async fn remove_expiry_candidate(&self, peer_id: WrappedPeerId) {
        self.candidates.remove(peer_id).await;
    }

    /// Mark a peer as expired, adding it to the invisibility window
    pub async fn mark_expired(&self, peer_id: WrappedPeerId) {
        self.remove_expiry_candidate(peer_id).await;
        self.mark_invisible(peer_id).await;
    }
}
