//! This file groups type definitions and helpers around global state that
//! is passed around throughout the code

use libp2p::{
    identity::{self, Keypair},
    Multiaddr,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    fmt::{Display, Formatter, Result as FmtResult},
    num::NonZeroU32,
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
};
use termion::color;

use crate::{
    api::heartbeat::HeartbeatMessage,
    gossip::types::{ClusterId, PeerInfo, WrappedPeerId},
    handshake::{manager::DEFAULT_HANDSHAKE_PRIORITY, types::OrderIdentifier},
};

use super::{
    peers::PeerIndex,
    wallet::{Wallet, WalletIndex},
};

/**
 * Constants and Types
 */

/// A type alias for a shared element, wrapped in a readers-writer mutex
pub type Shared<T> = Arc<RwLock<T>>;
/// Wrap an abstract value in a shared lock
pub(crate) fn new_shared<T>(wrapped: T) -> Shared<T> {
    Arc::new(RwLock::new(wrapped))
}

/// The top level object in the global state tree
///
/// The implementation of `RelayerState` handles locking various
/// state elements. This is mostly for convenience but also to
/// decouple the locking implementation with the readers/writers
#[derive(Clone, Debug)]
pub struct RelayerState {
    /// Whether or not the relayer is in debug mode
    pub debug: bool,
    /// The libp2p peerID assigned to the localhost
    pub local_peer_id: WrappedPeerId,
    /// The local libp2p keypair generated at startup
    pub local_keypair: Keypair,
    /// The cluster id of the local relayer
    pub local_cluster_id: Shared<ClusterId>,
    /// The listening address of the local relayer
    pub local_addr: Shared<Multiaddr>,
    /// The list of wallets managed by the sending relayer
    pub wallet_index: Shared<WalletIndex>,
    /// The set of peers known to the sending relayer
    pub peer_index: Shared<PeerIndex>,
    /// A list of matched orders
    /// TODO: Remove this
    pub matched_order_pairs: Shared<Vec<(OrderIdentifier, OrderIdentifier)>>,
    /// Priorities for scheduling handshakes with each peer
    pub handshake_priorities: Shared<HashMap<WrappedPeerId, NonZeroU32>>,
    /// Information about the local peer's cluster
    pub cluster_metadata: Shared<ClusterMetadata>,
}

/// Metadata about the local peer's cluster
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClusterMetadata {
    /// The cluster ID
    pub id: ClusterId,
    /// The known peers that are members of this cluster
    pub known_members: HashSet<WrappedPeerId>,
}

impl ClusterMetadata {
    /// Create a new, empty cluster metadata instance
    pub fn new(cluster_id: ClusterId) -> Self {
        Self {
            id: cluster_id,
            known_members: HashSet::new(),
        }
    }

    /// Returns whether the given peer is a known member of the cluster
    pub fn has_member(&self, peer_id: &WrappedPeerId) -> bool {
        self.known_members.contains(peer_id)
    }

    /// Add a member to the cluster
    pub fn add_member(&mut self, peer_id: WrappedPeerId) {
        self.known_members.insert(peer_id);
    }
}

impl RelayerState {
    /// Initialize the global state at startup
    pub fn initialize_global_state(
        debug: bool,
        wallets: Vec<Wallet>,
        cluster_id: ClusterId,
    ) -> Self {
        // Generate an keypair on curve 25519 for the local peer
        let local_keypair = identity::Keypair::generate_ed25519();
        let local_peer_id = WrappedPeerId(local_keypair.public().to_peer_id());

        // Setup initial wallets
        let mut wallet_index = WalletIndex::new(local_peer_id);
        for wallet in wallets.into_iter() {
            wallet_index.add_wallet(wallet);
        }

        // Setup the peer index
        let peer_index = PeerIndex::new(local_peer_id);

        Self {
            debug,
            // Replaced by a correct value when network manager initializes
            local_peer_id,
            local_keypair,
            local_cluster_id: new_shared(cluster_id.clone()),
            local_addr: new_shared(Multiaddr::empty()),
            wallet_index: new_shared(wallet_index),
            matched_order_pairs: new_shared(vec![]),
            peer_index: new_shared(peer_index),
            handshake_priorities: new_shared(HashMap::new()),
            cluster_metadata: new_shared(ClusterMetadata::new(cluster_id)),
        }
    }

    /// Get the local peer's info
    pub fn get_local_peer_info(&self) -> PeerInfo {
        PeerInfo::new(
            self.local_peer_id(),
            self.read_cluster_id().clone(),
            self.read_local_addr().clone(),
        )
    }

    /// Add a single peer to the global state
    pub fn add_single_peer(&self, peer_id: WrappedPeerId, peer_info: PeerInfo) {
        let info_map = HashMap::from([(peer_id, peer_info)]);
        self.add_peers(&[peer_id], &info_map);
    }

    /// Add a set of new peers to the global state
    pub fn add_peers(
        &self,
        peer_ids: &[WrappedPeerId],
        peer_info: &HashMap<WrappedPeerId, PeerInfo>,
    ) {
        let local_cluster_id = { self.read_cluster_id().clone() };
        let mut locked_peer_index = self.write_peer_index();
        let mut locked_handshake_priorities = self.write_handshake_priorities();

        for peer in peer_ids.iter() {
            // Skip this peer if peer info wasn't sent
            if let Some(info) = peer_info.get(peer) {
                // Record a dummy heartbeat to setup the initial state
                info.successful_heartbeat();
                locked_peer_index.add_peer(info.clone())
            } else {
                continue;
            }

            // Skip cluster peers (we don't need to handshake with them) and peers that already have assigned
            // priorities
            if let Entry::Vacant(e) = locked_handshake_priorities.entry(*peer)
                && locked_peer_index.read_peer(peer).unwrap().get_cluster_id() != local_cluster_id {
                e.insert(NonZeroU32::new(DEFAULT_HANDSHAKE_PRIORITY).unwrap());
            }
        }
    }

    /// Expire a set of peers that have been determined to have failed
    pub fn remove_peers(&self, peers: &[WrappedPeerId]) {
        // Update the peer info and cluster metadata
        {
            let mut locked_peer_info = self.write_peer_index();
            let mut locked_cluster_metadata = self.write_cluster_metadata();

            for peer in peers.iter() {
                if let Some(info) = locked_peer_info.remove_peer(peer) {
                    if info.get_cluster_id() == locked_cluster_metadata.id {
                        locked_cluster_metadata.known_members.remove(peer);
                    }
                }
            }
        } // locked_peer_info, locked_cluster_metadata released

        // Update the replicas set for any wallets replicated by the expired peer
        self.read_wallet_index().remove_peer_replicas(peers);

        // Remove the handshake priority entry for the peer
        {
            let mut locked_handshake_priorities = self.write_handshake_priorities();
            for peer in peers.iter() {
                locked_handshake_priorities.remove(peer);
            }
        } // locked_handshake_priorities released
    }

    /// Print the local relayer state to the screen for debugging
    pub fn print_screen(&self) {
        if !self.debug {
            return;
        }

        // Terminal control emissions to clear the terminal screen and
        // move the cursor to position (1, 1), then print self
        print!("{}[2J", 27 as char);
        print!("{esc}[2J{esc}[1;1H", esc = 27 as char);
        println!("{}", self);
    }

    /// Acquire a read lock on `local_peer_id`
    pub fn local_peer_id(&self) -> WrappedPeerId {
        self.local_peer_id
    }

    /// Acquire a read lock on `cluster_id`
    pub fn read_cluster_id(&self) -> RwLockReadGuard<ClusterId> {
        self.local_cluster_id
            .read()
            .expect("cluster_id lock poisoned")
    }

    /// Acquire a read lock on `local_addr`
    pub fn read_local_addr(&self) -> RwLockReadGuard<Multiaddr> {
        self.local_addr.read().expect("local_addr lock poisoned")
    }

    /// Acquire a write lock on `local_addr`
    pub fn write_local_addr(&self) -> RwLockWriteGuard<Multiaddr> {
        self.local_addr.write().expect("local_addr lock poisoned")
    }

    /// Acquire a read lock on `managed_wallets`
    pub fn read_wallet_index(&self) -> RwLockReadGuard<WalletIndex> {
        self.wallet_index
            .read()
            .expect("managed_wallets lock poisoned")
    }

    /// Acquire a write lock on `managed_wallets`
    pub fn write_wallet_index(&self) -> RwLockWriteGuard<WalletIndex> {
        self.wallet_index
            .write()
            .expect("managed_wallets lock poisoned")
    }

    /// Acquire a read lock on `matched_order_pairs`
    pub fn read_matched_order_pairs(
        &self,
    ) -> RwLockReadGuard<Vec<(OrderIdentifier, OrderIdentifier)>> {
        self.matched_order_pairs
            .read()
            .expect("matched_order_pairs lock poisoned")
    }

    /// Acquire a write lock on `matched_order_pairs`
    pub fn write_matched_order_pairs(
        &self,
    ) -> RwLockWriteGuard<Vec<(OrderIdentifier, OrderIdentifier)>> {
        self.matched_order_pairs
            .write()
            .expect("matched_order_pairs lock poisoned")
    }

    /// Acquire a read lock on `known_peers`
    pub fn read_peer_index(&self) -> RwLockReadGuard<PeerIndex> {
        self.peer_index.read().expect("known_peers lock poisoned")
    }

    /// Acquire a write lock on `known_peers`
    pub fn write_peer_index(&self) -> RwLockWriteGuard<PeerIndex> {
        self.peer_index.write().expect("known_peers lock poisoned")
    }

    /// Acquire a read lock on `handshake_priorities`
    pub fn read_handshake_priorities(&self) -> RwLockReadGuard<HashMap<WrappedPeerId, NonZeroU32>> {
        self.handshake_priorities
            .read()
            .expect("handshake_priorities lock poisoned")
    }

    /// Acquire a write lock on `handshake_priorities`
    pub fn write_handshake_priorities(
        &self,
    ) -> RwLockWriteGuard<HashMap<WrappedPeerId, NonZeroU32>> {
        self.handshake_priorities
            .write()
            .expect("handshake_priorities lock poisoned")
    }

    /// Acquire a read lock on `cluster_metadata`
    pub fn read_cluster_metadata(&self) -> RwLockReadGuard<ClusterMetadata> {
        self.cluster_metadata
            .read()
            .expect("cluster_metadata lock poisoned")
    }

    /// Acquire a write lock on `cluster_metadata`
    pub fn write_cluster_metadata(&self) -> RwLockWriteGuard<ClusterMetadata> {
        self.cluster_metadata
            .write()
            .expect("cluster_metadata lock poisoned")
    }
}

/// The derivation from global state to heartbeat message
impl From<&RelayerState> for HeartbeatMessage {
    fn from(state: &RelayerState) -> Self {
        // Get a mapping from wallet ID to information
        let wallet_info = state
            .wallet_index
            .read()
            .expect("wallet_index lock poisoned")
            .get_metadata_map();

        // Convert peer info keys to strings for serialization/deserialization
        let peer_info = state
            .peer_index
            .read()
            .expect("peer_index lock poisoned")
            .get_info_map()
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect();

        HeartbeatMessage {
            managed_wallets: wallet_info,
            known_peers: peer_info,
            cluster_metadata: state.read_cluster_metadata().clone(),
        }
    }
}

/// Display implementation for easy-to-read command line print-out
impl Display for RelayerState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_fmt(format_args!(
            "{}Local Relayer State:{}\n",
            color::Fg(color::Cyan),
            color::Fg(color::Reset),
        ))?;
        f.write_fmt(format_args!(
            "\t{}Listening on:{} {}/p2p/{}\n",
            color::Fg(color::LightGreen),
            color::Fg(color::Reset),
            self.read_peer_index()
                .read_peer(&self.local_peer_id())
                .unwrap()
                .get_addr(),
            self.local_peer_id().0
        ))?;
        f.write_fmt(format_args!(
            "\t{}PeerId:{} {}\n",
            color::Fg(color::LightGreen),
            color::Fg(color::Reset),
            self.local_peer_id().0
        ))?;
        f.write_fmt(format_args!(
            "\t{}ClusterId:{} {:?}\n",
            color::Fg(color::LightGreen),
            color::Fg(color::Reset),
            self.read_cluster_id()
        ))?;

        // Write wallet info to the format
        self.read_wallet_index().fmt(f)?;
        f.write_str("\n\n\n")?;

        // Write historically matched orders to the format
        f.write_fmt(format_args!(
            "\n\t{}Matched Order Pairs:{}\n",
            color::Fg(color::LightGreen),
            color::Fg(color::Reset),
        ))?;
        for (o1, o2) in self.read_matched_order_pairs().iter() {
            f.write_fmt(format_args!(
                "\t\t - {}({:?}, {:?}){}\n",
                color::Fg(color::LightYellow),
                o1,
                o2,
                color::Fg(color::Reset),
            ))?;
        }

        f.write_str("\n\n\n")?;
        // Write the known peers to the format
        f.write_fmt(format_args!(
            "\t{}Known Peers{}:\n",
            color::Fg(color::LightGreen),
            color::Fg(color::LightGreen)
        ))?;
        self.peer_index.read().unwrap().fmt(f)?;
        f.write_str("\n\n")?;

        // Write cluster metadata to the format
        f.write_fmt(format_args!(
            "\t{}Cluster Metadata{} (ID = {}{:?}{})\n",
            color::Fg(color::LightGreen),
            color::Fg(color::Reset),
            color::Fg(color::LightYellow),
            self.read_cluster_metadata().id,
            color::Fg(color::Reset)
        ))?;
        f.write_fmt(format_args!(
            "\t\t{}Members{}: [\n",
            color::Fg(color::LightYellow),
            color::Fg(color::Reset)
        ))?;
        for member in self.read_cluster_metadata().known_members.iter() {
            f.write_fmt(format_args!("\t\t\t{}\n", member.0))?;
        }
        f.write_str("\t\t]")?;

        Ok(())
    }
}
