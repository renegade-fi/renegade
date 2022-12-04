//! This file groups type definitions and helpers around global state that
//! is passed around throughout the code

use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fmt::{Display, Formatter, Result as FmtResult},
    str::FromStr,
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

use crate::gossip::types::{ClusterId, PeerInfo, WrappedPeerId};

/**
 * Constants and Types
 */

/// A type alias for a shared element, wrapped in a readers-writer mutex
pub type Shared<T> = Arc<RwLock<T>>;
/// Wrap an abstract value in a shared lock
fn new_shared<T>(wrapped: T) -> Shared<T> {
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
    pub local_peer_id: Shared<WrappedPeerId>,
    /// The cluster id of the local relayer
    pub local_cluster_id: Shared<ClusterId>,
    /// The list of wallets managed by the sending relayer
    pub managed_wallets: Shared<HashMap<Uuid, Wallet>>,
    /// The set of peers known to the sending relayer
    pub known_peers: Shared<HashMap<WrappedPeerId, PeerInfo>>,
    /// Information about the local peer's cluster
    pub cluster_metadata: Shared<ClusterMetadata>,
}

impl Display for RelayerState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("Local Relayer State:\n")?;
        f.write_fmt(format_args!(
            "\tListening on: {}/p2p/{}\n",
            self.read_known_peers()
                .get(&self.read_peer_id())
                .unwrap()
                .get_addr(),
            self.read_peer_id().0
        ))?;
        f.write_fmt(format_args!("\tPeerId: {}\n", self.read_peer_id().0))?;
        f.write_fmt(format_args!("\tClusterId: {:?}\n", self.read_cluster_id()))?;

        // Write wallet info to the format
        f.write_str("\n\tManaged Wallets:\n")?;
        for (wallet_id, wallet) in self.read_managed_wallets().iter() {
            f.write_fmt(format_args!(
                "\t\t- {:?}: {{\n\t\t\treplicas: [\n",
                wallet_id
            ))?;
            for replica in wallet.metadata.replicas.iter() {
                f.write_fmt(format_args!("\t\t\t\t{}\n", replica.0))?;
            }

            f.write_str("\t\t\t]\n\t\t}")?;
        }
        f.write_str("\n\n\n")?;

        // Write the known peers to the format
        f.write_str("\tKnown Peers:\n")?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("negative timestamp")
            .as_secs();
        for (peer_id, peer_info) in self.read_known_peers().iter() {
            let last_heartbeat_elapsed = if peer_id.ne(&self.read_peer_id()) {
                (now - peer_info.get_last_heartbeat()) * 1000
            } else {
                0
            };

            f.write_fmt(format_args!(
                "\t\t- {}: \n\t\t\tlast_heartbeat: {:?}ms \n\t\t\tcluster_id: {:?} }}\n\n",
                peer_id.0,
                last_heartbeat_elapsed,
                peer_info.get_cluster_id()
            ))?;
        }
        f.write_str("\n\n")?;

        // Write cluster metadata to the format
        f.write_fmt(format_args!(
            "\tCluster Metadata (ID = {:?})\n",
            self.read_cluster_metadata().id
        ))?;
        f.write_str("\t\tMembers: [\n")?;
        for member in self.read_cluster_metadata().known_members.iter() {
            f.write_fmt(format_args!("\t\t\t{}\n", member.0))?;
        }
        f.write_str("\t\t]")?;

        Ok(())
    }
}

impl RelayerState {
    /// Initialize the global state at startup
    pub fn initialize_global_state(
        debug: bool,
        managed_wallet_ids: Vec<String>,
        bootstrap_servers: Vec<PeerInfo>,
        cluster_id: ClusterId,
    ) -> Self {
        // Setup initial wallets
        let mut managed_wallets = HashMap::new();
        for wallet_id in managed_wallet_ids.iter() {
            let wallet_id = uuid::Uuid::from_str(wallet_id).expect("could not parse wallet ID");
            let wal = Wallet {
                wallet_id,
                metadata: WalletMetadata {
                    replicas: HashSet::new(),
                },
            };
            managed_wallets.insert(wallet_id, wal);
        }

        // Setup initial set of known peers to be the bootstrap servers
        let mut known_peers = HashMap::<WrappedPeerId, PeerInfo>::new();
        for server in bootstrap_servers.iter() {
            known_peers.insert(server.get_peer_id(), server.clone());
        }

        Self {
            debug,
            // Replaced buy a correct value when network manager initializes
            local_peer_id: new_shared(WrappedPeerId::random()),
            managed_wallets: new_shared(managed_wallets),
            known_peers: new_shared(known_peers),
            local_cluster_id: new_shared(cluster_id.clone()),
            cluster_metadata: new_shared(ClusterMetadata::new(cluster_id)),
        }
    }

    /// Expire a set of peers that have been determined to have failed
    pub fn remove_peers(&self, peers: &[WrappedPeerId]) {
        // Lock the peer info and cluster metadata
        let mut locked_peer_info = self.write_known_peers();
        let mut locked_cluster_metadata = self.write_cluster_metadata();

        for peer in peers.iter() {
            if let Some(info) = locked_peer_info.remove(peer) {
                if info.get_cluster_id() == locked_cluster_metadata.id {
                    locked_cluster_metadata.known_members.remove(peer);
                }
            }
        }
    }

    /// Print the local relayer state to the screen for debugging
    pub fn print_screen(&self) {
        if !self.debug {
            return;
        }

        print!("{}[2J", 27 as char);
        print!("{esc}[2J{esc}[1;1H", esc = 27 as char);
        println!("{}", self);
    }

    /// Acquire a read lock on `local_peer_id`
    /// TODO: Remove the lint allowance
    #[allow(dead_code)]
    pub fn read_peer_id(&self) -> RwLockReadGuard<WrappedPeerId> {
        self.local_peer_id
            .read()
            .expect("local_peer_id lock poisoned")
    }

    /// Acquire a write lock on `local_peer_id`
    pub fn write_peer_id(&self) -> RwLockWriteGuard<WrappedPeerId> {
        self.local_peer_id
            .write()
            .expect("local_peer_id lock poisoned")
    }

    /// Acquire a read lock on `cluster_id`
    /// TODO: Remove the lint allowance
    #[allow(dead_code)]
    pub fn read_cluster_id(&self) -> RwLockReadGuard<ClusterId> {
        self.local_cluster_id
            .read()
            .expect("cluster_id lock poisoned")
    }

    /// Acquire a write lock on `cluster_id`
    /// TODO: Remove the lint allowance
    #[allow(dead_code)]
    pub fn write_cluster_id(&self) -> RwLockWriteGuard<ClusterId> {
        self.local_cluster_id
            .write()
            .expect("cluster_id lock poisoned")
    }

    /// Acquire a read lock on `managed_wallets`
    pub fn read_managed_wallets(&self) -> RwLockReadGuard<HashMap<Uuid, Wallet>> {
        self.managed_wallets
            .read()
            .expect("managed_wallets lock poisoned")
    }

    /// Acquire a write lock on `managed_wallets`
    pub fn write_managed_wallets(&self) -> RwLockWriteGuard<HashMap<Uuid, Wallet>> {
        self.managed_wallets
            .write()
            .expect("managed_wallets lock poisoned")
    }

    /// Acquire a read lock on `known_peers`
    pub fn read_known_peers(&self) -> RwLockReadGuard<HashMap<WrappedPeerId, PeerInfo>> {
        self.known_peers.read().expect("known_peers lock poisoned")
    }

    /// Acquire a write lock on `known_peers`
    pub fn write_known_peers(&self) -> RwLockWriteGuard<HashMap<WrappedPeerId, PeerInfo>> {
        self.known_peers.write().expect("known_peers lock poisoned")
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
/// Represents a wallet managed by the local relayer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Wallet {
    /// Wallet metadata; replicas, trusted peers, etc
    pub metadata: WalletMetadata,
    /// Wallet id will eventually be replaced, for now it is UUID
    pub wallet_id: Uuid,
}

/// Metadata relevant to the wallet's network state
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletMetadata {
    /// The peers which are believed by the local node to be replicating a given wallet
    pub replicas: HashSet<WrappedPeerId>,
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
