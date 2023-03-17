//! This file groups type definitions and helpers around global state that
//! is passed around throughout the code

use crate::{
    gossip::types::{ClusterId, PeerInfo, WrappedPeerId},
    gossip_api::heartbeat::HeartbeatMessage,
    proof_generation::jobs::ValidCommitmentsBundle,
    state::orderbook::NetworkOrder,
    system_bus::SystemBus,
    types::SystemBusMessage,
};
use circuits::types::wallet::Nullifier;
use libp2p::{
    identity::{self, Keypair},
    Multiaddr,
};
use rand::{distributions::WeightedIndex, prelude::Distribution, thread_rng};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use tokio::sync::{RwLock as AsyncRwLock, RwLockReadGuard, RwLockWriteGuard};

use super::{
    orderbook::{NetworkOrderBook, OrderIdentifier},
    peers::PeerIndex,
    priority::HandshakePriorityStore,
    wallet::{Wallet, WalletIndex},
};

// -----------------------
// | Constants and Types |
// -----------------------

/// A type alias for a shared element, wrapped in an async capable readers-writer mutex
pub type AsyncShared<T> = Arc<AsyncRwLock<T>>;
/// A type alias for a shared element, wrapped in a readers-writer mutex
pub type Shared<T> = Arc<RwLock<T>>;

/// Wrap an abstract value in an async shared lock
pub fn new_async_shared<T>(wrapped: T) -> AsyncShared<T> {
    Arc::new(AsyncRwLock::new(wrapped))
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
    pub local_cluster_id: ClusterId,
    /// The listening address of the local relayer
    ///
    /// Despite being static after initialization, this value is
    /// set by the network manager, so we maintain a cross-worker
    /// reference
    pub local_addr: AsyncShared<Multiaddr>,
    /// The list of wallets managed by the sending relayer
    wallet_index: AsyncShared<WalletIndex>,
    /// The set of peers known to the sending relayer
    peer_index: AsyncShared<PeerIndex>,
    /// The order book and indexing structure for orders in the network
    order_book: AsyncShared<NetworkOrderBook>,
    /// A list of matched orders
    /// TODO: Remove this
    matched_order_pairs: AsyncShared<Vec<(OrderIdentifier, OrderIdentifier)>>,
    /// Priorities for scheduling handshakes with each peer
    pub handshake_priorities: AsyncShared<HandshakePriorityStore>,
}

impl RelayerState {
    /// Initialize the global state at startup
    pub fn initialize_global_state(
        debug: bool,
        wallets: Vec<Wallet>,
        cluster_id: ClusterId,
        system_bus: SystemBus<SystemBusMessage>,
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
        let peer_index = PeerIndex::new();

        // Setup the order book
        let order_book = NetworkOrderBook::new(system_bus);

        Self {
            debug,
            local_peer_id,
            local_keypair,
            local_cluster_id: cluster_id,
            local_addr: new_async_shared(Multiaddr::empty()),
            wallet_index: new_async_shared(wallet_index),
            matched_order_pairs: new_async_shared(vec![]),
            peer_index: new_async_shared(peer_index),
            order_book: new_async_shared(order_book),
            handshake_priorities: new_async_shared(HandshakePriorityStore::new()),
        }
    }

    // -----------
    // | Getters |
    // -----------

    /// Get the local peer's ID
    pub fn local_peer_id(&self) -> WrappedPeerId {
        self.local_peer_id
    }

    /// Get the peer info for the local peer
    pub async fn local_peer_info(&self) -> PeerInfo {
        self.read_peer_index()
            .await
            .get_peer_info(&self.local_peer_id)
            .await
            .unwrap()
    }

    /// Sample an order for handshake
    pub async fn choose_handshake_order(&self) -> Option<OrderIdentifier> {
        // Read the set of orders that are verified and thereby ready for batch
        let verified_orders = {
            self.read_order_book()
                .await
                .get_nonlocal_verified_orders()
                .await
        };
        if verified_orders.is_empty() {
            return None;
        }

        // Fetch the priorities for the verified orders
        let mut priorities = Vec::with_capacity(verified_orders.len());
        {
            let locked_priority_store = self.read_handshake_priorities().await;
            for order_id in verified_orders.iter() {
                let priority = locked_priority_store.get_order_priority(order_id).await;
                priorities.push(priority.get_effective_priority());
            }
        } // locked_priority_store released

        // Sample a random priority-weighted order from the result
        let mut rng = thread_rng();
        let distribution = WeightedIndex::new(&priorities).unwrap();
        Some(*verified_orders.get(distribution.sample(&mut rng)).unwrap())
    }

    /// Get a peer in the cluster that manages the given order, used to dial during
    /// handshake scheduling
    pub async fn get_peer_managing_order(
        &self,
        order_id: &OrderIdentifier,
    ) -> Option<WrappedPeerId> {
        // Get the cluster that manages this order
        let managing_cluster = {
            self.read_order_book()
                .await
                .get_order_info(order_id)
                .await?
                .cluster
        };

        // Get a peer in this cluster
        self.read_peer_index()
            .await
            .sample_cluster_peer(&managing_cluster)
            .await
    }

    // ----------------------
    // | Peer Index Setters |
    // ----------------------

    /// Add a single peer to the global state
    pub async fn add_single_peer(&self, peer_id: WrappedPeerId, peer_info: PeerInfo) {
        let info_map = HashMap::from([(peer_id, peer_info)]);
        self.add_peers(&[peer_id], &info_map).await;
    }

    /// Add a set of new peers to the global state
    pub async fn add_peers(
        &self,
        peer_ids: &[WrappedPeerId],
        peer_info: &HashMap<WrappedPeerId, PeerInfo>,
    ) {
        let mut locked_peer_index = self.write_peer_index().await;
        for peer in peer_ids.iter() {
            // Skip this peer if peer info wasn't sent, or if their cluster auth signature doesn't verify
            if let Some(info) = peer_info.get(peer) && info.verify_cluster_auth_sig().is_ok() {
                // Record a dummy heartbeat to setup the initial state
                info.successful_heartbeat();
                locked_peer_index.add_peer(info.clone()).await
            } else {
                continue;
            }
        }
    }

    /// Expire a set of peers that have been determined to have failed
    pub async fn remove_peer(&self, peer: &WrappedPeerId) {
        // Update the peer index
        self.write_peer_index().await.remove_peer(peer).await;
        // Update the replicas set for any wallets replicated by the expired peer
        self.read_wallet_index()
            .await
            .remove_peer_replicas(peer)
            .await;
    }

    // ----------------------
    // | Order Book Setters |
    // ----------------------

    /// Add an order to the book
    pub async fn add_order(&self, order: NetworkOrder) {
        // Add the order to the book and to the priority store
        self.write_handshake_priorities()
            .await
            .new_order(order.id, order.cluster.clone());
        self.write_order_book().await.add_order(order).await;
    }

    /// Add a validity proof for an order
    pub async fn add_order_validity_proof(
        &self,
        order_id: &OrderIdentifier,
        proof: ValidCommitmentsBundle,
    ) {
        self.write_order_book()
            .await
            .update_order_validity_proof(order_id, proof)
            .await
    }

    /// Nullify all orders with a given nullifier
    pub async fn nullify_orders(&self, nullifier: Nullifier) {
        let mut locked_order_book = self.write_order_book().await;
        let orders_to_nullify = locked_order_book.get_orders_by_nullifier(nullifier).await;
        for order_id in orders_to_nullify.into_iter() {
            locked_order_book.transition_cancelled(&order_id).await;
        }
    }

    // ------------------------
    // | Wallet Index Setters |
    // ------------------------

    /// Add wallets to the state as managed wallets
    ///
    /// The orders in the wallet are assumed to be locally managed, as the
    /// wallet is given in plaintext
    ///
    /// This may happen at startup when a relayer advertises its presence to
    /// cluster peers; or when a new wallet is created on a remote cluster peer
    pub async fn add_wallets(&self, wallets: Vec<Wallet>) {
        let mut locked_wallet_index = self.write_wallet_index().await;
        let mut locked_order_book = self.write_order_book().await;

        for wallet in wallets.into_iter() {
            let wallet_match_nullifier = wallet.get_match_nullifier();
            locked_wallet_index.add_wallet(wallet.clone());

            for order_id in wallet.orders.into_keys() {
                locked_order_book
                    .add_order(NetworkOrder::new(
                        order_id,
                        wallet_match_nullifier,
                        self.local_cluster_id.clone(),
                        true, /* local */
                    ))
                    .await;
            }
        }
    }

    /// Mark an order pair as matched, this is both for bookkeeping and for
    /// order state updates that are available to the frontend
    pub async fn mark_order_pair_matched(&self, o1: OrderIdentifier, o2: OrderIdentifier) {
        // Remove the scheduling priorities for the orders
        let mut locked_handshake_priorities = self.write_handshake_priorities().await;
        locked_handshake_priorities.remove_order(&o1);
        locked_handshake_priorities.remove_order(&o2);

        // Mark the order pair as matched
        self.write_matched_order_pairs().await.push((o1, o2));
    }

    // -----------
    // | Locking |
    // -----------

    /// Acquire a write lock on `local_addr`
    pub async fn write_local_addr(&self) -> RwLockWriteGuard<Multiaddr> {
        self.local_addr.write().await
    }

    /// Acquire a read lock on `managed_wallets`
    pub async fn read_wallet_index(&self) -> RwLockReadGuard<WalletIndex> {
        self.wallet_index.read().await
    }

    /// Acquire a write lock on `managed_wallets`
    async fn write_wallet_index(&self) -> RwLockWriteGuard<WalletIndex> {
        self.wallet_index.write().await
    }

    /// Acquire a read lock on `known_peers`
    pub async fn read_peer_index(&self) -> RwLockReadGuard<PeerIndex> {
        self.peer_index.read().await
    }

    /// Acquire a write lock on `known_peers`
    async fn write_peer_index(&self) -> RwLockWriteGuard<PeerIndex> {
        self.peer_index.write().await
    }

    /// Acquire a read lock on `order_book`
    pub async fn read_order_book(&self) -> RwLockReadGuard<NetworkOrderBook> {
        self.order_book.read().await
    }

    /// Acquire a write lock on `order_book`
    pub(super) async fn write_order_book(&self) -> RwLockWriteGuard<NetworkOrderBook> {
        self.order_book.write().await
    }

    /// Acquire a read lock on `matched_order_pairs`
    #[allow(unused)]
    pub async fn read_matched_order_pairs(
        &self,
    ) -> RwLockReadGuard<Vec<(OrderIdentifier, OrderIdentifier)>> {
        self.matched_order_pairs.read().await
    }

    /// Acquire a write lock on `matched_order_pairs`
    async fn write_matched_order_pairs(
        &self,
    ) -> RwLockWriteGuard<Vec<(OrderIdentifier, OrderIdentifier)>> {
        self.matched_order_pairs.write().await
    }

    /// Acquire a read lock on `handshake_priorities`
    pub async fn read_handshake_priorities(&self) -> RwLockReadGuard<HandshakePriorityStore> {
        self.handshake_priorities.read().await
    }

    /// Acquire a write lock on `handshake_priorities`
    async fn write_handshake_priorities(&self) -> RwLockWriteGuard<HandshakePriorityStore> {
        self.handshake_priorities.write().await
    }

    /// Construct a heartbeat message from the relayer state
    pub async fn construct_heartbeat(&self) -> HeartbeatMessage {
        // Get a mapping from wallet ID to information
        let wallet_info = self.read_wallet_index().await.get_metadata_map().await;

        // Convert peer info keys to strings for serialization/deserialization
        let peer_info = self
            .read_peer_index()
            .await
            .get_info_map()
            .await
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect();

        // Get a list of all orders in the book
        let order_info = self.read_order_book().await.get_order_owner_pairs().await;

        HeartbeatMessage {
            managed_wallets: wallet_info,
            known_peers: peer_info,
            orders: order_info,
        }
    }
}
