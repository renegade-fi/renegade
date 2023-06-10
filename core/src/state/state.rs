//! This file groups type definitions and helpers around global state that
//! is passed around throughout the code

use crate::{
    config::RelayerConfig,
    gossip::types::{ClusterId, PeerInfo, WrappedPeerId},
    gossip_api::heartbeat::HeartbeatMessage,
    proof_generation::OrderValidityProofBundle,
    state::orderbook::NetworkOrder,
    system_bus::SystemBus,
    types::{wallet_topic_name, SystemBusMessage, NETWORK_TOPOLOGY_TOPIC},
};
use circuits::types::{order::Order, wallet::Nullifier};
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
    /// A reference to the relayer-global system bus; used to stream state updates
    /// to listening parties
    pub system_bus: SystemBus<SystemBusMessage>,
}

impl RelayerState {
    /// Initialize the global state at startup
    pub fn initialize_global_state(
        args: &RelayerConfig,
        system_bus: SystemBus<SystemBusMessage>,
    ) -> Self {
        // Generate an keypair on curve 25519 for the local peer or fetch from config
        let local_keypair = args
            .p2p_key
            .clone()
            .map(|b64_encoded| {
                let decoded = base64::decode(b64_encoded).expect("p2p key formatted incorrectly");
                identity::Keypair::from_protobuf_encoding(&decoded).expect("error parsing p2p key")
            })
            .unwrap_or_else(identity::Keypair::generate_ed25519);
        let local_peer_id = WrappedPeerId(local_keypair.public().to_peer_id());
        // Setup initial wallets
        let mut wallet_index = WalletIndex::new(local_peer_id);
        for wallet in args.wallets.iter().cloned() {
            wallet_index.add_wallet(wallet);
        }

        // Setup the peer index
        let peer_index = PeerIndex::new(args.allow_local);

        // Setup the order book
        let order_book = NetworkOrderBook::new(system_bus.clone());

        Self {
            debug: args.debug,
            local_peer_id,
            local_keypair,
            local_cluster_id: args.cluster_id.clone(),
            wallet_index: new_async_shared(wallet_index),
            matched_order_pairs: new_async_shared(vec![]),
            peer_index: new_async_shared(peer_index),
            order_book: new_async_shared(order_book),
            handshake_priorities: new_async_shared(HandshakePriorityStore::new()),
            system_bus,
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

    /// Get the info for a locally managed order
    pub async fn get_order(&self, order_id: &OrderIdentifier) -> Option<Order> {
        let locked_wallet_index = self.read_wallet_index().await;
        let managing_wallet_id = locked_wallet_index.get_wallet_for_order(order_id)?;
        let wallet = locked_wallet_index.get_wallet(&managing_wallet_id).await?;

        wallet.orders.get(order_id).cloned()
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

    /// Add a peer without validation that the cluster auth signature is valid or that the
    /// peer's address is dialable
    ///
    /// This should only be used when validation can be assumed from context
    pub async fn add_peer_unchecked(&self, peer_info: PeerInfo) {
        self.write_peer_index()
            .await
            .add_peer_unchecked(peer_info)
            .await;
    }

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
                locked_peer_index.add_peer(info.clone()).await;

                // Push a message onto the bus indicating the new peer discovery
                self.system_bus
                    .publish(
                        NETWORK_TOPOLOGY_TOPIC.to_string(),
                        SystemBusMessage::NewPeer { peer: info.clone().into() }
                    );
            } else {
                continue;
            }
        }
    }

    /// Expire a set of peers that have been determined to have failed
    pub async fn remove_peer(&self, peer: &WrappedPeerId) {
        // Update the peer index
        let expired_peer = self.write_peer_index().await.remove_peer(peer).await;
        // Update the replicas set for any wallets replicated by the expired peer
        self.read_wallet_index()
            .await
            .remove_peer_replicas(peer)
            .await;

        // Push an event onto the bus signalling the peer is expired
        if let Some(peer) = expired_peer {
            self.system_bus.publish(
                NETWORK_TOPOLOGY_TOPIC.to_string(),
                SystemBusMessage::PeerExpired { peer: peer.into() },
            );
        }
    }

    /// Update the local peer's public IP address after discovery via gossip
    ///
    /// Returns the previous address if one existed
    pub async fn update_local_peer_addr(&self, addr: Multiaddr) {
        self.read_peer_index()
            .await
            .update_peer_addr(&self.local_peer_id, addr)
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
    pub async fn add_order_validity_proofs(
        &self,
        order_id: &OrderIdentifier,
        validity_proofs: OrderValidityProofBundle,
    ) {
        self.write_order_book()
            .await
            .update_order_validity_proofs(order_id, validity_proofs)
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
            // Index the wallet
            let wallet_share_nullifier = wallet.get_wallet_nullifier();
            locked_wallet_index.add_wallet(wallet.clone());

            // Publish a message to the system bus indicating a wallet update
            let wallet_topic = wallet_topic_name(&wallet.wallet_id);
            self.system_bus.publish(
                wallet_topic,
                SystemBusMessage::WalletUpdate {
                    wallet: wallet.clone().into(),
                },
            );

            // Index all orders in the wallet
            for (order_id, order) in wallet.orders.into_iter() {
                // Skip default orders
                if order.is_default() {
                    continue;
                }

                locked_order_book
                    .add_order(NetworkOrder::new(
                        order_id,
                        wallet_share_nullifier,
                        self.local_cluster_id.clone(),
                        true, /* local */
                    ))
                    .await;
            }
        }
    }

    /// Update an existing wallet in the global state
    pub async fn update_wallet(&self, mut wallet: Wallet) {
        wallet.remove_default_elements();

        // Add the wallet's orders to the book
        let mut locked_order_book = self.write_order_book().await;
        let wallet_share_nullifier = wallet.get_wallet_nullifier();
        for order_id in wallet.orders.keys() {
            if !locked_order_book.contains_order(order_id) {
                locked_order_book
                    .add_order(NetworkOrder::new(
                        *order_id,
                        wallet_share_nullifier,
                        self.local_cluster_id.clone(),
                        true, /* local */
                    ))
                    .await;
            }
        }

        let mut locked_wallet_index = self.write_wallet_index().await;
        locked_wallet_index.add_wallet(wallet.clone());

        // Publish a message to the system bus indicating a wallet update
        let wallet_topic = wallet_topic_name(&wallet.wallet_id);
        self.system_bus.publish(
            wallet_topic,
            SystemBusMessage::WalletUpdate {
                wallet: wallet.clone().into(),
            },
        );
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
