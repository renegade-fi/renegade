//! This file groups type definitions and helpers around global state that
//! is passed around throughout the code

use circuits::{
    native_helpers::compute_poseidon_hash,
    types::{balance::Balance, fee::Fee, order::Order},
    zk_gadgets::merkle::{MerkleOpening, MerkleRoot},
};
use crossbeam::channel::Sender;
use curve25519_dalek::scalar::Scalar;
use itertools::Itertools;
use libp2p::{
    identity::{self, Keypair},
    Multiaddr,
};
use num_bigint::BigUint;
use rand::{distributions::WeightedIndex, prelude::Distribution, thread_rng};
use std::{
    collections::HashMap,
    fmt::{Display, Formatter, Result as FmtResult},
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
    thread::Builder,
};
use termion::color;
use tokio::sync::{mpsc::UnboundedSender, oneshot};

use crate::{
    api::{
        gossip::{GossipOutbound, PubsubMessage},
        heartbeat::HeartbeatMessage,
        orderbook_management::{OrderBookManagementMessage, ORDER_BOOK_TOPIC},
    },
    gossip::types::{ClusterId, PeerInfo, WrappedPeerId},
    proof_generation::jobs::{ProofJob, ProofManagerJob, ValidCommitmentsBundle},
    state::orderbook::NetworkOrder,
    system_bus::SystemBus,
    types::SystemBusMessage,
    MERKLE_HEIGHT,
};

use super::{
    orderbook::{NetworkOrderBook, OrderIdentifier},
    peers::PeerIndex,
    priority::HandshakePriorityStore,
    wallet::{Wallet, WalletIndex},
};

// -----------------------
// | Constants and Types |
// -----------------------

/// An error emitted when order initialization fails
const ERR_ORDER_INIT_FAILED: &str = "order commitment initialization thread panic";
/// The name of the thread initialized to generate proofs of `VALID COMMITMENTS` at startup
const ORDER_INIT_THREAD: &str = "order-commitment-init";

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
    pub local_cluster_id: ClusterId,
    /// The listening address of the local relayer
    ///
    /// Despite being static after initialization, this value is
    /// set by the network manager, so we maintain a cross-worker
    /// reference
    pub local_addr: Shared<Multiaddr>,
    /// The list of wallets managed by the sending relayer
    wallet_index: Shared<WalletIndex>,
    /// The set of peers known to the sending relayer
    peer_index: Shared<PeerIndex>,
    /// The order book and indexing structure for orders in the network
    order_book: Shared<NetworkOrderBook>,
    /// A list of matched orders
    /// TODO: Remove this
    matched_order_pairs: Shared<Vec<(OrderIdentifier, OrderIdentifier)>>,
    /// Priorities for scheduling handshakes with each peer
    pub handshake_priorities: Shared<HandshakePriorityStore>,
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
        let peer_index = PeerIndex::new(local_peer_id);

        // Setup the order book
        let order_book = NetworkOrderBook::new(system_bus);

        Self {
            debug,
            local_peer_id,
            local_keypair,
            local_cluster_id: cluster_id,
            local_addr: new_shared(Multiaddr::empty()),
            wallet_index: new_shared(wallet_index),
            matched_order_pairs: new_shared(vec![]),
            peer_index: new_shared(peer_index),
            order_book: new_shared(order_book),
            handshake_priorities: new_shared(HandshakePriorityStore::new()),
        }
    }

    /// Initialize proofs of `VALID COMMITMENTS` for any locally managed orders
    ///
    /// At startup; if a relayer is initialized with wallets in its config, we generate
    /// proofs of `VALID COMMITMENTS` as a pre-requisite to entering them into match
    /// MPCs
    ///
    /// This method does not block, instead it spawns a thread to manage the process of
    /// updating the order state. For this reason, the method is defined as a static
    /// method instead of an instance method, so that a lock need not be held on the
    /// state the entire time
    pub fn initialize_order_proofs(
        &self,
        proof_manager_queue: Sender<ProofManagerJob>,
        network_sender: UnboundedSender<GossipOutbound>,
    ) {
        // Spawn the helpers in a thread
        let self_clone = self.clone();
        Builder::new()
            .name(ORDER_INIT_THREAD.to_string())
            .spawn(move || {
                self_clone.initialize_order_proof_helper(proof_manager_queue, network_sender)
            })
            .expect(ERR_ORDER_INIT_FAILED);
    }

    /// A helper passed as a callback to the threading logic in the caller
    fn initialize_order_proof_helper(
        &self,
        proof_manager_queue: Sender<ProofManagerJob>,
        network_sender: UnboundedSender<GossipOutbound>,
    ) {
        // Store a handle to the response channels for each proof; await them one by one
        let mut proof_response_channels = Vec::new();

        {
            // Iterate over all orders in all managed wallets and generate proofs
            let locked_wallet_index = self.read_wallet_index();
            for wallet in locked_wallet_index.get_all_wallets().iter() {
                for (order_id, order) in wallet.orders.iter() {
                    {
                        self.write_order_book().add_order(NetworkOrder::new(
                            *order_id,
                            self.local_cluster_id.clone(),
                            true, /* local */
                        ));
                    } // order_book lock released

                    if let Some((_, balance, fee, fee_balance)) =
                        locked_wallet_index.get_order_balance_and_fee(&wallet.wallet_id, order_id)
                    {
                        // Generate a merkle proof of inclusion for this wallet in the contract state
                        let (merkle_root, wallet_opening) = Self::generate_merkle_proof(wallet);

                        // Create a job and a response channel to get proofs back on
                        let job = ProofJob::ValidCommitments {
                            wallet: wallet.clone().into(),
                            wallet_opening,
                            order: order.clone(),
                            balance,
                            fee,
                            fee_balance,
                            sk_match: wallet.secret_keys.sk_match,
                            merkle_root,
                        };
                        let (response_sender, response_receiver) = oneshot::channel();

                        // Send a request to build a proof
                        proof_manager_queue
                            .send(ProofManagerJob {
                                type_: job,
                                response_channel: response_sender,
                            })
                            .unwrap();

                        // Store a handle to the response channel
                        proof_response_channels.push((*order_id, response_receiver));
                    } else {
                        println!("Skipping wallet validity proof; no balance and fee found");
                        continue;
                    }
                }
            }
        } // locked_wallet_index released

        // Await a proof response for each order then attach it to the order index entry
        for (order_id, receiver) in proof_response_channels.into_iter() {
            // Await a proof
            let proof_bundle: ValidCommitmentsBundle = receiver.blocking_recv().unwrap().into();

            // Update the local orderbook state
            self.read_order_book()
                .update_order_validity_proof(&order_id, proof_bundle.clone());

            // Gossip about the updated proof to the network
            let message = GossipOutbound::Pubsub {
                topic: ORDER_BOOK_TOPIC.to_string(),
                message: PubsubMessage::OrderBookManagement(
                    OrderBookManagementMessage::OrderProofUpdated {
                        order_id,
                        cluster: self.local_cluster_id.clone(),
                        proof: proof_bundle,
                    },
                ),
            };
            network_sender.send(message).unwrap()
        }
    }

    /// Generate a dummy Merkle proof for an order
    ///
    /// Returns a tuple of (dummy root, merkle opening)
    ///
    /// TODO: Replace this with a method that retrieves or has access to the on-chain Merkle state
    /// and creates a legitimate Merkle proof
    fn generate_merkle_proof(wallet: &Wallet) -> (MerkleRoot, MerkleOpening) {
        // For now, just assume the wallet is the zero'th entry in the tree, and
        // the rest of the tree is zeros
        let opening_elems = vec![Scalar::zero(); MERKLE_HEIGHT];
        let opening_indices = vec![Scalar::zero(); MERKLE_HEIGHT];

        // Compute the dummy root
        let mut curr_root = wallet.get_commitment();
        for sibling in opening_elems.iter() {
            curr_root = compute_poseidon_hash(&[curr_root, *sibling]);
        }

        (
            curr_root,
            MerkleOpening {
                elems: opening_elems,
                indices: opening_indices,
            },
        )
    }

    // -----------
    // | Getters |
    // -----------

    /// Get the local peer's ID
    pub fn local_peer_id(&self) -> WrappedPeerId {
        self.local_peer_id
    }

    /// Get the peer info for the local peer
    pub fn local_peer_info(&self) -> PeerInfo {
        self.read_peer_index()
            .get_peer_info(&self.local_peer_id)
            .unwrap()
    }

    /// Sample an order for handshake
    pub fn choose_handshake_order(&self) -> Option<OrderIdentifier> {
        // Read the set of orders that are verified and thereby ready for batch
        let verified_orders = { self.read_order_book().get_nonlocal_verified_orders() };
        if verified_orders.is_empty() {
            return None;
        }

        // Fetch the priorities for the verified orders
        let mut priorities = Vec::with_capacity(verified_orders.len());
        {
            let locked_priority_store = self.read_handshake_priorities();
            for order_id in verified_orders.iter() {
                let priority = locked_priority_store.get_order_priority(order_id);
                priorities.push(priority.get_effective_priority());
            }
        } // locked_priority_store released

        // Sample a random priority-weighted order from the result
        let mut rng = thread_rng();
        let distribution = WeightedIndex::new(&priorities).unwrap();
        Some(*verified_orders.get(distribution.sample(&mut rng)).unwrap())
    }

    /// Get the order, balance, and fee information for a given order_id
    pub fn get_order_balance_fee(
        &self,
        order_id: &OrderIdentifier,
    ) -> Option<(Order, Balance, Fee)> {
        let order_wallet = { self.read_wallet_index().get_wallet_for_order(order_id) }?;
        let (order, balance, fee, _) = self
            .read_wallet_index()
            .get_order_balance_and_fee(&order_wallet, order_id)?;

        Some((order, balance, fee))
    }

    /// Fetch the wallet randomness to attach to an order during the handshake
    pub fn get_randomness_for_order(&self, order_id: &OrderIdentifier) -> Option<BigUint> {
        // Use the randomness of the wallet that the order belongs to
        let locked_wallet_index = self.read_wallet_index();
        let wallet_id = locked_wallet_index.get_wallet_for_order(order_id)?;
        locked_wallet_index
            .read_wallet(&wallet_id)
            .map(|wallet| wallet.randomness.clone())
    }

    /// Get a peer in the cluster that manages the given order, used to dial during
    /// handshake scheduling
    pub fn get_peer_managing_order(&self, order_id: &OrderIdentifier) -> Option<WrappedPeerId> {
        // Get the cluster that manages this order
        let managing_cluster = { self.read_order_book().get_order_info(order_id)?.cluster };

        // Get a peer in this cluster
        self.read_peer_index()
            .sample_cluster_peer(&managing_cluster)
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

    // -----------
    // | Setters |
    // -----------

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
        let mut locked_peer_index = self.write_peer_index();
        for peer in peer_ids.iter() {
            // Skip this peer if peer info wasn't sent, or if their cluster auth signature doesn't verify
            if let Some(info) = peer_info.get(peer) && info.verify_cluster_auth_sig().is_ok() {
                // Record a dummy heartbeat to setup the initial state
                info.successful_heartbeat();
                locked_peer_index.add_peer(info.clone())
            } else {
                continue;
            }
        }
    }

    /// Expire a set of peers that have been determined to have failed
    pub fn remove_peer(&self, peer: &WrappedPeerId) {
        // Update the peer index
        self.write_peer_index().remove_peer(peer);
        // Update the replicas set for any wallets replicated by the expired peer
        self.read_wallet_index().remove_peer_replicas(peer);
    }

    /// Add an order to the book
    pub fn add_order(&self, order: NetworkOrder) {
        // Add the order to the book and to the priority store
        self.write_handshake_priorities()
            .new_order(order.id, order.cluster.clone());
        self.write_order_book().add_order(order);
    }

    /// Add wallets to the state as managed wallets
    ///
    /// This may happen at startup when a relayer advertises its presence to
    /// cluster peers; or when a new wallet is created on a remote cluster peer
    pub fn add_wallets(&self, wallets: Vec<Wallet>) {
        let mut new_orders = Vec::new();

        // Add all wallets to the index of locally managed wallets
        {
            let mut locked_wallet_index = self.write_wallet_index();
            for wallet in wallets.into_iter() {
                new_orders.append(&mut wallet.orders.keys().cloned().collect_vec());
                locked_wallet_index.add_wallet(wallet);
            }
        } // locked_wallet_index released

        // Add all new orders to the order book
        let mut locked_order_book = self.write_order_book();
        for order_id in new_orders.into_iter() {
            locked_order_book.add_order(NetworkOrder::new(
                order_id,
                self.local_cluster_id.clone(),
                true, /* local */
            ));
        }
    }

    /// Mark an order pair as matched, this is both for bookkeeping and for
    /// order state updates that are available to the frontend
    pub fn mark_order_pair_matched(&self, o1: OrderIdentifier, o2: OrderIdentifier) {
        // Remove the scheduling priorities for the orders
        let mut locked_handshake_priorities = self.write_handshake_priorities();
        locked_handshake_priorities.remove_order(&o1);
        locked_handshake_priorities.remove_order(&o2);

        // Mark the order pair as matched
        self.write_matched_order_pairs().push((o1, o2));
    }

    // -----------
    // | Locking |
    // -----------

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
    fn write_wallet_index(&self) -> RwLockWriteGuard<WalletIndex> {
        self.wallet_index
            .write()
            .expect("managed_wallets lock poisoned")
    }

    /// Acquire a read lock on `known_peers`
    pub fn read_peer_index(&self) -> RwLockReadGuard<PeerIndex> {
        self.peer_index.read().expect("known_peers lock poisoned")
    }

    /// Acquire a write lock on `known_peers`
    fn write_peer_index(&self) -> RwLockWriteGuard<PeerIndex> {
        self.peer_index.write().expect("known_peers lock poisoned")
    }

    /// Acquire a read lock on `order_book`
    /// TODO: Remove this lint allowance
    #[allow(unused)]
    pub fn read_order_book(&self) -> RwLockReadGuard<NetworkOrderBook> {
        self.order_book.read().expect("order_book lock poisoned")
    }

    /// Acquire a write lock on `order_book`
    /// TODO: Remove this lint allowance
    #[allow(unused)]
    fn write_order_book(&self) -> RwLockWriteGuard<NetworkOrderBook> {
        self.order_book.write().expect("order_book lock poisoned")
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
    fn write_matched_order_pairs(
        &self,
    ) -> RwLockWriteGuard<Vec<(OrderIdentifier, OrderIdentifier)>> {
        self.matched_order_pairs
            .write()
            .expect("matched_order_pairs lock poisoned")
    }

    /// Acquire a read lock on `handshake_priorities`
    pub fn read_handshake_priorities(&self) -> RwLockReadGuard<HandshakePriorityStore> {
        self.handshake_priorities
            .read()
            .expect("handshake_priorities lock poisoned")
    }

    /// Acquire a write lock on `handshake_priorities`
    fn write_handshake_priorities(&self) -> RwLockWriteGuard<HandshakePriorityStore> {
        self.handshake_priorities
            .write()
            .expect("handshake_priorities lock poisoned")
    }
}

/// The derivation from global state to heartbeat message
impl From<&RelayerState> for HeartbeatMessage {
    fn from(state: &RelayerState) -> Self {
        // Get a mapping from wallet ID to information
        let wallet_info = state.read_wallet_index().get_metadata_map();

        // Convert peer info keys to strings for serialization/deserialization
        let peer_info = state
            .read_peer_index()
            .get_info_map()
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect();

        // Get a list of all orders in the book
        let order_info = state.read_order_book().get_order_owner_pairs();

        HeartbeatMessage {
            managed_wallets: wallet_info,
            known_peers: peer_info,
            orders: order_info,
        }
    }
}

/// Display color for light green text
const LG: color::Fg<color::LightGreen> = color::Fg(color::LightGreen);
/// Display color for light yellow text
const LY: color::Fg<color::LightYellow> = color::Fg(color::LightYellow);
/// Display color for cyan text
const CY: color::Fg<color::Cyan> = color::Fg(color::Cyan);
/// Terminal control to reset text color
const RES: color::Fg<color::Reset> = color::Fg(color::Reset);

/// Display implementation for easy-to-read command line print-out
impl Display for RelayerState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_fmt(format_args!("{CY}Local Relayer State:{RES}\n",))?;
        f.write_fmt(format_args!(
            "\t{LG}Listening on:{RES} {}/p2p/{}\n",
            self.read_peer_index()
                .read_peer(&self.local_peer_id())
                .unwrap()
                .get_addr(),
            self.local_peer_id().0
        ))?;
        f.write_fmt(format_args!(
            "\t{LG}PeerId:{RES} {}\n",
            self.local_peer_id().0
        ))?;
        f.write_fmt(format_args!(
            "\t{LG}ClusterId:{RES} {:?}\n",
            self.local_cluster_id
        ))?;

        // Write wallet info to the format
        self.read_wallet_index().fmt(f)?;
        f.write_str("\n\n\n")?;

        // Write order information for locally managed orders
        self.read_order_book().fmt(f)?;
        f.write_str("\n\n")?;

        // Write historically matched orders to the format
        f.write_fmt(format_args!("\n\t{LG}Matched Order Pairs:{RES}\n",))?;
        for (o1, o2) in self.read_matched_order_pairs().iter() {
            f.write_fmt(format_args!("\t\t - {LY}({:?}, {:?}){RES}\n", o1, o2,))?;
        }

        f.write_str("\n\n\n")?;
        // Write the known peers to the format
        f.write_fmt(format_args!("\t{LG}Known Peers{LG}:\n",))?;
        self.peer_index.read().unwrap().fmt(f)?;
        f.write_str("\n\n")?;

        // Write the set of known cluster peers to the formatter
        f.write_fmt(format_args!(
            "\t{LG}Cluster Metadata{RES} (ID = {LY}{:?}{RES})\n",
            self.local_cluster_id,
        ))?;
        f.write_fmt(format_args!("\t\t{LY}Members{RES}: [\n",))?;
        for member in self
            .read_peer_index()
            .get_all_cluster_peers(&self.local_cluster_id)
        {
            f.write_fmt(format_args!("\t\t\t{}\n", member.0))?;
        }
        f.write_str("\t\t]")?;

        Ok(())
    }
}
