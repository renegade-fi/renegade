//! The order book state primitive represents a cache of known orders in the network
//!
//! Note that these orders are not necessarily locally managed orders; this state
//! element also holds orders known to be managed by other peers. This allows the
//! local node to take into account known outstanding orders when scheduling
//! handshakes with peers.
//!
//! As well, this state primitive provides a means by which to centralize the collection
//! of IoIs (indications of interest); which are partially revealing elements of an
//! order (e.g. volume, direction, base asset, etc). These are also taken into account
//! when scheduling handshakes

// TODO: Remove this lint allowance
#![allow(unused)]

use circuits::{types::wallet::Nullifier, zk_circuits::valid_commitments::ValidCommitmentsWitness};
use futures::stream::{futures_unordered::FuturesUnordered, iter as to_stream, StreamExt};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    fmt::{Display, Formatter, Result as FmtResult},
};
use tokio::sync::{RwLockReadGuard, RwLockWriteGuard};
use uuid::Uuid;

use crate::{
    gossip::types::{ClusterId, WrappedPeerId},
    proof_generation::jobs::ValidCommitmentsBundle,
    system_bus::SystemBus,
    types::{SizedValidCommitmentsWitness, SystemBusMessage, ORDER_STATE_CHANGE_TOPIC},
};

use super::{new_async_shared, AsyncShared};

/// Error message emitted when the local order lock is poisoned
const ERR_LOCAL_ORDERS_POISONED: &str = "local order lock poisoned";
/// Error message emitted when an order lock is poisoned
const ERR_ORDER_POISONED: &str = "order lock poisoned";
/// Error message emitted when the nullifier index is poisoned
const ERR_NULLIFIER_INDEX_POISONED: &str = "orderbook nullifier index poisoned";
/// Error message emitted when the verified orders set lock is poisoned
const ERR_VERIFIED_ORDERS_POISONED: &str = "verified orders lock poisoned";

/// An identifier of an order used for caching
pub type OrderIdentifier = Uuid;

/// The state of a known order in the network
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum NetworkOrderState {
    /// The received state indicates that the local node knows about the order, but
    /// has not received a proof of `VALID COMMITMENTS` to indicate that this order
    /// is a valid member of the state tree
    ///
    /// Orders in the received state cannot yet be matched against
    Received,
    /// The verified state indicates that a proof of `VALID COMMITMENTS` has been received
    /// and verified by the local node
    ///
    /// Orders in the Verified state are ready to be matched
    Verified,
    /// The matched state indicates that this order is known to be matched, not necessarily
    /// by the local node
    Matched {
        /// Whether or not this was a match by the local node
        by_local_node: bool,
    },
    /// A cancelled order is invalidated because a nullifier for the wallet was submitted
    /// on-chain
    Cancelled,
    /// A pruned order was valid, but the originating relayer is not contactable, the local
    /// node places an order in this state and allows some time for the originating relayer's
    /// cluster peers to pick up the order and begin shopping it around the network
    Pruned,
}

/// Represents an order discovered either via gossip, or from within the local
/// node's managed wallets
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkOrder {
    /// The identifier of the order
    pub id: OrderIdentifier,
    /// The match nullifier of the containing wallet
    pub match_nullifier: Nullifier,
    /// Whether or not the order is managed locally, this does not imply that the owner
    /// field is the same as the local peer's ID. For simplicity the owner field is the
    /// relayer that originated the order. If the owner is a cluster peer, then the local
    /// node may have local = True, with `owner` as a different node
    pub local: bool,
    /// The cluster known to manage the given order
    pub cluster: ClusterId,
    /// The state of the order via the local peer
    pub state: NetworkOrderState,
    /// The proof of `VALID COMMITMENTS` that has been verified by the local node
    pub valid_commit_proof: Option<ValidCommitmentsBundle>,
    /// The witness to the proof of `VALID COMMITMENTS`, this is only stored for orders that
    /// the local node directly manages
    ///
    /// Skip serialization to avoid sending witness, the serialized type will have `None` in place
    #[serde(skip)]
    pub valid_commit_witness: Option<SizedValidCommitmentsWitness>,
}

impl NetworkOrder {
    /// Create a new order in the `Received` state
    pub fn new(
        order_id: OrderIdentifier,
        match_nullifier: Nullifier,
        cluster: ClusterId,
        local: bool,
    ) -> Self {
        Self {
            id: order_id,
            match_nullifier,
            local,
            cluster,
            state: NetworkOrderState::Received,
            valid_commit_proof: None,
            valid_commit_witness: None,
        }
    }

    /// Transitions the state of an order from `Received` to `Verified` by
    /// attaching a proof of `VALID COMMITMENTS` to the order
    pub(self) fn attach_commitment_proof(&mut self, proof: ValidCommitmentsBundle) {
        self.state = NetworkOrderState::Verified;
        self.match_nullifier = proof.statement.nullifier;
        self.valid_commit_proof = Some(proof);
    }

    /// The following state transition methods are made module private because we prefer
    /// that access flow through the parent (`OrderBook`) object. This object has a reference
    /// to the system bus for internal events to be published

    /// Transitions the state of an order back to the received state, this drops
    /// the existing proof of `VALID COMMITMENTS`
    pub(self) fn transition_received(&mut self) {
        self.state = NetworkOrderState::Received;
    }

    /// Transitions the state of an order to the verified state
    pub(self) fn transition_verified(&mut self, proof: ValidCommitmentsBundle) {
        assert_eq!(
            self.state,
            NetworkOrderState::Received,
            "only orders in Received state may become Verified"
        );
        self.attach_commitment_proof(proof);
    }

    /// Transitions the state of an order from `Verified` to `Matched`
    pub(self) fn transition_matched(&mut self, by_local_node: bool) {
        assert_eq!(
            self.state,
            NetworkOrderState::Verified,
            "order must be in Verified state to transition to Matched"
        );
        self.state = NetworkOrderState::Matched { by_local_node };
    }

    /// Transitions the state of an order to `Cancelled`
    pub(self) fn transition_cancelled(&mut self) {
        self.state = NetworkOrderState::Cancelled;

        // We no longer need the validity proof (if it exists)
        // so it is safe to drop
        self.valid_commit_proof = None;
        self.valid_commit_witness = None;
    }

    /// Transitions the state of an order to `Pruned`
    pub(self) fn transition_pruned(&mut self) {
        self.state = NetworkOrderState::Pruned;

        // We no longer need the validity proof (if it exists)
        // so it is safe to drop
        self.valid_commit_proof = None;
        self.valid_commit_witness = None;
    }
}

/// Display implementation that ignores enum struct values
impl Display for NetworkOrderState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            NetworkOrderState::Received => f.write_str("Received"),
            NetworkOrderState::Verified { .. } => f.write_str("Verified"),
            NetworkOrderState::Matched { .. } => f.write_str("Matched"),
            NetworkOrderState::Cancelled => f.write_str("Cancelled"),
            NetworkOrderState::Pruned => f.write_str("Pruned"),
        }
    }
}

/// Represents the order index, a collection of known orders allocated in the network
#[derive(Clone, Debug)]
pub struct NetworkOrderBook {
    /// The mapping from order identifier to order information
    order_map: HashMap<OrderIdentifier, AsyncShared<NetworkOrder>>,
    /// A mapping from the wallet match nullifier to the order
    orders_by_nullifier: HashMap<Nullifier, AsyncShared<HashSet<OrderIdentifier>>>,
    /// A list of order IDs maintained locally
    local_orders: AsyncShared<HashSet<OrderIdentifier>>,
    /// The set of orders in the `Verified` state; i.e. ready to match
    verified_orders: AsyncShared<HashSet<OrderIdentifier>>,
    /// A handle referencing the system bus to publish state transition events onto
    system_bus: SystemBus<SystemBusMessage>,
}

impl NetworkOrderBook {
    /// Construct the order book state primitive
    pub fn new(system_bus: SystemBus<SystemBusMessage>) -> Self {
        Self {
            order_map: HashMap::new(),
            orders_by_nullifier: HashMap::new(),
            local_orders: new_async_shared(HashSet::new()),
            verified_orders: new_async_shared(HashSet::new()),
            system_bus,
        }
    }

    // -----------
    // | Locking |
    // -----------

    /// Acquire a read lock on an order
    pub async fn read_order(
        &self,
        order_id: &OrderIdentifier,
    ) -> Option<RwLockReadGuard<NetworkOrder>> {
        Some(self.order_map.get(order_id)?.read().await)
    }

    /// Acquire a read lock on the verified orders
    pub async fn read_verified_orders(&self) -> RwLockReadGuard<HashSet<OrderIdentifier>> {
        self.verified_orders.read().await
    }

    /// Acquire a read lock on the locally managed orders
    pub async fn read_local_orders(&self) -> RwLockReadGuard<HashSet<OrderIdentifier>> {
        self.local_orders.read().await
    }

    /// Acquire a write lock on an order
    pub async fn write_order(
        &self,
        order_id: &OrderIdentifier,
    ) -> Option<RwLockWriteGuard<NetworkOrder>> {
        Some(self.order_map.get(order_id)?.write().await)
    }

    /// Acquire a write lock on the verified orders
    pub async fn write_verified_orders(&self) -> RwLockWriteGuard<HashSet<OrderIdentifier>> {
        self.verified_orders.write().await
    }

    /// Acquire a write lock on the locally managed orders
    pub async fn write_local_orders(&self) -> RwLockWriteGuard<HashSet<OrderIdentifier>> {
        self.local_orders.write().await
    }

    /// Acquire a read lock on an order by nullifier set
    pub async fn read_nullifier_order_set(
        &self,
        nullifier: &Nullifier,
    ) -> Option<RwLockReadGuard<HashSet<OrderIdentifier>>> {
        if let Some(locked_orders) = self.orders_by_nullifier.get(nullifier) {
            Some(locked_orders.read().await)
        } else {
            None
        }
    }

    /// Acquire a write lock on an order by nullifier set
    pub async fn write_nullifier_order_set(
        &mut self,
        match_nullifier: Nullifier,
    ) -> RwLockWriteGuard<HashSet<OrderIdentifier>> {
        self.orders_by_nullifier
            .entry(match_nullifier)
            .or_insert_with(|| new_async_shared(HashSet::new()))
            .write()
            .await
    }

    // -----------
    // | Getters |
    // -----------

    /// Whether or not the given order is already indexed
    pub fn contains_order(&self, order_id: &OrderIdentifier) -> bool {
        self.order_map.contains_key(order_id)
    }

    /// Fetch the info for an order if it is stored
    pub async fn get_order_info(&self, order_id: &OrderIdentifier) -> Option<NetworkOrder> {
        if let Some(order_info_locked) = self.order_map.get(order_id) {
            Some(order_info_locked.read().await.clone())
        } else {
            None
        }
    }

    /// Fetch the match nullifier for an order
    pub async fn get_match_nullifier(&self, order_id: &OrderIdentifier) -> Option<Nullifier> {
        self.read_order(order_id)
            .await?
            .valid_commit_proof
            .as_ref()
            .map(|proof| proof.statement.nullifier)
    }

    /// Fetch all orders under a given nullifier
    pub async fn get_orders_by_nullifier(&self, nullifier: Nullifier) -> Vec<OrderIdentifier> {
        if let Some(set) = self.read_nullifier_order_set(&nullifier).await {
            set.iter().cloned().collect_vec()
        } else {
            Vec::new()
        }
    }

    /// Fetch all the verified orders in the order book
    pub async fn get_verified_orders(&self) -> Vec<OrderIdentifier> {
        self.read_verified_orders()
            .await
            .clone()
            .into_iter()
            .collect_vec()
    }

    /// Return whether the given locally managed order is ready to schedule handshakes on
    ///
    /// This amounts to validating that a copy of the validity proof and witness are stored
    /// locally
    pub async fn order_ready_for_handshake(&self, order_id: &OrderIdentifier) -> bool {
        self.has_validity_proof(order_id).await && self.has_validity_witness(order_id).await
    }

    /// Fetch a list of locally managed orders for which
    pub async fn get_local_scheduleable_orders(&self) -> Vec<OrderIdentifier> {
        let locked_verified_orders = self.read_verified_orders().await;
        let locked_local_orders = self.read_local_orders().await;

        // Get the set of local, verified orders
        let local_verified_orders = locked_verified_orders
            .intersection(&locked_local_orders)
            .cloned()
            .collect_vec();

        // Filter out those for which the local node does not have a copy of the witness
        to_stream(local_verified_orders)
            .filter_map(|order_id| async move {
                if self.has_validity_witness(&order_id).await {
                    Some(order_id)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .await
    }

    /// Fetch all the non-locally managed, verified orders
    ///
    /// Used for choosing orders to schedule handshakes on
    pub async fn get_nonlocal_verified_orders(&self) -> Vec<OrderIdentifier> {
        let locked_verified_orders = self.read_verified_orders().await;
        let locked_local_orders = self.read_local_orders().await;

        locked_verified_orders
            .difference(&locked_local_orders)
            .cloned()
            .collect_vec()
    }

    /// Return a list of all known order IDs in the book with clusters to contact for info
    pub async fn get_order_owner_pairs(&self) -> Vec<(OrderIdentifier, ClusterId)> {
        let mut pairs = Vec::new();
        for (order_id, info) in self.order_map.iter() {
            pairs.push((*order_id, info.read().await.cluster.clone()))
        }

        pairs
    }

    /// Returns whether or not the local node holds a proof of `VALID COMMITMENTS`
    /// for the given order
    pub async fn has_validity_proof(&self, order_id: &OrderIdentifier) -> bool {
        if let Some(order_info) = self.read_order(order_id).await {
            return order_info.valid_commit_proof.is_some();
        }

        false
    }

    /// Fetch a copy of the validity proof for the given order, or `None` if a proof
    /// is not locally stored
    pub async fn get_validity_proof(
        &self,
        order_id: &OrderIdentifier,
    ) -> Option<ValidCommitmentsBundle> {
        self.read_order(order_id).await?.valid_commit_proof.clone()
    }

    /// Returns whether the local node holds a witness to a the proof of `VALID COMMITMENTS`
    /// for the given order
    pub async fn has_validity_witness(&self, order_id: &OrderIdentifier) -> bool {
        if let Some(order_info) = self.read_order(order_id).await {
            return order_info.valid_commit_witness.is_some();
        }

        false
    }

    /// Fetch a copy of the witness to the validity proof if one exists
    pub async fn get_validity_proof_witness(
        &self,
        order_id: &OrderIdentifier,
    ) -> Option<SizedValidCommitmentsWitness> {
        self.read_order(order_id)
            .await?
            .valid_commit_witness
            .clone()
    }

    /// Fetch a copy of the local order book
    pub async fn get_order_book_snapshot(&self) -> HashMap<OrderIdentifier, NetworkOrder> {
        let mut res = HashMap::new();
        for order_id in self.order_map.keys() {
            let mut info = { self.read_order(order_id).await.unwrap().clone() };
            res.insert(*order_id, info);
        }

        res
    }

    // -----------
    // | Setters |
    // -----------

    /// Add an order to the book, necessarily this order is in the received state because
    /// we must fetch a validity proof to move it to verified
    pub async fn add_order(&mut self, mut order: NetworkOrder) {
        // If the order is local, add it to the local order list
        if order.local {
            self.write_local_orders().await.insert(order.id);
        }

        // If the order is verified already, add it to the list of verified orders
        if matches!(order.state, NetworkOrderState::Verified) {
            self.add_verified_order(order.id).await;
        }

        // Add an entry in the orders by nullifier index
        self.write_nullifier_order_set(order.match_nullifier)
            .await
            .insert(order.id);

        // Add an entry in the order index
        self.order_map.insert(order.id, new_async_shared(order));
    }

    /// Update the validity proof for an order
    pub async fn update_order_validity_proof(
        &mut self,
        order_id: &OrderIdentifier,
        proof: ValidCommitmentsBundle,
    ) {
        // Index by the match nullifier seen in the proof, this is guaranteed correct
        self.write_nullifier_order_set(proof.statement.nullifier)
            .await
            .insert(*order_id);

        if let Some(mut locked_order) = self.write_order(order_id).await {
            locked_order.attach_commitment_proof(proof);
        }

        self.add_verified_order(*order_id).await;
    }

    /// Attach a validity proof witness to the local order state
    pub async fn attach_validity_proof_witness(
        &self,
        order_id: &OrderIdentifier,
        witness: SizedValidCommitmentsWitness,
    ) {
        if let Some(mut locked_order) = self.write_order(order_id).await {
            locked_order.valid_commit_witness = Some(witness);
        }
    }

    /// Add an order to the verified orders list
    async fn add_verified_order(&self, order_id: Uuid) {
        if !self.read_verified_orders().await.contains(&order_id) {
            self.write_verified_orders().await.insert(order_id);
        }

        let orders = self.read_verified_orders().await.clone();
    }

    /// Remove an order from the verified orders list
    async fn remove_verified_order(&self, order_id: &Uuid) {
        if self.verified_orders.read().await.contains(order_id) {
            self.verified_orders.write().await.remove(order_id);
        }
    }

    // --------------------------
    // | Order State Transition |
    // --------------------------

    /// Transitions the state of an order back to the received state, this drops
    /// the existing proof of `VALID COMMITMENTS`
    pub async fn transition_order_received(&mut self, order_id: &OrderIdentifier) {
        if let Some(mut order) = self.write_order(order_id).await {
            let prev_state = order.state;
            order.transition_received();

            self.remove_verified_order(order_id);

            self.system_bus.publish(
                ORDER_STATE_CHANGE_TOPIC.to_string(),
                SystemBusMessage::OrderStateChange {
                    order_id: *order_id,
                    prev_state,
                    new_state: order.state,
                },
            );
        }
    }

    /// Transitions the state of an order to the verified state
    pub async fn transition_verified(
        &mut self,
        order_id: &OrderIdentifier,
        proof: ValidCommitmentsBundle,
    ) {
        if let Some(mut order) = self.write_order(order_id).await {
            let prev_state = order.state;
            order.transition_verified(proof);

            self.add_verified_order(*order_id).await;

            self.system_bus.publish(
                ORDER_STATE_CHANGE_TOPIC.to_string(),
                SystemBusMessage::OrderStateChange {
                    order_id: *order_id,
                    prev_state,
                    new_state: order.state,
                },
            );
        }
    }

    /// Transitions the state of an order from `Verified` to `Matched`
    pub async fn transition_matched(&mut self, order_id: &OrderIdentifier, by_local_node: bool) {
        if let Some(mut order) = self.write_order(order_id).await {
            let prev_state = order.state;
            order.transition_matched(by_local_node);

            self.remove_verified_order(order_id).await;

            self.system_bus.publish(
                ORDER_STATE_CHANGE_TOPIC.to_string(),
                SystemBusMessage::OrderStateChange {
                    order_id: *order_id,
                    prev_state,
                    new_state: order.state,
                },
            );
        }
    }

    /// Transitions the state of an order to `Cancelled`
    pub async fn transition_cancelled(&mut self, order_id: &OrderIdentifier) {
        if let Some(mut order) = self.write_order(order_id).await {
            let prev_state = order.state;
            order.transition_cancelled();

            self.remove_verified_order(order_id).await;

            self.system_bus.publish(
                ORDER_STATE_CHANGE_TOPIC.to_string(),
                SystemBusMessage::OrderStateChange {
                    order_id: *order_id,
                    prev_state,
                    new_state: order.state,
                },
            );
        }
    }

    /// Transitions the state of an order to `Pruned`
    pub async fn transition_pruned(&mut self, order_id: &OrderIdentifier) {
        if let Some(mut order) = self.write_order(order_id).await {
            let prev_state = order.state;
            order.transition_pruned();

            self.remove_verified_order(order_id).await;

            self.system_bus.publish(
                ORDER_STATE_CHANGE_TOPIC.to_string(),
                SystemBusMessage::OrderStateChange {
                    order_id: *order_id,
                    prev_state,
                    new_state: order.state,
                },
            );
        }
    }
}
