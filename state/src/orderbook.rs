//! The order book state primitive represents a cache of known orders in the
//! network
//!
//! Note that these orders are not necessarily locally managed orders; this
//! state element also holds orders known to be managed by other peers. This
//! allows the local node to take into account known outstanding orders when
//! scheduling handshakes with peers.
//!
//! As well, this state primitive provides a means by which to centralize the
//! collection of IoIs (indications of interest); which are partially revealing
//! elements of an order (e.g. volume, direction, base asset, etc). These are
//! also taken into account when scheduling handshakes

use circuit_types::wallet::Nullifier;
use common::{
    new_async_shared,
    types::{
        gossip::ClusterId,
        network_order::{NetworkOrder, NetworkOrderState},
        proof_bundles::{OrderValidityProofBundle, OrderValidityWitnessBundle},
        wallet::OrderIdentifier,
    },
    AsyncShared,
};
use constants::ORDER_STATE_CHANGE_TOPIC;
use external_api::bus_message::SystemBusMessage;
use futures::stream::{iter as to_stream, StreamExt};
use itertools::Itertools;
use job_types::handshake_manager::HandshakeExecutionJob;
use std::collections::{HashMap, HashSet};
use system_bus::SystemBus;
use tokio::sync::{mpsc::UnboundedSender as TokioSender, RwLockReadGuard, RwLockWriteGuard};
use uuid::Uuid;

/// The error emitted when enqueueing a job to the handshake manager fails
const ERR_MATCH_JOB_ENQUEUE: &str = "error enqueuing internal matching engine job";

/// Represents the order index, a collection of known orders allocated in the
/// network
#[derive(Clone, Debug)]
pub struct NetworkOrderBook {
    /// The mapping from order identifier to order information
    order_map: HashMap<OrderIdentifier, AsyncShared<NetworkOrder>>,
    /// A mapping from the wallet's public share nullifier to the set of orders
    /// in this wallet
    orders_by_nullifier: HashMap<Nullifier, AsyncShared<HashSet<OrderIdentifier>>>,
    /// A list of order IDs maintained locally
    local_orders: AsyncShared<HashSet<OrderIdentifier>>,
    /// The set of orders in the `Verified` state; i.e. ready to match
    verified_orders: AsyncShared<HashSet<OrderIdentifier>>,
    /// A producer to the handshake work queue, so that the orderbook may
    /// schedule internal matching engine jobs on newly verified orders
    handshake_job_queue: TokioSender<HandshakeExecutionJob>,
    /// A handle referencing the system bus to publish state transition events
    /// onto
    system_bus: SystemBus<SystemBusMessage>,
}

impl NetworkOrderBook {
    /// Construct the order book state primitive
    pub fn new(
        handshake_job_queue: TokioSender<HandshakeExecutionJob>,
        system_bus: SystemBus<SystemBusMessage>,
    ) -> Self {
        Self {
            order_map: HashMap::new(),
            orders_by_nullifier: HashMap::new(),
            local_orders: new_async_shared(HashSet::new()),
            verified_orders: new_async_shared(HashSet::new()),
            handshake_job_queue,
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
        public_share_nullifier: Nullifier,
    ) -> RwLockWriteGuard<HashSet<OrderIdentifier>> {
        self.orders_by_nullifier
            .entry(public_share_nullifier)
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

    /// Get the public share nullifier for a given order
    pub async fn get_nullifier(&self, order_id: &OrderIdentifier) -> Option<Nullifier> {
        self.read_order(order_id)
            .await
            .map(|order_info_locked| order_info_locked.public_share_nullifier)
    }

    /// Fetch all orders under a given nullifier
    pub async fn get_orders_by_nullifier(&self, nullifier: Nullifier) -> Vec<OrderIdentifier> {
        if let Some(set) = self.read_nullifier_order_set(&nullifier).await {
            set.iter().cloned().collect_vec()
        } else {
            Vec::new()
        }
    }

    /// Return whether the given locally managed order is ready to schedule
    /// handshakes on
    ///
    /// This amounts to validating that a copy of the validity proof and witness
    /// are stored locally
    pub async fn order_ready_for_handshake(&self, order_id: &OrderIdentifier) -> bool {
        self.read_order(order_id)
            .await
            .map_or(false, |order_info| order_info.ready_for_match())
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

    /// Return a list of all known order IDs in the book with clusters to
    /// contact for info
    pub async fn get_order_owner_pairs(&self) -> Vec<(OrderIdentifier, ClusterId)> {
        let mut pairs = Vec::new();
        for (order_id, info) in self.order_map.iter() {
            pairs.push((*order_id, info.read().await.cluster.clone()))
        }

        pairs
    }

    /// Returns true if the local node holds validity proofs (reblind and
    /// commitment) for the given order
    pub async fn has_validity_proofs(&self, order_id: &OrderIdentifier) -> bool {
        if let Some(order_info) = self.read_order(order_id).await {
            return order_info.validity_proofs.is_some();
        }

        false
    }

    /// Fetch a copy of the validity proofs for the given order, or `None` if
    /// the proofs are not locally stored
    pub async fn get_validity_proofs(
        &self,
        order_id: &OrderIdentifier,
    ) -> Option<OrderValidityProofBundle> {
        self.read_order(order_id).await?.validity_proofs.clone()
    }

    /// Returns true if the local node holds a copy of the witnesses for `VALID
    /// REBLIND` and `VALID COMMITMENTS` for the given order
    pub async fn has_validity_witness(&self, order_id: &OrderIdentifier) -> bool {
        if let Some(order_info) = self.read_order(order_id).await {
            return order_info.validity_proof_witnesses.is_some();
        }

        false
    }

    /// Fetch a copy of the witnesses used in the validity proofs for this order
    pub async fn get_validity_proof_witnesses(
        &self,
        order_id: &OrderIdentifier,
    ) -> Option<OrderValidityWitnessBundle> {
        self.read_order(order_id)
            .await?
            .validity_proof_witnesses
            .clone()
    }

    /// Fetch a copy of the local order book
    pub async fn get_order_book_snapshot(&self) -> HashMap<OrderIdentifier, NetworkOrder> {
        let mut res = HashMap::new();
        for order_id in self.order_map.keys() {
            let info = { self.read_order(order_id).await.unwrap().clone() };
            res.insert(*order_id, info);
        }

        res
    }

    // -----------
    // | Setters |
    // -----------

    /// Add an order to the book, necessarily this order is in the received
    /// state because we must fetch a validity proof to move it to verified
    pub async fn add_order(&mut self, order: NetworkOrder) {
        // If the order is local, add it to the local order list
        if order.local {
            self.write_local_orders().await.insert(order.id);
        }

        // If the order is verified already, add it to the list of verified orders
        if matches!(order.state, NetworkOrderState::Verified) {
            self.add_verified_order(order.id).await;
        }

        // Add an entry in the orders by nullifier index
        self.write_nullifier_order_set(order.public_share_nullifier)
            .await
            .insert(order.id);

        // Add an entry in the order index
        self.order_map
            .insert(order.id, new_async_shared(order.clone()));

        // Publish the new order to the system bus
        self.system_bus.publish(
            ORDER_STATE_CHANGE_TOPIC.to_string(),
            SystemBusMessage::NewOrder { order },
        )
    }

    /// Update the validity proofs for an order
    pub async fn update_order_validity_proofs(
        &mut self,
        order_id: &OrderIdentifier,
        proofs: OrderValidityProofBundle,
    ) {
        // If the order was previously indexed, remove its old nullifier
        if let Some(locked_order) = self.get_order_info(order_id).await {
            self.write_nullifier_order_set(locked_order.public_share_nullifier)
                .await
                .remove(order_id);
        }

        // Index by the public share nullifier seen in the proof, this is guaranteed
        // correct
        self.write_nullifier_order_set(proofs.reblind_proof.statement.original_shares_nullifier)
            .await
            .insert(*order_id);
        self.transition_verified(order_id, proofs).await;
    }

    /// Attach a set of validity proof witnesses to the local order state
    pub async fn attach_validity_proof_witness(
        &self,
        order_id: &OrderIdentifier,
        witnesses: OrderValidityWitnessBundle,
    ) {
        if let Some(mut locked_order) = self.write_order(order_id).await {
            locked_order.validity_proof_witnesses = Some(witnesses);
        }

        // Enqueue a job with the handshake manager to run the internal matching engine
        // on the newly verified order
        if self.order_ready_for_handshake(order_id).await {
            self.handshake_job_queue
                .send(HandshakeExecutionJob::InternalMatchingEngine { order: *order_id })
                .expect(ERR_MATCH_JOB_ENQUEUE);
        }
    }

    /// Add an order to the verified orders list
    async fn add_verified_order(&self, order_id: Uuid) {
        if !self.read_verified_orders().await.contains(&order_id) {
            self.write_verified_orders().await.insert(order_id);
        }
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

    /// Transitions the state of an order to the verified state
    #[allow(unused)]
    pub async fn transition_verified(
        &mut self,
        order_id: &OrderIdentifier,
        validity_proofs: OrderValidityProofBundle,
    ) {
        if let Some(mut order) = self.write_order(order_id).await {
            order.transition_verified(validity_proofs);
            self.add_verified_order(*order_id).await;

            // Enqueue a job with the handshake manager to run the internal matching engine
            // on
            if order.ready_for_match() {
                self.handshake_job_queue
                    .send(HandshakeExecutionJob::InternalMatchingEngine { order: order.id })
                    .expect(ERR_MATCH_JOB_ENQUEUE);
            }

            self.system_bus.publish(
                ORDER_STATE_CHANGE_TOPIC.to_string(),
                SystemBusMessage::OrderStateChange {
                    order: order.clone(),
                },
            );
        }
    }

    /// Transitions the state of an order from `Verified` to `Matched`
    #[allow(unused)]
    pub async fn transition_matched(&mut self, order_id: &OrderIdentifier, by_local_node: bool) {
        if let Some(mut order) = self.write_order(order_id).await {
            let prev_state = order.state;
            order.transition_matched(by_local_node);
            self.remove_verified_order(order_id).await;

            self.system_bus.publish(
                ORDER_STATE_CHANGE_TOPIC.to_string(),
                SystemBusMessage::OrderStateChange {
                    order: order.clone(),
                },
            );
        }
    }

    /// Transitions the state of an order to `Cancelled`
    #[allow(unused)]
    pub async fn transition_cancelled(&mut self, order_id: &OrderIdentifier) {
        if let Some(mut order) = self.write_order(order_id).await {
            let prev_state = order.state;
            order.transition_cancelled();
            self.remove_verified_order(order_id).await;

            self.system_bus.publish(
                ORDER_STATE_CHANGE_TOPIC.to_string(),
                SystemBusMessage::OrderStateChange {
                    order: order.clone(),
                },
            );
        }
    }
}
