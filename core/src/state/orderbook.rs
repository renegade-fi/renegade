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

use serde::{Deserialize, Serialize};
use std::{
    collections::{hash_map::Entry, HashMap},
    fmt::{Display, Formatter, Result as FmtResult},
    sync::{RwLockReadGuard, RwLockWriteGuard},
};
use termion::color;
use uuid::Uuid;

use crate::{
    proof_generation::jobs::ValidCommitmentsBundle,
    system_bus::SystemBus,
    types::{SystemBusMessage, ORDER_STATE_CHANGE_TOPIC},
};

use super::{new_shared, Shared};

/// Error message emitted when the local order lock is poisoned
const ERR_LOCAL_ORDERS_POISONED: &str = "local order lock poisoned";
/// Error message emitted when an order lock is poisoned
const ERR_ORDER_POISONED: &str = "order lock poisoned";

/// An identifier of an order used for caching
/// TODO: Update this with a commitment to an order, UUID for testing
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
#[derive(Clone, Debug)]
pub struct NetworkOrder {
    /// The identifier of the order
    pub id: OrderIdentifier,
    /// Whether or not the order is a locally managed order
    pub local: bool,
    /// The state of the order via the local peer
    pub state: NetworkOrderState,
    /// The proof of `VALID COMMITMENTS` that has been verified by the local node
    /// TODO: Update this proof with a fleshed out bundle
    valid_commit_proof: Option<ValidCommitmentsBundle>,
}

impl NetworkOrder {
    /// Create a new order in the `Received` state
    pub fn new(order_id: OrderIdentifier, local: bool) -> Self {
        Self {
            id: order_id,
            local,
            state: NetworkOrderState::Received,
            valid_commit_proof: None,
        }
    }

    /// Transitions the state of an order from `Received` to `Verified` by
    /// attaching a proof of `VALID COMMITMENTS` to the order
    pub fn attach_commitment_proof(&mut self, proof: ValidCommitmentsBundle) {
        self.state = NetworkOrderState::Verified;
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
    }

    /// Transitions the state of an order to `Pruned`
    pub(self) fn transition_pruned(&mut self) {
        self.state = NetworkOrderState::Pruned;
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
    order_map: HashMap<OrderIdentifier, Shared<NetworkOrder>>,
    /// A list of order IDs maintained locally
    local_orders: Shared<Vec<OrderIdentifier>>,
    /// A handle referencing the system bus to publish state transition events onto
    system_bus: SystemBus<SystemBusMessage>,
}

impl NetworkOrderBook {
    /// Construct the order book state primitive
    pub fn new(system_bus: SystemBus<SystemBusMessage>) -> Self {
        Self {
            order_map: HashMap::new(),
            local_orders: new_shared(Vec::new()),
            system_bus,
        }
    }

    // -----------
    // | Locking |
    // -----------

    /// Acquire a read lock on an order
    pub fn read_order(&self, order_id: &OrderIdentifier) -> Option<RwLockReadGuard<NetworkOrder>> {
        Some(
            self.order_map
                .get(order_id)?
                .read()
                .expect(ERR_ORDER_POISONED),
        )
    }

    /// Acquire a write lock on an order
    pub fn write_order(
        &self,
        order_id: &OrderIdentifier,
    ) -> Option<RwLockWriteGuard<NetworkOrder>> {
        Some(
            self.order_map
                .get(order_id)?
                .write()
                .expect(ERR_ORDER_POISONED),
        )
    }

    // -----------
    // | Getters |
    // -----------

    /// Whether or not the given order is already indexed
    pub fn contains_order(&self, order_id: &OrderIdentifier) -> bool {
        self.order_map.contains_key(order_id)
    }

    /// Returns whether or not the local node holds a proof of `VALID COMMITMENTS`
    /// for the given order
    pub fn has_validity_proof(&self, order_id: &OrderIdentifier) -> bool {
        if let Some(order_info) = self.read_order(order_id) {
            return order_info.valid_commit_proof.is_some();
        }

        false
    }

    /// Fetch a copy of the validity proof for the given order, or `None` if a proof
    /// is not locally stored
    pub fn get_validity_proof(&self, order_id: &OrderIdentifier) -> Option<ValidCommitmentsBundle> {
        self.read_order(order_id)?.valid_commit_proof.clone()
    }

    // -----------
    // | Setters |
    // -----------

    /// Add an order to the book, necessarily this order is in the received state because
    /// we must fetch a validity proof to move it to verified
    pub fn add_order(&mut self, mut order: NetworkOrder) {
        // If the order is local, add it to the local order list
        if order.local {
            self.local_orders
                .write()
                .expect(ERR_LOCAL_ORDERS_POISONED)
                .push(order.id)
        }

        // Add an entry in the order index
        self.order_map.insert(order.id, new_shared(order));
    }

    /// Update the validity proof for an order
    pub fn update_order_validity_proof(
        &self,
        order_id: &OrderIdentifier,
        proof: ValidCommitmentsBundle,
    ) {
        if let Some(mut locked_order) = self.write_order(order_id) {
            locked_order.attach_commitment_proof(proof);
        }
    }

    // --------------------------
    // | Order State Transition |
    // --------------------------

    /// Transitions the state of an order back to the received state, this drops
    /// the existing proof of `VALID COMMITMENTS`
    pub fn transition_order_received(&mut self, order_id: &OrderIdentifier) {
        if let Some(mut order) = self.write_order(order_id) {
            let prev_state = order.state;
            order.transition_received();

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
    pub fn transition_verified(
        &mut self,
        order_id: &OrderIdentifier,
        proof: ValidCommitmentsBundle,
    ) {
        if let Some(mut order) = self.write_order(order_id) {
            let prev_state = order.state;
            order.transition_verified(proof);

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
    pub fn transition_matched(&mut self, order_id: &OrderIdentifier, by_local_node: bool) {
        if let Some(mut order) = self.write_order(order_id) {
            let prev_state = order.state;
            order.transition_matched(by_local_node);

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
    pub fn transition_cancelled(&mut self, order_id: &OrderIdentifier) {
        if let Some(mut order) = self.write_order(order_id) {
            let prev_state = order.state;
            order.transition_cancelled();

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
    pub fn transition_pruned(&mut self, order_id: &OrderIdentifier) {
        if let Some(mut order) = self.write_order(order_id) {
            let prev_state = order.state;
            order.transition_pruned();

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

/// Display color for light green text
const LG: color::Fg<color::LightGreen> = color::Fg(color::LightGreen);
/// Display color for light yellow text
const LY: color::Fg<color::LightYellow> = color::Fg(color::LightYellow);
/// Display color for cyan text
const CY: color::Fg<color::Cyan> = color::Fg(color::Cyan);
/// Terminal control to reset text color
const RES: color::Fg<color::Reset> = color::Fg(color::Reset);

impl Display for NetworkOrderBook {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_fmt(format_args!("\n\t{LG}Order Book:{RES}\n",))?;

        // Loop over the locally managed orders and print info
        for order_id in self.order_map.keys() {
            let order_info = self.read_order(order_id).unwrap();
            // Write the order_id
            f.write_fmt(format_args!(
                "\t\t- {LY}{}{RES} ({}): {CY}{}{RES}\n",
                order_id,
                if order_info.local {
                    "local"
                } else {
                    "non-local"
                },
                order_info.state,
            ));
        }

        Ok(())
    }
}
