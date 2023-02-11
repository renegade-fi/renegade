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

use std::{
    collections::{hash_map::Entry, HashMap},
    fmt::{Display, Formatter, Result as FmtResult},
    sync::{RwLockReadGuard, RwLockWriteGuard},
};
use termion::color;
use uuid::Uuid;

use crate::proof_generation::jobs::ValidCommitmentsBundle;

use super::{new_shared, Shared};

/// Error message emitted when the local order lock is poisoned
const ERR_LOCAL_ORDERS_POISONED: &str = "local order lock poisoned";
/// Error message emitted when an order lock is poisoned
const ERR_ORDER_POISONED: &str = "order lock poisoned";

/// An identifier of an order used for caching
/// TODO: Update this with a commitment to an order, UUID for testing
pub type OrderIdentifier = Uuid;

/// The state of a known order in the network
#[derive(Clone, Debug, PartialEq, Eq)]
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
        assert_eq!(
            self.state,
            NetworkOrderState::Received,
            "order must be in received state to attach proof"
        );

        self.state = NetworkOrderState::Verified;
        self.valid_commit_proof = Some(proof);
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
}

impl NetworkOrderBook {
    /// Construct the order book state primitive
    pub fn new() -> Self {
        Self {
            order_map: HashMap::new(),
            local_orders: new_shared(Vec::new()),
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

    /// Returns whether or not the local node holds a proof of `VALID COMMITMENTS`
    /// for the given order
    pub fn has_validity_proof(&self, order_id: &OrderIdentifier) -> bool {
        if let Some(order_info) = self.read_order(order_id) {
            return order_info.valid_commit_proof.is_some();
        }

        false
    }

    // -----------
    // | Setters |
    // -----------

    /// Add an order to the book
    pub fn add_order(&mut self, order: NetworkOrder) {
        // Do nothing if the order is already indexed, state updates should come from
        // separate methods
        if self.order_map.contains_key(&order.id) {
            return;
        }

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
}

impl Display for NetworkOrderBook {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_fmt(format_args!(
            "\n\t{}Locally Managed Order State:{}\n",
            color::Fg(color::LightGreen),
            color::Fg(color::Reset)
        ))?;

        // Loop over the locally managed orders and print info
        for order_id in self.local_orders.read().unwrap().iter() {
            let order_info = self.read_order(order_id).unwrap();
            // Write the order_id
            f.write_fmt(format_args!(
                "\t\t- {}{}{}: {}{}{}",
                color::Fg(color::LightYellow),
                order_id,
                color::Fg(color::Reset),
                color::Fg(color::Cyan),
                order_info.state,
                color::Fg(color::Reset)
            ));
        }

        Ok(())
    }
}
