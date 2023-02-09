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
    collections::HashMap,
    sync::{RwLockReadGuard, RwLockWriteGuard},
};
use uuid::Uuid;

use crate::proof_generation::jobs::ValidCommitmentsBundle;

use super::Shared;

/// Error message thrown when an order lock is poisoned
const ERR_ORDER_POISONED: &str = "order lock poisoned";

/// An identifier of an order used for caching
/// TODO: Update this with a commitment to an order, UUID for testing
pub type OrderIdentifier = Uuid;

/// Represents an order discovered either via gossip, or from within the local
/// node's managed wallets
#[derive(Clone, Debug)]
pub struct NetworkOrder {
    /// The identifier of the order
    id: OrderIdentifier,
    /// The state of the order via the local peer
    state: NetworkOrderState,
}

/// The state of a known order in the network
#[derive(Clone, Debug)]
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
    Verified {
        /// The proof of `VALID COMMITMENTS` that has been verified by the local node
        /// TODO: Update this proof with a fleshed out bundle
        valid_commit_proof: ValidCommitmentsBundle,
    },
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

/// Represents the order index, a collection of known orders allocated in the network
#[derive(Clone, Debug)]
pub struct NetworkOrderBook {
    /// The mapping from order identifier to order information
    order_map: HashMap<OrderIdentifier, Shared<NetworkOrder>>,
}

impl NetworkOrderBook {
    /// Construct the order book state primitive
    pub fn new() -> Self {
        Self {
            order_map: HashMap::new(),
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

    // -----------
    // | Setters |
    // -----------
}
