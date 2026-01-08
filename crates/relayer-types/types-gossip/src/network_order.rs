//! Type definitions for orders seen "from the network", i.e. where private
//! information about the order is not known

#![cfg_attr(feature = "rkyv", allow(missing_docs))]

use std::fmt::{Display, Formatter, Result as FmtResult};

use circuit_types::Nullifier;
#[cfg(feature = "rkyv")]
use darkpool_types::rkyv_remotes::ScalarDef;
#[cfg(feature = "rkyv")]
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};
use types_account::OrderId;
use util::get_current_time_millis;

use crate::ClusterId;

/// The default priority for a cluster
pub const CLUSTER_DEFAULT_PRIORITY: u32 = 1;
/// The default priority for an order
pub const ORDER_DEFAULT_PRIORITY: u32 = 1;

/// The state of a known order in the network
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "rkyv", derive(Archive, RkyvSerialize, RkyvDeserialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug), attr(allow(missing_docs))))]
#[allow(clippy::large_enum_variant)]
pub enum NetworkOrderState {
    /// The received state indicates that the local node knows about the order,
    /// but has not received a proof of `VALID COMMITMENTS` to indicate that
    /// this order is a valid member of the state tree
    ///
    /// Orders in the received state cannot yet be matched against
    Received,
    /// The verified state indicates that a proof of `VALID COMMITMENTS` has
    /// been received and verified by the local node
    ///
    /// Orders in the Verified state are ready to be matched
    Verified,
    /// The matched state indicates that this order is known to be matched, not
    /// necessarily by the local node
    Matched {
        /// Whether or not this was a match by the local node
        by_local_node: bool,
    },
    /// A cancelled order is invalidated because a nullifier for the wallet was
    /// submitted on-chain
    Cancelled,
}

/// Represents an order discovered either via gossip, or from within the local
/// node's managed wallets
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "rkyv", derive(Archive, RkyvSerialize, RkyvDeserialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug), attr(allow(missing_docs))))]
pub struct NetworkOrder {
    /// The identifier of the order
    pub id: OrderId,
    /// The nullifier of the order's intent
    #[cfg_attr(feature = "rkyv", rkyv(with = ScalarDef))]
    pub nullifier: Nullifier,
    /// Whether or not the order is managed locally; i.e. by the local node's
    /// cluster
    pub local: bool,
    /// The cluster known to manage the given order
    pub cluster: ClusterId,
    /// The state of the order via the local peer
    pub state: NetworkOrderState,
    /// The timestamp this order was received at, in milliseconds since the UNIX
    /// epoch
    pub timestamp: u64,
}

impl NetworkOrder {
    /// Create a new order in the `Received` state
    pub fn new(order_id: OrderId, nullifier: Nullifier, cluster: ClusterId, local: bool) -> Self {
        Self {
            id: order_id,
            nullifier,
            local,
            cluster,
            state: NetworkOrderState::Received,
            timestamp: get_current_time_millis(),
        }
    }

    /// Whether the order is cancelled
    pub fn is_cancelled(&self) -> bool {
        self.state == NetworkOrderState::Cancelled
    }

    /// Returns whether the order is ready for matching
    ///
    /// This amounts to whether the order has validity proofs and witnesses
    /// attached to it
    pub fn ready_for_match(&self) -> bool {
        self.state == NetworkOrderState::Verified
    }

    /// Transitions the state of an order back to the received state, this drops
    /// the existing proof of `VALID COMMITMENTS`
    pub fn transition_received(&mut self) {
        self.state = NetworkOrderState::Received;
    }

    /// Transitions the state of an order to the verified state
    pub fn transition_verified(&mut self, nullifier: Nullifier) {
        self.state = NetworkOrderState::Verified;
        self.nullifier = nullifier;
    }

    /// Transitions the state of an order from `Verified` to `Matched`
    #[allow(unused)]
    pub fn transition_matched(&mut self, by_local_node: bool) {
        self.state = NetworkOrderState::Matched { by_local_node };
    }
}

impl PartialEq for NetworkOrder {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.cluster == other.cluster
            && self.nullifier == other.nullifier
            && self.state == other.state
    }
}

impl Eq for NetworkOrder {}

/// Display implementation that ignores enum struct values
impl Display for NetworkOrderState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            NetworkOrderState::Received => f.write_str("Received"),
            NetworkOrderState::Verified => f.write_str("Verified"),
            NetworkOrderState::Matched { .. } => f.write_str("Matched"),
            NetworkOrderState::Cancelled => f.write_str("Cancelled"),
        }
    }
}

/// A type that represents the match priority for an order, including its
/// cluster priority
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "rkyv", derive(Archive, RkyvSerialize, RkyvDeserialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug), attr(allow(missing_docs))))]
pub struct OrderPriority {
    /// The priority of the cluster that the order is managed by
    pub cluster_priority: u32,
    /// The priority of the order itself
    pub order_priority: u32,
}

impl Default for OrderPriority {
    fn default() -> Self {
        OrderPriority {
            cluster_priority: CLUSTER_DEFAULT_PRIORITY,
            order_priority: ORDER_DEFAULT_PRIORITY,
        }
    }
}

impl OrderPriority {
    /// Compute the effective scheduling priority for an order
    pub fn get_effective_priority(&self) -> u32 {
        self.cluster_priority * self.order_priority
    }
}

#[cfg(feature = "rkyv")]
mod rkyv_impls {
    //! Implementations for network orders on the rkyv-derived type
    use crate::network_order::{ArchivedNetworkOrder, ArchivedNetworkOrderState};

    impl ArchivedNetworkOrder {
        /// Whether the order is read for matching
        pub fn ready_for_match(&self) -> bool {
            matches!(self.state, ArchivedNetworkOrderState::Verified)
        }
    }
}

/// Test helpers for creating dummy network orders
#[cfg(feature = "mocks")]
pub mod test_helpers {
    use std::str::FromStr;

    use constants::Scalar;
    use rand::thread_rng;
    use uuid::Uuid;

    use crate::ClusterId;

    use super::{NetworkOrder, NetworkOrderState};

    /// Create a dummy network order
    pub fn dummy_network_order() -> NetworkOrder {
        let mut rng = thread_rng();
        NetworkOrder {
            id: Uuid::new_v4(),
            nullifier: Scalar::random(&mut rng),
            cluster: ClusterId::from_str("cluster").unwrap(),
            state: NetworkOrderState::Received,
            timestamp: 0,
            local: true,
        }
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use constants::Scalar;
    use rand::thread_rng;
    use util::get_current_time_millis;
    use uuid::Uuid;

    use crate::ClusterId;

    use super::{NetworkOrder, NetworkOrderState};

    /// Checks the behavior of the equals operation on a `NetworkOrder`
    ///
    /// This test is largely meant to force the equality operation to include
    /// all fields other than those explicitly ignored. When new fields are
    /// added, this test will need to be updated, indicating that the
    /// `PartialEq` implementation should also be updated
    #[test]
    fn test_network_order_eq() {
        let mut rng = thread_rng();
        let order1 = NetworkOrder {
            id: Uuid::new_v4(),
            nullifier: Scalar::random(&mut rng),
            local: true,
            cluster: ClusterId::from_str("cluster").unwrap(),
            state: NetworkOrderState::Cancelled,
            timestamp: get_current_time_millis(),
        };
        let mut order2 = order1.clone();

        assert_eq!(order1, order2);

        // Change an arbitrary field
        order2.id = Uuid::new_v4();
        assert_ne!(order1, order2);
    }
}
