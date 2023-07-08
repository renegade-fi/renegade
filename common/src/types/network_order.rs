//! Type definitions for orders seen "from the network", i.e. where private information
//! about the order is not known

use std::fmt::{Display, Formatter, Result as FmtResult};

use circuit_types::wallet::Nullifier;
use serde::{Deserialize, Serialize};

use super::{
    gossip::ClusterId,
    proof_bundles::{OrderValidityProofBundle, OrderValidityWitnessBundle},
    wallet::OrderIdentifier,
};

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
}

/// Represents an order discovered either via gossip, or from within the local
/// node's managed wallets
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkOrder {
    /// The identifier of the order
    pub id: OrderIdentifier,
    /// The public shares nullifier of the wallet containing this order
    pub public_share_nullifier: Nullifier,
    /// Whether or not the order is managed locally, this does not imply that the owner
    /// field is the same as the local peer's ID. For simplicity the owner field is the
    /// relayer that originated the order. If the owner is a cluster peer, then the local
    /// node may have local = True, with `owner` as a different node
    pub local: bool,
    /// The cluster known to manage the given order
    pub cluster: ClusterId,
    /// The state of the order via the local peer
    pub state: NetworkOrderState,
    /// The proofs of `VALID COMMITMENTS` and `VALID REBLIND` that
    /// have been verified by the local node
    pub validity_proofs: Option<OrderValidityProofBundle>,
    /// The witnesses to the proofs of `VALID REBLIND` and `VALID COMMITMENTS`, only stored for orders that
    /// the local node directly manages
    ///
    /// Skip serialization to avoid sending witness, the serialized type will have `None` in place
    #[serde(skip)]
    pub validity_proof_witnesses: Option<OrderValidityWitnessBundle>,
}

impl NetworkOrder {
    /// Create a new order in the `Received` state
    pub fn new(
        order_id: OrderIdentifier,
        public_share_nullifier: Nullifier,
        cluster: ClusterId,
        local: bool,
    ) -> Self {
        Self {
            id: order_id,
            public_share_nullifier,
            local,
            cluster,
            state: NetworkOrderState::Received,
            validity_proofs: None,
            validity_proof_witnesses: None,
        }
    }

    /// Returns whether the order is ready for matching
    ///
    /// This amounts to whether the order has validity proofs and witnesses attached to it
    pub fn ready_for_match(&self) -> bool {
        self.validity_proofs.is_some() && self.validity_proof_witnesses.is_some()
    }

    /// Transitions the state of an order from `Received` to `Verified` by
    /// attaching two validity proofs:
    ///   1. `VALID REBLIND`: Commits to a valid reblinding of the wallet that will
    ///     be revealed upon successful match. Proved per-wallet.
    ///   2. `VALID COMMITMENTS`: Proves the state elements used as input to the matching
    ///     engine are valid (orders, balances, fees, etc). Proved per-order.
    pub fn attach_validity_proofs(&mut self, validity_proofs: OrderValidityProofBundle) {
        self.state = NetworkOrderState::Verified;
        self.public_share_nullifier = validity_proofs
            .reblind_proof
            .statement
            .original_shares_nullifier;
        self.validity_proofs = Some(validity_proofs)
    }

    /// The following state transition methods are made module private because we prefer
    /// that access flow through the parent (`OrderBook`) object. This object has a reference
    /// to the system bus for internal events to be published

    /// Transitions the state of an order back to the received state, this drops
    /// the existing proof of `VALID COMMITMENTS`
    #[allow(unused)]
    pub fn transition_received(&mut self) {
        self.state = NetworkOrderState::Received;
    }

    /// Transitions the state of an order to the verified state
    #[allow(unused)]
    pub fn transition_verified(&mut self, validity_proofs: OrderValidityProofBundle) {
        self.attach_validity_proofs(validity_proofs);
    }

    /// Transitions the state of an order from `Verified` to `Matched`
    #[allow(unused)]
    pub fn transition_matched(&mut self, by_local_node: bool) {
        self.state = NetworkOrderState::Matched { by_local_node };
    }

    /// Transitions the state of an order to `Cancelled`
    #[allow(unused)]
    pub fn transition_cancelled(&mut self) {
        self.state = NetworkOrderState::Cancelled;

        // We no longer need the validity proof (if it exists)
        // so it is safe to drop
        self.validity_proofs = None;
        self.validity_proof_witnesses = None;
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
        }
    }
}
