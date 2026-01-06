//! Pubsub message types for broadcasting order information to peers

use circuit_types::Nullifier;
use serde::{Deserialize, Serialize};
use types_account::account::OrderId;
use types_gossip::ClusterId;

/// The network pubsub topic to use for listening to orderbook changes
pub const ORDER_BOOK_TOPIC: &str = "orderbook";

/// The message type attached to an OrderBookManagement pubsub message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum OrderBookManagementMessage {
    /// A new order has been added to the book, peers should place it in the
    /// received state in their local book
    OrderReceived {
        /// The identifier of the new order
        order_id: OrderId,
        /// The public share nullifier of the new order's wallet
        nullifier: Nullifier,
        /// The cluster that manages this order
        cluster: ClusterId,
    },
    /// A new validity proof bundle has been generated for an order, it should
    /// be placed in the `Verified` state after local peers verify the proof
    OrderProofUpdated {
        /// The identifier of the now updated order
        order_id: OrderId,
        /// The cluster that manages this order
        cluster: ClusterId,
        /// The new validity proof bundle for the order, containing a proof of
        /// `VALID COMMITMENTS` for the order, and one of `VALID
        /// REBLIND` for the wallet
        proof_bundle: (), // TODO: Add the proof bundle type
    },
}
