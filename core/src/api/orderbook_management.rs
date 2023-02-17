//! Defines types related to orderbook message passing within the p2p network

use serde::{Deserialize, Serialize};

use crate::{
    gossip::types::ClusterId,
    proof_generation::jobs::ValidCommitmentsBundle,
    state::{NetworkOrder, OrderIdentifier},
};

/// The network pubsub topic to use for listening to orderbook changes
pub const ORDER_BOOK_TOPIC: &str = "orderbook";

/// The message type used to request order information from a peer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrderInfoRequest {
    /// The ID of the order
    pub order_id: OrderIdentifier,
}

/// The message type used to response with order information to a peer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrderInfoResponse {
    /// The ID of the order that the info is attached to
    pub order_id: OrderIdentifier,
    /// The order information stored locally for the order
    ///
    /// Value is `None` if the local peer does not store the order
    pub info: Option<NetworkOrder>,
}

/// The message type attached to an OrderBookManagement pubsub message
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum OrderBookManagementMessage {
    /// A new order has been added to the book, peers should place it in the
    /// received state in their local book
    OrderReceived {
        /// The identifier of the new order
        order_id: OrderIdentifier,
        /// The cluster that manages this order
        cluster: ClusterId,
    },
    /// A new validity proof has been generated for an order, it should be placed in
    /// the `Verified` state after local peers verify the proof
    OrderProofUpdated {
        /// The identifier of the now updated order
        order_id: OrderIdentifier,
        /// The cluster that manages this order
        cluster: ClusterId,
        /// The new proof of `VALID COMMITMENTS`
        proof: ValidCommitmentsBundle,
    },
}
