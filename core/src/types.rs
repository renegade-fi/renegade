//! Groups type definitions relevant to all modules and at the top level

use serde::{Deserialize, Serialize};

use crate::{handshake::types::OrderIdentifier, price_reporter::reporter::PriceReport};

/**
 * Topic names
 */

/// The topic published to when the handshake manager begins a new
/// match computation with a peer
pub const HANDSHAKE_STATUS_TOPIC: &str = "handshakes";

/// A message type for generic system bus messages, broadcast to all modules
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SystemBusMessage {
    /// A message indicating that a handshake with a peer has started
    HandshakeInProgress {
        /// The order_id of the local party
        local_order_id: OrderIdentifier,
        /// The order_id of the remote peer
        peer_order_id: OrderIdentifier,
    },
    /// A message indicating that a handshake with a peer has completed
    HandshakeCompleted {
        /// The order_id of the local party
        local_order_id: OrderIdentifier,
        /// The order_id of the remote peer
        peer_order_id: OrderIdentifier,
    },
    /// A message indicating that a new median PriceReport has been published
    PriceReportMedian(PriceReport),
}
