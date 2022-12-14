//! Groups API definitions for handshake request response
use portpicker::Port;
use serde::{Deserialize, Serialize};

use crate::{gossip::types::WrappedPeerId, handshake::manager::OrderIdentifier};

/// Enumerates the different operations possible via handshake
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HandshakeMessage {
    /// A generic ACK to attest to liveness during handshake execution
    Ack,
    /// An MPC operation to be performed during handshake
    InitiateMatch {
        /// The ID of the peer initiating the match
        peer_id: WrappedPeerId,
        /// An order local to the sender, that the sender wants to computed matches for
        sender_order: OrderIdentifier,
    },
    /// Propose an order to match with an order sent in InitiateMatch
    ///
    /// If all orders in the local peer's book have already been matched
    /// against the requestsed order, send back `None`
    ProposeMatchCandidate {
        /// The ID of the peer proposing a match candidate
        peer_id: WrappedPeerId,
        /// The recipient's order that the sender is proposing a match with
        peer_order: OrderIdentifier,
        /// The sender's order that it wishes to match against the receiver's
        ///
        /// Set to `None` by the sender if all locally held orders are cached
        /// as already matched with the `peer_order`
        sender_order: Option<OrderIdentifier>,
    },
    /// Go forward with a handshake after a proposed order pair is setup
    ExecuteMatch {
        /// The ID of the peer ACKing the proposal
        peer_id: WrappedPeerId,
        /// The port that the sender can be dialed on to begin the request
        port: Port,
        /// A flag indicating that the order pair has already been matched
        ///
        /// In this case, the peers will not attempt to match the orders, as they have
        /// already been determined to not match elsewhere in the system
        ///
        /// This message is sent as a courtesy cache-feedback message from the peer that
        /// has already cached this order pair, to the peer that proposed this order pair
        /// so that the proposer may update its cache
        previously_matched: bool,
        /// The first order to attempt to match
        order1: OrderIdentifier,
        /// The second order to attempt to match
        order2: OrderIdentifier,
    },
}
