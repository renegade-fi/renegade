//! Groups API definitions for handshake request response
use common::types::{gossip::WrappedPeerId, token::Token, wallet::OrderIdentifier, Price};
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// A type representing the midpoint price of a given token pair
pub type MidpointPrice = (Token, Token, Price);
/// A price vector that a peer proposes to its counterparty during a handshake
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PriceVector(pub Vec<MidpointPrice>);
impl PriceVector {
    /// Returns the price of a given token pair, if it exists in the price vector
    pub fn find_pair(&self, base: &Token, quote: &Token) -> Option<MidpointPrice> {
        self.0
            .iter()
            .find(|(b, q, _)| b == base && q == quote)
            .cloned()
    }
}

impl From<PriceVector> for HashMap<(Token, Token), Price> {
    fn from(price_vector: PriceVector) -> Self {
        price_vector
            .0
            .into_iter()
            .map(|(base, quote, price)| ((base, quote), price))
            .collect()
    }
}

/// Enumerates the different operations possible via handshake
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HandshakeMessage {
    /// A generic ACK to attest to liveness during handshake execution
    Ack,
    /// Propose an order to match with an order sent in InitiateMatch
    ///
    /// If all orders in the local peer's book have already been matched
    /// against the requested order, send back `None`
    ProposeMatchCandidate {
        /// The ID of the peer proposing a match candidate
        peer_id: WrappedPeerId,
        /// The recipient's order that the sender is proposing a match with
        peer_order: OrderIdentifier,
        /// The sender's order that it wishes to match against the receiver's
        ///
        /// Set to `None` by the sender if all locally held orders are cached
        /// as already matched with the `peer_order`
        sender_order: OrderIdentifier,
        /// The vector of prices that the sender is proposing to the receiver
        price_vector: PriceVector,
    },
    /// Reject a proposed match candidate, this can happen for a number of reasons;
    /// e.g. the local peer has already cached the proposed order pair as matched,
    /// or the local peer has not yet validated the proof of `VALID COMMITMENTS` for
    /// the peer's order
    RejectMatchCandidate {
        /// The ID of the peer rejecting the proposal
        peer_id: WrappedPeerId,
        /// The recipient's order, i.e. the order that the proposer used from their own
        /// managed book
        peer_order: OrderIdentifier,
        /// The order of the sender, i.e. the peer that rejects the match proposal
        sender_order: OrderIdentifier,
        /// The reason that the rejecting peer is rejecting the proposal
        reason: MatchRejectionReason,
    },
    /// Go forward with a handshake after a proposed order pair is setup
    AcceptMatchCandidate {
        /// The ID of the peer ACKing the proposal
        peer_id: WrappedPeerId,
        /// The port that the sender can be dialed on to begin the request
        port: u16,
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

/// The reason for rejecting a match candidate proposal
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MatchRejectionReason {
    /// The order pair is already cached by the rejecting peer
    Cached,
    /// The local order proposed is not ready for scheduling
    LocalOrderNotReady,
    /// The rejecting peer has not yet verified the proposer's proof of `VALID COMMITMENTS`
    NoValidityProof,
    /// The prices proposed by the peer are not accepted by the rejecting peer
    NoPriceAgreement,
}
