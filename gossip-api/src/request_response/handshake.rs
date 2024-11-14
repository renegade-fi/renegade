//! Groups API definitions for handshake request response
use common::types::{
    gossip::WrappedPeerId, token::Token, wallet::OrderIdentifier, TimestampedPrice,
};
use std::collections::HashMap;
use uuid::Uuid;

use serde::{Deserialize, Serialize};

// ----------------
// | Price Vector |
// ----------------

/// A type representing the midpoint price of a given token pair
pub type MidpointPrice = (Token, Token, TimestampedPrice);

/// A price vector that a peer proposes to its counterparty during a handshake
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PriceVector(pub Vec<MidpointPrice>);
impl PriceVector {
    /// Returns the price of a given token pair, if it exists in the price
    /// vector
    pub fn find_pair(&self, base: &Token, quote: &Token) -> Option<MidpointPrice> {
        self.0.iter().find(|(b, q, _)| b == base && q == quote).cloned()
    }
}

impl From<PriceVector> for HashMap<(Token, Token), TimestampedPrice> {
    fn from(price_vector: PriceVector) -> Self {
        price_vector.0.into_iter().map(|(base, quote, price)| ((base, quote), price)).collect()
    }
}

// ----------------------
// | Handshake Messages |
// ----------------------

/// The handshake message, sent in request/response to negotiate an MPC match
/// attempt
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandshakeMessage {
    /// The request ID; used track handshakes across events
    pub request_id: Uuid,
    /// The type of the message
    pub message_type: HandshakeMessageType,
}

/// Enumerates the different operations possible via handshake
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HandshakeMessageType {
    /// Propose a match candidate
    Propose(ProposeMatchCandidate),
    /// Reject a match candidate
    Reject(RejectMatchCandidate),
    /// Accept a match candidate
    Accept(AcceptMatchCandidate),
}

/// Propose an order to match with against the given order sent to the peer
///
/// If all orders in the local peer's book have already been matched against
/// the requested order, send back `None`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposeMatchCandidate {
    /// The ID of the peer proposing a match candidate
    pub peer_id: WrappedPeerId,
    /// The recipient's order that the sender is proposing a match with
    pub peer_order: OrderIdentifier,
    /// The sender's order that it wishes to match against the receiver's
    pub sender_order: OrderIdentifier,
    /// The vector of prices that the sender is proposing to the receiver
    pub price_vector: PriceVector,
}

/// Reject a proposed match candidate,
///
/// This can happen for a number of reasons; e.g. the local peer has already
/// cached the proposed order pair as matched, or the local peer has not yet
/// validated the order's proofs
/// pair as matched, or the local peer has not yet validated the order's proofs
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RejectMatchCandidate {
    /// The ID of the peer rejecting the proposal
    pub peer_id: WrappedPeerId,
    /// The recipient's order, i.e. the order that the proposer used from
    /// their own managed book
    pub peer_order: OrderIdentifier,
    /// The order of the sender, i.e. the peer that rejects the match
    /// proposal
    pub sender_order: OrderIdentifier,
    /// The reason that the rejecting peer is rejecting the proposal
    pub reason: MatchRejectionReason,
}

/// The reason for rejecting a match candidate proposal
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MatchRejectionReason {
    /// The order pair is already cached by the rejecting peer
    Cached,
    /// The local order proposed is not ready for scheduling
    LocalOrderNotReady,
    /// The rejecting peer has not yet verified the proposer's validity proof's
    NoValidityProof,
    /// The prices proposed by the peer are not accepted by the rejecting peer
    NoPriceAgreement,
}

/// Go forward with a handshake after a proposed order pair is setup
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AcceptMatchCandidate {
    /// The ID of the peer ACKing the proposal
    pub peer_id: WrappedPeerId,
    /// The port that the sender can be dialed on to begin the request
    pub port: u16,
    /// The first order to attempt to match
    pub order1: OrderIdentifier,
    /// The second order to attempt to match
    pub order2: OrderIdentifier,
}
