//! Groups type definitions relevant to all modules and at the top level

use circuits::zk_circuits::{
    valid_commitments::{ValidCommitments, ValidCommitmentsWitness},
    valid_settle::{ValidSettleStatement, ValidSettleWitness},
    valid_wallet_update::ValidWalletUpdateWitness,
};
use serde::{Deserialize, Serialize};

use crate::{
    external_api::types::{NetworkOrder, Peer, Wallet},
    price_reporter::reporter::PriceReport,
    state::{wallet::WalletIdentifier, OrderIdentifier},
    MAX_BALANCES, MAX_FEES, MAX_ORDERS,
};

// ----------------------------------
// | Circuit Default Generics Types |
// ----------------------------------

/// `VALID COMMITMENTS` with default state element sizing
pub type SizedValidCommitments = ValidCommitments<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
/// A `VALID COMMITMENTS` witness with default const generic sizing parameters
pub type SizedValidCommitmentsWitness = ValidCommitmentsWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
/// A `VALID WALLET UPDATE` witness with default const generic sizing parameters
pub type SizedValidWalletUpdateWitness =
    ValidWalletUpdateWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
/// A `VALID SETTLE` statement with default const generic sizing parameters
pub type SizedValidSettleStatement = ValidSettleStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
/// A `VALID SETTLE` witness with default const generic sizing parameters
pub type SizedValidSettleWitness = ValidSettleWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

// ----------------------
// | Pubsub Topic Names |
// ----------------------

/// The topic published to when the handshake manager begins a new
/// match computation with a peer
pub const HANDSHAKE_STATUS_TOPIC: &str = "handshakes";
/// The topic published to when a state change occurs on an order
pub const ORDER_STATE_CHANGE_TOPIC: &str = "order-state";

// ----------------------------
// | System Bus Message Types |
// ----------------------------

/// The system bus topic published to when a network topology change occurs
pub const NETWORK_TOPOLOGY_TOPIC: &str = "network-topology";

/// Get the topic name for a given wallet
pub fn wallet_topic_name(wallet_id: &WalletIdentifier) -> String {
    format!("wallet-updates-{}", wallet_id)
}

/// A message type for generic system bus messages, broadcast to all modules
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[allow(clippy::large_enum_variant)]
pub enum SystemBusMessage {
    // -- Handshake --
    /// A message indicating that a handshake with a peer has started
    HandshakeInProgress {
        /// The order_id of the local party
        local_order_id: OrderIdentifier,
        /// The order_id of the remote peer
        peer_order_id: OrderIdentifier,
        /// The timestamp of the event
        timestamp: u64,
    },
    /// A message indicating that a handshake with a peer has completed
    HandshakeCompleted {
        /// The order_id of the local party
        local_order_id: OrderIdentifier,
        /// The order_id of the remote peer
        peer_order_id: OrderIdentifier,
        /// The timestamp of the event
        timestamp: u64,
    },

    // -- Order Book --
    /// A message indicating that a new order has come into the network order book
    NewOrder {
        /// The newly discovered order
        order: NetworkOrder,
    },
    /// A message indicating that an order has changed state in the local order
    /// book
    OrderStateChange {
        /// The new state of the order
        order: NetworkOrder,
    },

    // -- Network Updates --
    /// A new peer has been discovered on the network
    NewPeer {
        /// The peer discovered
        peer: Peer,
    },
    /// A peer was expired after successive heartbeat failures
    PeerExpired {
        /// The expired peer
        peer: Peer,
    },

    // -- Price Report -- //
    /// A message indicating that a new median PriceReport has been published
    PriceReportMedian(PriceReport),
    /// A message indicating that a new individual exchange PriceReport has been published
    PriceReportExchange(PriceReport),

    // -- Wallet Updates -- //
    /// A message indicating that a wallet has been updated
    WalletUpdate {
        /// The new wallet after update
        wallet: Wallet,
    },
}

/// A wrapper around a SystemBusMessage containing the topic, used for serializing websocket
/// messages to clients
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemBusMessageWithTopic {
    /// The topic of this message
    pub topic: String,
    /// The event itself
    pub event: SystemBusMessage,
}
