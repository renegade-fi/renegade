//! Defines types broadcast onto the system bus and thereby websockets

use common::types::{
    exchange::PriceReport,
    gossip::{PeerInfo, WrappedPeerId},
    network_order::NetworkOrder,
    tasks::TaskIdentifier,
    token::Token,
    wallet::{
        order_metadata::OrderMetadata, OrderIdentifier, Wallet as StateWallet, WalletIdentifier,
    },
};
use serde::Serialize;

use crate::{
    http::task::ApiTaskStatus,
    types::{ApiHistoricalTask, ApiWallet},
};

// ----------------------------
// | System Bus Message Types |
// ----------------------------

/// The system bus topic published to when a network topology change occurs
pub const NETWORK_TOPOLOGY_TOPIC: &str = "network-topology";
/// The system bus topic published to for all wallet updates, not those given by
/// Id
pub const ALL_WALLET_UPDATES_TOPIC: &str = "wallet-updates";

/// Get the topic name for a given wallet
pub fn wallet_topic(wallet_id: &WalletIdentifier) -> String {
    format!("wallet-updates-{}", wallet_id)
}

/// Get the topic name for a wallet's order history
pub fn wallet_order_history_topic(wallet_id: &WalletIdentifier) -> String {
    format!("wallet-order-history-{}", wallet_id)
}

/// Get the topic name for a given task
pub fn task_topic(task_id: &TaskIdentifier) -> String {
    format!("task-updates-{}", task_id)
}

/// Get the task history topic name for a wallet
pub fn task_history_topic(wallet_id: &WalletIdentifier) -> String {
    format!("task-history-{}", wallet_id)
}

/// Get the topic name for a price report
pub fn price_report_topic(base: &Token, quote: &Token) -> String {
    format!("price-report-{}-{}", base.get_addr(), quote.get_addr())
}

/// A message type for generic system bus messages, broadcast to all modules
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
pub enum SystemBusMessage {
    // -- Handshake -- //
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

    // -- Order Book -- //
    /// A message indicating that a new order has come into the network order
    /// book
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

    // -- Network Updates -- //
    /// A new peer has been discovered on the network
    NewPeer {
        /// The peer discovered
        peer: PeerInfo,
    },
    /// A peer was expired after successive heartbeat failures
    PeerExpired {
        /// The expired peer
        peer: WrappedPeerId,
    },

    // -- Price Report -- //
    /// A message indicating that a new PriceReport has been published
    PriceReport(PriceReport),

    // -- Tasks -- //
    /// A message indicating that a task has
    TaskStatusUpdate {
        /// The updated status of the task
        status: ApiTaskStatus,
    },

    // -- Wallet Updates -- //
    /// A message indicating that a wallet has been updated
    WalletUpdate {
        /// The new wallet after update
        wallet: Box<ApiWallet>,
    },

    /// A message indicating an internal (gossip metadata) update has been
    /// made to a wallet
    InternalWalletUpdate {
        /// The new wallet after update
        wallet: Box<StateWallet>,
    },

    // -- Order History Updates -- //
    /// A message indicating that an order has been updated
    OrderMetadataUpdated {
        /// The new state of the order
        order: OrderMetadata,
    },

    // --- Task History Updates -- //
    /// A message indicating an update to a task in the task history
    TaskHistoryUpdate {
        /// The new state of the task
        task: ApiHistoricalTask,
    },
}

/// A wrapper around a SystemBusMessage containing the topic, used for
/// serializing websocket messages to clients
#[derive(Clone, Debug, Serialize)]
pub struct SystemBusMessageWithTopic {
    /// The topic of this message
    pub topic: String,
    /// The event itself
    pub event: SystemBusMessage,
}
