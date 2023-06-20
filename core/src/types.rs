//! Groups type definitions relevant to all modules and at the top level

use serde::Serialize;

use crate::{
    external_api::types::{NetworkOrder, Peer, Wallet},
    price_reporter::reporter::PriceReport,
    state::{wallet::Wallet as StateWallet, wallet::WalletIdentifier, OrderIdentifier},
    tasks::driver::{StateWrapper as TaskStatus, TaskIdentifier},
};

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
/// The system bus topic published to for all wallet updates, not those given by Id
pub const ALL_WALLET_UPDATES_TOPIC: &str = "wallet-updates";

/// Get the topic name for a given wallet
pub fn wallet_topic_name(wallet_id: &WalletIdentifier) -> String {
    format!("wallet-updates-{}", wallet_id)
}

/// Get the topic name for a given task
pub fn task_topic_name(task_id: &TaskIdentifier) -> String {
    format!("task-updates-{}", task_id)
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

    // -- Network Updates -- //
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

    // -- Tasks -- //
    /// A message indicating that a task has
    TaskStatusUpdate {
        /// The ID of the task
        task_id: TaskIdentifier,
        /// The new state of the task
        state: Box<TaskStatus>,
    },

    // -- Wallet Updates -- //
    /// A message indicating that a wallet has been updated
    WalletUpdate {
        /// The new wallet after update
        wallet: Box<Wallet>,
    },

    /// A message indicating an internal (gossip metadata) update has been
    /// made to a wallet
    InternalWalletUpdate {
        /// The new wallet after update
        wallet: Box<StateWallet>,
    },
}

/// A wrapper around a SystemBusMessage containing the topic, used for serializing websocket
/// messages to clients
#[derive(Clone, Debug, Serialize)]
pub struct SystemBusMessageWithTopic {
    /// The topic of this message
    pub topic: String,
    /// The event itself
    pub event: SystemBusMessage,
}
