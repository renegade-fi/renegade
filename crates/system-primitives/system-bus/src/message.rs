//! Defines types broadcast onto the system bus and thereby websockets

use darkpool_types::bounded_match_result::BoundedMatchResult;
use types_account::account::{Account, OrderId};
use types_core::AccountId;
use types_gossip::{PeerInfo, WrappedPeerId};
use types_tasks::TaskIdentifier;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ----------------------------
// | System Bus Message Types |
// ----------------------------

/// The system bus topic published to when a network topology change occurs
pub const NETWORK_TOPOLOGY_TOPIC: &str = "network-topology";
/// The system bus topic published to for all wallet updates, not those given by
/// Id
pub const ALL_WALLET_UPDATES_TOPIC: &str = "wallet-updates";
/// The system bus topic published to for all admin wallet updates, including
/// order placements and cancellations
pub const ADMIN_WALLET_UPDATES_TOPIC: &str = "admin-wallet-updates";

/// Get the topic name for a given wallet
pub fn account_topic(account_id: &AccountId) -> String {
    format!("account-updates-{account_id}")
}

/// Get the topic name for a given task
pub fn task_topic(task_id: &TaskIdentifier) -> String {
    format!("task-updates-{task_id}")
}

/// Get a topic name for an atomic match response
pub fn gen_atomic_match_response_topic() -> String {
    format!("atomic-match-{}", Uuid::new_v4())
}

// ----------------------
// | Task Status Types  |
// ----------------------

/// Task status for system bus messages
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskStatus {
    /// The task identifier
    pub id: Uuid,
    /// The task status
    pub status: String,
    /// The task description
    pub description: Option<String>,
}

/// A message type for generic system bus messages, broadcast to all modules
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SystemBusMessage {
    // -- Handshake -- //
    /// A message indicating that a handshake with a peer has started
    HandshakeInProgress {
        /// The order_id of the local party
        local_order_id: OrderId,
        /// The order_id of the remote peer
        peer_order_id: OrderId,
        /// The timestamp of the event
        timestamp: u64,
    },
    /// A message indicating that a handshake with a peer has completed
    HandshakeCompleted {
        /// The order_id of the local party
        local_order_id: OrderId,
        /// The order_id of the remote peer
        peer_order_id: OrderId,
        /// The timestamp of the event
        timestamp: u64,
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

    // -- Tasks -- //
    /// A message indicating that a task has been updated
    TaskStatusUpdate {
        /// The updated status of the task
        status: TaskStatus,
    },

    // -- Account Updates -- //
    /// A message indicating that an account has been updated
    AccountUpdate {
        /// The new account after update
        account: Box<Account>,
    },

    // --- External Match API --- //
    /// A message containing a quote for an external order
    ExternalOrderQuote {
        /// The quote
        quote: BoundedMatchResult,
    },
    /// A message indicating that no atomic match was found for a request
    NoExternalMatchFound,

    // --- Admin -- //
    /// A message indicating that an account has been updated, intended for
    /// consumption by the admin API
    AdminAccountUpdate {
        /// The ID of the account that was updated
        account_id: AccountId,
    },
}

/// A wrapper around a SystemBusMessage containing the topic, used for
/// serializing websocket messages to clients
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemBusMessageWithTopic {
    /// The topic of this message
    pub topic: String,
    /// The event itself
    pub event: SystemBusMessage,
}
