//! API types for WebSocket communication

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    admin::ApiAdminOrder,
    balance::ApiBalance,
    order::{ApiOrder, ApiOrderCore, ApiOrderUpdateType, ApiPartialOrderFill},
    task::ApiTask,
};

// ---------------------------
// | Client Message Types    |
// ---------------------------

/// A message from the client over WebSocket
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientWebsocketMessage {
    /// Headers for the message
    pub headers: HashMap<String, String>,
    /// The message body
    pub body: ClientWebsocketMessageBody,
}

/// The body of a client WebSocket message
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum ClientWebsocketMessageBody {
    /// Subscribe to a topic
    Subscribe {
        /// The topic to subscribe to
        topic: String,
    },
    /// Unsubscribe from a topic
    Unsubscribe {
        /// The topic to unsubscribe from
        topic: String,
    },
}

// ------------------------
// | Server Message Types |
// ------------------------

/// A message from the server over WebSocket
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerWebsocketMessage {
    /// The topic of the message
    pub topic: String,
    /// The message body
    pub body: ServerWebsocketMessageBody,
}

/// The body of a server WebSocket message
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ServerWebsocketMessageBody {
    /// List of current subscriptions
    Subscriptions {
        /// The list of subscribed topics
        subscriptions: Vec<String>,
    },
    /// A balance update event
    BalanceUpdate {
        /// The updated balance
        balance: ApiBalance,
    },
    /// An order update event
    OrderUpdate {
        /// The updated order
        order: ApiOrder,
        /// The type of update
        update_type: ApiOrderUpdateType,
    },
    /// A fill event
    Fill {
        /// The fill details
        fill: ApiPartialOrderFill,
        /// The order that was filled
        order: ApiOrderCore,
        /// Whether the order is now fully filled
        filled: bool,
    },
    /// A task update event
    TaskUpdate {
        /// The updated task
        task: ApiTask,
    },
    /// An admin balance update event
    AdminBalanceUpdate {
        /// The account ID
        account_id: Uuid,
        /// The updated balance
        balance: ApiBalance,
    },
    /// An admin order update event
    AdminOrderUpdate {
        /// The account ID
        account_id: Uuid,
        /// The updated order
        order: ApiAdminOrder,
        /// The type of update
        update_type: ApiOrderUpdateType,
    },
}
