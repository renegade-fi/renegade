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

// --- Individual message body types ---

/// A subscriptions list message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubscriptionsMessage {
    /// The list of subscribed topics
    pub subscriptions: Vec<String>,
}

/// A balance update message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BalanceUpdateMessage {
    /// The updated balance
    pub balance: ApiBalance,
}

/// An order update message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrderUpdateMessage {
    /// The updated order
    pub order: ApiOrder,
    /// The type of update
    pub update_type: ApiOrderUpdateType,
}

/// A fill message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FillMessage {
    /// The fill details
    pub fill: ApiPartialOrderFill,
    /// The order that was filled
    pub order: ApiOrderCore,
    /// Whether the order is now fully filled
    pub filled: bool,
}

/// A task update message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskUpdateMessage {
    /// The updated task
    pub task: ApiTask,
}

/// An admin balance update message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminBalanceUpdateMessage {
    /// The account ID
    pub account_id: Uuid,
    /// The updated balance
    pub balance: ApiBalance,
}

/// An admin order update message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminOrderUpdateMessage {
    /// The account ID
    pub account_id: Uuid,
    /// The updated order
    pub order: ApiAdminOrder,
    /// The type of update
    pub update_type: ApiOrderUpdateType,
}

/// The body of a server WebSocket message
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ServerWebsocketMessageBody {
    /// List of current subscriptions
    Subscriptions(SubscriptionsMessage),
    /// A balance update event
    BalanceUpdate(BalanceUpdateMessage),
    /// An order update event
    OrderUpdate(OrderUpdateMessage),
    /// A fill event
    Fill(FillMessage),
    /// A task update event
    TaskUpdate(TaskUpdateMessage),
    /// An admin balance update event
    AdminBalanceUpdate(AdminBalanceUpdateMessage),
    /// An admin order update event
    AdminOrderUpdate(AdminOrderUpdateMessage),
}
