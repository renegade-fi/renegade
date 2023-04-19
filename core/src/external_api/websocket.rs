//! Groups API definitions for the websocket API

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// The wrapper websocket message type that contains both a header and body
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientWebsocketMessage {
    /// The headers associated with the client message
    pub headers: HashMap<String, String>,
    /// The body of the request
    pub body: WebsocketMessage,
}

/// A message type that indicates the client would like to either subscribe or unsubscribe
/// from a given topic
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "lowercase")]
pub enum WebsocketMessage {
    /// Indicates that the client would like to subscribe to the given topic
    Subscribe {
        /// The topic being subscribed to
        topic: String,
    },
    /// Indicates that the client would like to unsubscribe to the given topic
    Unsubscribe {
        /// The topic being unsubscribed from
        topic: String,
    },
}

/// A message that is sent in response to a subscribe/unsubscribe message, notifies the client
/// of the now active subscriptions after a subscribe/unsubscribe message is applied
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubscriptionResponse {
    /// The subscriptions that remain after applying the requested update
    pub subscriptions: Vec<String>,
}
