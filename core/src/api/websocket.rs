//! Groups API definitions for the websocket API

use serde::{Deserialize, Serialize};

/// A message type that indicates the client would like to either subscribe or unsubscribe
/// from a given topic
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SubscriptionMessage {
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

/// A message that is sent in response to a SubscriptionMessage, notifies the client
/// of the now active subscriptions after a subscribe/unsubscripe message is applied
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubscriptionResponse {
    /// The subscriptions that remain after applying the requested update
    pub subscriptions: Vec<String>,
}
