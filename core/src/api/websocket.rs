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
