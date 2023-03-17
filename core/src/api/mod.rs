//! The API module defines messaging interfaces between p2p nodes
#![deny(missing_docs)]

use serde::{Deserialize, Serialize};

pub mod cluster_management;
pub mod gossip;
pub mod handshake;
pub mod heartbeat;
pub mod http;
pub mod orderbook_management;
pub mod websocket;

/// An empty request/response type
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct EmptyRequestResponse;
