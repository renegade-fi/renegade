//! The API module defines messaging interfaces between p2p nodes
#![deny(missing_docs)]

use serde::{Deserialize, Serialize};

pub mod http;
pub mod websocket;

/// An empty request/response type
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct EmptyRequestResponse;
