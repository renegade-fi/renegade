//! Groups error types returned by the client

use std::fmt::Display;

/// The error type returned by the StarknetClient interface
#[derive(Clone, Debug)]
pub enum StarknetClientError {
    /// An error executing a transaction
    ExecuteTransaction(String),
    /// No value was found when scanning contract state
    NotFound(String),
    /// An error performing a JSON-RPC request
    Rpc(String),
    /// An error serializing/deserializing calldata
    Serde(String),
}

impl Display for StarknetClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
