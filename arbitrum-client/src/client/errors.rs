//! Possible errors thrown by the Arbitrum client

use std::{error::Error, fmt::Display};

/// The error type returned by the Arbitrum client configuration interface
#[derive(Clone, Debug)]
pub enum ArbitrumClientConfigError {
    /// Error thrown when the RPC client fails to initialize
    RpcClientInitialization(String),
    /// Error thrown when a contract address can't be parsed
    AddressParsing(String),
}

impl Display for ArbitrumClientConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl Error for ArbitrumClientConfigError {}

/// The error type returned by the Arbitrum client interface
#[derive(Clone, Debug)]
pub enum ArbitrumClientError {
    /// Error thrown when the Arbitrum client configuration fails
    Config(ArbitrumClientConfigError),
}

impl Display for ArbitrumClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl Error for ArbitrumClientError {}

impl From<ArbitrumClientConfigError> for ArbitrumClientError {
    fn from(e: ArbitrumClientConfigError) -> Self {
        Self::Config(e)
    }
}
