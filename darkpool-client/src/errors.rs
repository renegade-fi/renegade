//! Possible errors thrown by the darkpool client

use std::{error::Error, fmt::Display};

use alloy_sol_types::Error as SolError;

/// The error type returned by the darkpool client interface
#[derive(Clone, Debug)]
pub enum DarkpoolClientError {
    /// Error thrown when the darkpool client configuration fails
    Config(DarkpoolClientConfigError),
    /// Error thrown when a contract call fails
    ContractInteraction(String),
    /// Error thrown when a darkpool sub-call cannot be found in a tx
    DarkpoolSubcallNotFound(String),
    /// Error thrown when serializing/deserializing calldata/retdata
    Serde(String),
    /// An signing error
    Signing(String),
    /// Error thrown when converting between relayer & smart contract types
    Conversion(ConversionError),
    /// Error thrown when querying events
    EventQuerying(String),
    /// Error thrown when a commitment can't be found in the Merkle tree
    CommitmentNotFound,
    /// An error interacting with the lower level rpc client
    Rpc(String),
    /// Error thrown when getting a transaction fails
    TxQuerying(String),
    /// Error thrown when a transaction can't be found
    TxNotFound(String),
    /// Error thrown when a transaction is dropped from the mempool
    TxDropped,
    /// Error thrown when a transaction's selector doesn't match
    /// one of the supported ones
    /// (`newWallet`, `updateWallet`, `processMatchSettle`)
    InvalidSelector,
    /// Error thrown when a target public blinder share was not found
    /// in a given transaction
    BlinderNotFound,
}

impl DarkpoolClientError {
    /// Create a new contract interaction error
    #[allow(clippy::needless_pass_by_value)]
    pub fn contract_interaction<T: ToString>(msg: T) -> Self {
        Self::ContractInteraction(msg.to_string())
    }

    /// Create a new event querying error
    #[allow(clippy::needless_pass_by_value)]
    pub fn event_querying<T: ToString>(msg: T) -> Self {
        Self::EventQuerying(msg.to_string())
    }

    /// Create a new RPC error
    #[allow(clippy::needless_pass_by_value)]
    pub fn rpc<T: ToString>(msg: T) -> Self {
        Self::Rpc(msg.to_string())
    }

    /// Create a new signing error
    #[allow(clippy::needless_pass_by_value)]
    pub fn signing<T: ToString>(msg: T) -> Self {
        Self::Signing(msg.to_string())
    }

    /// Create a new transaction querying error
    #[allow(clippy::needless_pass_by_value)]
    pub fn tx_querying<T: ToString>(msg: T) -> Self {
        Self::TxQuerying(msg.to_string())
    }
}

impl Display for DarkpoolClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl Error for DarkpoolClientError {}

/// The error type returned by the darkpool client configuration interface
#[derive(Clone, Debug)]
pub enum DarkpoolClientConfigError {
    /// Error thrown when the RPC client fails to initialize
    RpcClientInitialization(String),
    /// Error thrown when a contract address can't be parsed
    AddressParsing(String),
}

impl Display for DarkpoolClientConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl Error for DarkpoolClientConfigError {}

impl From<DarkpoolClientConfigError> for DarkpoolClientError {
    fn from(e: DarkpoolClientConfigError) -> Self {
        Self::Config(e)
    }
}

/// Errors generated when converting between relayer and smart contract types
#[derive(Clone, Debug)]
pub enum ConversionError {
    /// Error thrown when a variable-length input
    /// can't be coerced into a fixed-length array
    InvalidLength,
    /// Error thrown when converting between uint types
    InvalidUint,
}

impl Display for ConversionError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl Error for ConversionError {}

impl From<ConversionError> for DarkpoolClientError {
    fn from(e: ConversionError) -> Self {
        Self::Conversion(e)
    }
}

impl From<SolError> for DarkpoolClientError {
    fn from(e: SolError) -> Self {
        Self::ContractInteraction(e.to_string())
    }
}
