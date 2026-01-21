//! Possible errors thrown by the darkpool client

use alloy_sol_types::Error as SolError;

/// The error type returned by the darkpool client interface
#[derive(Clone, Debug, thiserror::Error)]
pub enum DarkpoolClientError {
    /// Error thrown when a target public blinder share was not found
    /// in a given transaction
    #[error("blinder not found")]
    BlinderNotFound,
    /// Error thrown when a commitment can't be found in the Merkle tree
    #[error("commitment not found")]
    CommitmentNotFound,
    /// Error thrown when the darkpool client configuration fails
    #[error("darkpool client configuration error: {0}")]
    Config(#[from] DarkpoolClientConfigError),
    /// Error thrown when converting between relayer & smart contract types
    #[error("conversion error: {0}")]
    Conversion(#[from] ConversionError),
    /// Error thrown when a contract call fails
    #[error("contract interaction error: {0}")]
    ContractInteraction(String),
    /// Error thrown when a darkpool sub-call cannot be found in a tx
    #[error("darkpool sub-call not found: {0}")]
    DarkpoolSubcallNotFound(String),
    /// An error interacting with an erc20 contract
    #[error("ERC20 error: {0}")]
    Erc20(String),
    /// An error interacting with permit2
    #[error("Permit2 error: {0}")]
    Permit2(String),
    /// Error thrown when querying events
    #[error("event querying error: {0}")]
    EventQuerying(String),
    /// Error thrown when a transaction's selector doesn't match
    /// one of the supported ones
    /// (`newWallet`, `updateWallet`, `processMatchSettle`)
    #[error("invalid selector")]
    InvalidSelector,
    /// An error interacting with the lower level rpc client
    #[error("RPC error: {0}")]
    Rpc(String),
    /// Error thrown when serializing/deserializing calldata/retdata
    #[error("serialization error: {0}")]
    Serde(String),
    /// An signing error
    #[error("signing error: {0}")]
    Signing(String),
    /// Error thrown when a transaction is dropped from the mempool
    #[error("transaction dropped from mempool")]
    TxDropped,
    /// Error thrown when a transaction can't be found
    #[error("transaction not found: {0}")]
    TxNotFound(String),
    /// Error thrown when getting a transaction fails
    #[error("transaction querying error: {0}")]
    TxQuerying(String),
}

impl DarkpoolClientError {
    /// Create a new contract interaction error
    #[allow(clippy::needless_pass_by_value)]
    pub fn contract_interaction<T: ToString>(msg: T) -> Self {
        Self::ContractInteraction(msg.to_string())
    }

    /// Create a new erc20 error
    #[allow(clippy::needless_pass_by_value)]
    pub fn erc20<T: ToString>(msg: T) -> Self {
        Self::Erc20(msg.to_string())
    }

    /// Create a new permit2 error
    #[allow(clippy::needless_pass_by_value)]
    pub fn permit2<T: ToString>(msg: T) -> Self {
        Self::Permit2(msg.to_string())
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

/// The error type returned by the darkpool client configuration interface
#[derive(Clone, Debug, thiserror::Error)]
pub enum DarkpoolClientConfigError {
    /// Error thrown when the RPC client fails to initialize
    #[error("RPC client initialization error: {0}")]
    RpcClientInitialization(String),
    /// Error thrown when a contract address can't be parsed
    #[error("address parsing error: {0}")]
    AddressParsing(String),
}

/// Errors generated when converting between relayer and smart contract types
#[derive(Clone, Debug, thiserror::Error)]
pub enum ConversionError {
    /// Error thrown when a variable-length input
    /// can't be coerced into a fixed-length array
    #[error("invalid length")]
    InvalidLength,
    /// Error thrown when converting between uint types
    #[error("invalid uint")]
    InvalidUint,
}

impl From<SolError> for DarkpoolClientError {
    fn from(e: SolError) -> Self {
        Self::ContractInteraction(e.to_string())
    }
}
