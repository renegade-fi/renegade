//! Error types for settlement helpers

use state::error::StateError;

/// The error type for settlement helpers
#[derive(Clone, Debug, thiserror::Error)]
pub enum SettlementError {
    /// An error building bundle calldata
    #[error("error building bundle calldata: {0}")]
    BuildBundleCalldata(String),
    /// A darkpool client error
    #[error("darkpool client error: {0}")]
    Darkpool(String),
    /// A proof generation error
    #[error("proof generation error: {0}")]
    ProofGeneration(String),
    /// A state error
    #[error("state error: {0}")]
    State(String),
    /// A signing error
    #[error("signing error: {0}")]
    Signing(String),
    /// An unsupported error
    #[error("unsupported ring: {0}")]
    UnsupportedRing(String),
}

impl SettlementError {
    /// Create a new build bundle calldata error
    #[allow(clippy::needless_pass_by_value)]
    pub fn bundle_calldata<T: ToString>(e: T) -> Self {
        Self::BuildBundleCalldata(e.to_string())
    }

    /// Create a new darkpool client error
    #[allow(clippy::needless_pass_by_value)]
    pub fn darkpool<T: ToString>(e: T) -> Self {
        Self::Darkpool(e.to_string())
    }

    /// Create a new proof generation error
    #[allow(clippy::needless_pass_by_value)]
    pub fn proof_generation<T: ToString>(e: T) -> Self {
        Self::ProofGeneration(e.to_string())
    }

    /// Create a new state error
    #[allow(clippy::needless_pass_by_value)]
    pub fn state<T: ToString>(e: T) -> Self {
        Self::State(e.to_string())
    }

    /// Create a new signing error
    #[allow(clippy::needless_pass_by_value)]
    pub fn signing<T: ToString>(e: T) -> Self {
        Self::Signing(e.to_string())
    }

    /// Create a new unsupported ring error
    #[allow(clippy::needless_pass_by_value)]
    pub fn unsupported<T: ToString>(e: T) -> Self {
        Self::UnsupportedRing(e.to_string())
    }
}

impl From<StateError> for SettlementError {
    fn from(e: StateError) -> Self {
        Self::State(e.to_string())
    }
}
