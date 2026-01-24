//! Error types for settlement helpers

use state::error::StateError;

/// The error type for settlement helpers
#[derive(Clone, Debug, thiserror::Error)]
pub enum SettlementError {
    /// An error building bundle calldata
    #[error("error building bundle calldata: {0}")]
    BuildBundleCalldata(String),
    /// A state error
    #[error("state error: {0}")]
    State(String),
    /// A signing error
    #[error("signing error: {0}")]
    Signing(String),
}

impl SettlementError {
    /// Create a new build bundle calldata error
    #[allow(clippy::needless_pass_by_value)]
    pub fn bundle_calldata<T: ToString>(e: T) -> Self {
        Self::BuildBundleCalldata(e.to_string())
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
}

impl From<StateError> for SettlementError {
    fn from(e: StateError) -> Self {
        Self::State(e.to_string())
    }
}
