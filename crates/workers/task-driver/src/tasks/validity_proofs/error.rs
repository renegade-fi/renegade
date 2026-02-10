//! Error types for validity proofs

use state::error::StateError;

/// The error type for validity proofs
#[derive(Clone, Debug, thiserror::Error)]
pub enum ValidityProofsError {
    /// A state error
    #[error("state error: {0}")]
    State(String),
    /// Merkle proof not found for the intent
    #[error("merkle proof not found for intent")]
    MerkleProofNotFound,
    /// Proof generation failed
    #[error("proof generation failed: {0}")]
    ProofGeneration(String),
}

impl ValidityProofsError {
    /// Create a new state error
    #[allow(clippy::needless_pass_by_value)]
    pub fn state<T: ToString>(msg: T) -> Self {
        Self::State(msg.to_string())
    }

    /// Create a new merkle proof not found error
    pub fn merkle_proof_not_found() -> Self {
        Self::MerkleProofNotFound
    }

    /// Create a new proof generation error
    #[allow(clippy::needless_pass_by_value)]
    pub fn proof_generation<T: ToString>(msg: T) -> Self {
        Self::ProofGeneration(msg.to_string())
    }
}

impl From<StateError> for ValidityProofsError {
    fn from(error: StateError) -> Self {
        Self::State(error.to_string())
    }
}
