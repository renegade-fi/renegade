//! Groups error types for the circuits crate

/// Represents an error during the course of an MPC circuit execution
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MpcError {
    /// Error when setting up an MPC
    SetupError(String),
    /// Error serializing and deserializing network values
    SerializationError(String),
    /// Represents an error during the course of an arithmetic operation
    ArithmeticError(String),
    /// Error opening a value during circuit evaluation
    OpeningError(String),
    // TODO: remove this
    NotImplemented,
}
