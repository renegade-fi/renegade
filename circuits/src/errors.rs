//! Groups error types for the circuits crate

use std::fmt::{Display, Formatter, Result};

/// Represents an error during the course of an MPC circuit execution
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MpcError {
    /// Represents an error during the course of an arithmetic operation
    ArithmeticError(String),
    /// Error opening a value during circuit evaluation
    OpeningError(String),
    /// Error serializing and deserializing network values
    SerializationError(String),
    /// Error when setting up an MPC
    SetupError(String),
    /// Error sharing a privately held value
    SharingError(String),
}

impl Display for MpcError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{:?}", self)
    }
}

/// Represents an error in converting to/from this package's types
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeConversionError(pub(crate) String /* reason */);

impl Display for TypeConversionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{:?}", self.0)
    }
}
