//! Groups error types for the circuits crate

use std::fmt::{Display, Formatter, Result};

use mpc_bulletproof::r1cs_mpc::R1CSError;

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

/// Represents an error during the course of proving a statement
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProverError {
    /// An error during the course of a multi-prover execution that results
    /// from the MPC network itself
    Mpc(MpcError),
    /// An error that occurs from an R1CS error directly
    R1CS(R1CSError),
}

impl Display for ProverError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{:?}", self)
    }
}

/// Represents an error during proof verification
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifierError {
    /// An error that occurs as a result of R1CS non-satisfaction
    R1CS(R1CSError),
}

impl Display for VerifierError {
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
