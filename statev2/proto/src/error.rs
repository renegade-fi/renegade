//! Error types emitted by proto parsing code

use std::{error::Error, fmt::Display};

/// The error type emitted when operations on protos fail
#[derive(Clone, Debug)]
pub enum StateProtoError {
    /// A field is missing from a proto
    MissingField { field_name: String },
    /// An error parsing a proto message into a runtime type
    ParseError(String),
}

impl Display for StateProtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for StateProtoError {}
