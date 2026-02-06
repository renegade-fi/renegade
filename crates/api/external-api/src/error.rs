//! Error types for API type conversions

/// Error type for API type conversions
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApiTypeError {
    /// Error parsing or converting a value
    Parsing(String),
    /// Error validating a value
    Validation(String),
}

impl ApiTypeError {
    /// Create a parsing error from any type that can be converted to a string
    pub fn parsing<T: ToString>(err: T) -> Self {
        Self::Parsing(err.to_string())
    }

    /// Create a validation error from any type that can be converted to a
    /// string
    pub fn validation<T: ToString>(err: T) -> Self {
        Self::Validation(err.to_string())
    }
}

impl std::fmt::Display for ApiTypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiTypeError::Parsing(msg) => write!(f, "parsing error: {msg}"),
            ApiTypeError::Validation(msg) => write!(f, "validation error: {msg}"),
        }
    }
}

impl std::error::Error for ApiTypeError {}
