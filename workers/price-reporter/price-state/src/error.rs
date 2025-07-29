//! The error type for the price state primitive

use common::types::token::Token;

/// The error type for the price state primitive
#[derive(Debug, thiserror::Error)]
pub enum PriceStateError {
    /// The price is not available
    #[error("The price is not available for pair {base}/{quote}")]
    PairNotConfigured {
        /// The base token
        base: Token,
        /// The quote token
        quote: Token,
    },
}

impl PriceStateError {
    /// Create a new `PairNotConfigured` error
    pub fn pair_not_configured(base: Token, quote: Token) -> Self {
        Self::PairNotConfigured { base, quote }
    }
}
