//! The error type for the price state primitive

use types_core::Token;

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
    /// No price data available
    #[error("No price data: {0}")]
    NoPriceData(String),
}

impl PriceStateError {
    /// Create a new `PairNotConfigured` error
    pub fn pair_not_configured(base: Token, quote: Token) -> Self {
        Self::PairNotConfigured { base, quote }
    }

    /// Create a new `NoPriceData` error
    pub fn no_price_data(msg: impl ToString) -> Self {
        Self::NoPriceData(msg.to_string())
    }
}
