//! Centralizes disabled-asset policy for the API layer

use std::collections::HashSet;

use alloy::primitives::Address;
use types_core::{Token, get_all_base_tokens};

use crate::error::{ApiServerError, bad_request};

/// Error returned when a request references a disabled token
const ERR_TOKEN_DISABLED: &str = "token is not supported";

/// Holds the resolved set of disabled asset addresses and exposes
/// a small API for checking and filtering tokens.
#[derive(Clone, Debug)]
pub(crate) struct AssetFilter {
    disabled: HashSet<Address>,
}

impl AssetFilter {
    /// Build an `AssetFilter` by resolving ticker strings to addresses.
    /// Tickers missing from the token remap are skipped: their address can't
    /// be reached via ticker lookup by any inbound request either, so omitting
    /// them from the disabled set is safe.
    pub fn new(tickers: &[String]) -> Self {
        let disabled = tickers
            .iter()
            .filter_map(|t| match Token::maybe_from_ticker(t) {
                Some(tok) => Some(tok.get_alloy_address()),
                None => {
                    tracing::warn!("disabled asset ticker {t} not in token remap; skipping");
                    None
                },
            })
            .collect();
        Self { disabled }
    }

    /// Reject if `addr` is disabled
    pub fn check_token(&self, addr: &Address) -> Result<(), ApiServerError> {
        if self.disabled.contains(addr) {
            return Err(bad_request(ERR_TOKEN_DISABLED));
        }
        Ok(())
    }

    /// Reject if either of two tokens is disabled
    pub fn check_pair(&self, token_a: &Address, token_b: &Address) -> Result<(), ApiServerError> {
        if self.disabled.contains(token_a) || self.disabled.contains(token_b) {
            return Err(bad_request(ERR_TOKEN_DISABLED));
        }
        Ok(())
    }

    /// Return only the base tokens that are *not* disabled
    pub fn enabled_base_tokens(&self) -> Vec<Token> {
        get_all_base_tokens()
            .into_iter()
            .filter(|t| !self.disabled.contains(&t.get_alloy_address()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use types_core::{Chain, set_default_chain};

    use super::*;

    /// Regression: a disabled-asset ticker that isn't in the token remap must
    /// not panic construction. Previously `Token::from_ticker` panicked at
    /// `types-core/src/token.rs:154`, which crashed the relayer at startup
    /// and amplified through the worker-watcher supervision.
    #[test]
    fn new_skips_tickers_missing_from_token_remap() {
        // `maybe_from_ticker` calls `default_chain()` which requires a default
        // chain to be set (or exactly one chain in the remap). In production
        // the relayer sets this at startup; set it here for the test.
        set_default_chain(Chain::ArbitrumOne);

        let tickers = vec!["__TICKER_DEFINITELY_MISSING_FROM_REMAP__".to_string()];
        let filter = AssetFilter::new(&tickers);
        assert_eq!(filter.disabled.len(), 0);
    }
}
