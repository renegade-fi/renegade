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
    /// Build an `AssetFilter` by resolving ticker strings to addresses
    pub fn new(tickers: &[String]) -> Self {
        let disabled = tickers.iter().map(|t| Token::from_ticker(t).get_alloy_address()).collect();
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
