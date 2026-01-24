//! Defines a pair of tokens with an implicit direction

use alloy::primitives::Address;
use darkpool_types::intent::Intent;
use serde::{Deserialize, Serialize};
use types_core::Token;

/// The pair of an order
///
/// In order (input_token, output_token)
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Pair {
    /// The input token on the pair
    pub in_token: Address,
    /// The output token on the pair
    pub out_token: Address,
}

impl Pair {
    /// Construct a new pair from the given tokens
    pub fn new(in_token: Address, out_token: Address) -> Self {
        Self { in_token, out_token }
    }

    /// Construct the reverse pair
    pub fn reverse(&self) -> Self {
        Self { in_token: self.out_token, out_token: self.in_token }
    }

    /// Get the pair of an intent
    pub fn from_intent(intent: &Intent) -> Self {
        Self { in_token: intent.in_token, out_token: intent.out_token }
    }

    /// Get the input token for the pair
    pub fn in_token(&self) -> Token {
        Token::from_alloy_address(&self.in_token)
    }

    /// Get the output token for the pair
    pub fn out_token(&self) -> Token {
        Token::from_alloy_address(&self.out_token)
    }

    /// Get the base token for the pair
    pub fn base_token(&self) -> Token {
        let usdc = Token::usdc().get_alloy_address();
        if self.in_token == usdc { self.out_token() } else { self.in_token() }
    }

    /// Get the quote token for the pair
    pub fn quote_token(&self) -> Token {
        let usdc = Token::usdc().get_alloy_address();
        if self.in_token == usdc { self.in_token() } else { self.out_token() }
    }

    /// Get a usdc quoted pair wherein input token is the base and output token
    /// is the USDC quote
    pub fn to_usdc_quoted(&self) -> Result<Self, String> {
        let usdc = Token::usdc().get_alloy_address();
        let new_pair = if self.in_token == usdc {
            self.reverse()
        } else if self.out_token == usdc {
            *self
        } else {
            return Err("Pair does not contain USDC".to_string());
        };

        Ok(new_pair)
    }
}
