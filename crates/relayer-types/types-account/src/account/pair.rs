//! Defines a pair of tokens with an implicit direction

use alloy::primitives::Address;
use darkpool_types::intent::Intent;
use serde::{Deserialize, Serialize};

/// The pair of an order
///
/// In order (input_token, output_token)
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Pair {
    /// The input token on the pair
    in_token: Address,
    /// The output token on the pair
    out_token: Address,
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
}
