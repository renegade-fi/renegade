//! Defines the bounded match result type
//!
//! A bounded match result represents a settlement between an internal party and
//! an external party at a fixed price before a block deadline. The trade size
//! is bounded by a minimum and maximum, and the external party chooses the
//! actual trade size within those bounds at settlement time

#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use alloy_primitives::Address;
use circuit_macros::circuit_type;
use circuit_types::{Amount, fixed_point::FixedPoint, traits::BaseType};
use constants::Scalar;
use serde::{Deserialize, Serialize};

#[cfg(feature = "proof-system-types")]
use {
    circuit_types::traits::{
        CircuitBaseType, CircuitVarType, SecretShareBaseType, SecretShareType, SecretShareVarType,
    },
    constants::ScalarField,
    mpc_relation::{Variable, traits::Circuit},
    std::ops::Add,
};

/// A bounded match result
#[cfg_attr(feature = "proof-system-types", circuit_type(serde, singleprover_circuit, secret_share))]
#[cfg_attr(not(feature = "proof-system-types"), circuit_type(serde))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BoundedMatchResult {
    /// The internal party's input token
    pub internal_party_input_token: Address,
    /// The internal party's output token
    pub internal_party_output_token: Address,
    /// The minimum amount of the internal party's input token to be traded
    pub min_internal_party_amount_in: Amount,
    /// The maximum amount of the internal party's input token to be traded
    pub max_internal_party_amount_in: Amount,
    /// The price of the match, in units of
    /// `internal_party_output_token/internal_party_input_token`
    pub price: FixedPoint,
    /// The block deadline of the match
    pub block_deadline: u64,
}
