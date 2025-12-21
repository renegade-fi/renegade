//! Defines the settlement obligation type
//!
//! A settlement obligation represents the obligation of one party to settle a
//! match.

#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use alloy_primitives::Address;
use circuit_macros::circuit_type;
use circuit_types::{Amount, traits::BaseType};
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

/// A settlement obligation
///
/// Represents the obligation of one party to settle a match, specifying the
/// tokens and amounts involved in the trade.
#[cfg_attr(feature = "proof-system-types", circuit_type(serde, singleprover_circuit, secret_share))]
#[cfg_attr(not(feature = "proof-system-types"), circuit_type(serde))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementObligation {
    /// The input token address
    pub input_token: Address,
    /// The output token address
    pub output_token: Address,
    /// The amount of the input token to trade
    pub amount_in: Amount,
    /// The amount of the output token to receive, before fees
    pub amount_out: Amount,
}
