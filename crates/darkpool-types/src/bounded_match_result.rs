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
use crypto::fields::scalar_to_u128;
use serde::{Deserialize, Serialize};

use crate::settlement_obligation::SettlementObligation;

#[cfg(feature = "rkyv")]
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};

#[cfg(feature = "rkyv")]
use crate::rkyv_remotes::{AddressDef, FixedPointDef};

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
#[cfg_attr(feature = "rkyv", derive(Archive, RkyvDeserialize, RkyvSerialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BoundedMatchResult {
    /// The internal party's input token
    #[cfg_attr(feature = "rkyv", rkyv(with = AddressDef))]
    pub internal_party_input_token: Address,
    /// The internal party's output token
    #[cfg_attr(feature = "rkyv", rkyv(with = AddressDef))]
    pub internal_party_output_token: Address,
    /// The minimum amount of the internal party's input token to be traded
    pub min_internal_party_amount_in: Amount,
    /// The maximum amount of the internal party's input token to be traded
    pub max_internal_party_amount_in: Amount,
    /// The price of the match, in units of
    /// `internal_party_output_token/internal_party_input_token`
    #[cfg_attr(feature = "rkyv", rkyv(with = FixedPointDef))]
    pub price: FixedPoint,
    /// The block deadline of the match
    pub block_deadline: u64,
}

impl BoundedMatchResult {
    /// Convert to settlement obligation for the internal party
    ///
    /// The amount in here refers to the internal party's input amount
    pub fn to_internal_obligation(&self, amount_in: Amount) -> SettlementObligation {
        let amount_out = self.price.floor_mul_int(amount_in);
        SettlementObligation {
            input_token: self.internal_party_input_token,
            output_token: self.internal_party_output_token,
            amount_in,
            amount_out: scalar_to_u128(&amount_out),
        }
    }

    /// Convert to settlement obligation for the external party
    ///
    /// The amount in here refers to the external party's input amount
    pub fn to_external_obligation(&self, amount_in: Amount) -> SettlementObligation {
        let inverse_price = self.price.inverse().expect("price is zero");
        let amount_out = inverse_price.floor_mul_int(amount_in);
        SettlementObligation {
            input_token: self.internal_party_output_token,
            output_token: self.internal_party_input_token,
            amount_in,
            amount_out: scalar_to_u128(&amount_out),
        }
    }
}
