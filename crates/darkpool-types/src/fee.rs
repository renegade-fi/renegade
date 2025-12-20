//! Defines the types for fees in the darkpool state

#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use circuit_macros::circuit_type;
use circuit_types::{Amount, fixed_point::FixedPoint, traits::BaseType};
use constants::Scalar;
use crypto::fields::scalar_to_u128;
use serde::{Deserialize, Serialize};

#[cfg(feature = "proof-system-types")]
use {
    circuit_types::traits::{
        CircuitBaseType, CircuitVarType, SecretShareBaseType, SecretShareType,
        SecretShareVarType,
    },
    constants::ScalarField,
    mpc_relation::{Variable, traits::Circuit},
    std::ops::Add,
};

/// The type for a fee
#[cfg_attr(feature = "proof-system-types", circuit_type(serde, singleprover_circuit, secret_share))]
#[cfg_attr(not(feature = "proof-system-types"), circuit_type(serde))]
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct FeeTake {
    /// The relayer fee
    pub relayer_fee: Amount,
    /// The protocol fee
    pub protocol_fee: Amount,
}

impl FeeTake {
    /// Compute the total fee for a given fee take
    pub fn total(&self) -> Amount {
        self.relayer_fee + self.protocol_fee
    }
}

/// A pair of fee rates that generate a fee when multiplied by a match amount
#[cfg_attr(feature = "proof-system-types", circuit_type(serde, singleprover_circuit, secret_share))]
#[cfg_attr(not(feature = "proof-system-types"), circuit_type(serde))]
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct FeeRates {
    /// The relayer fee rate
    pub relayer_fee_rate: FixedPoint,
    /// The protocol fee rate
    pub protocol_fee_rate: FixedPoint,
}

impl FeeRates {
    /// Constructor
    pub fn new(relayer_fee_rate: FixedPoint, protocol_fee_rate: FixedPoint) -> Self {
        Self { relayer_fee_rate, protocol_fee_rate }
    }

    /// Compute a fee take for a given receive amount
    pub fn compute_fee_take(&self, receive_amount: Amount) -> FeeTake {
        let relayer_fee = self.relayer_fee_rate.floor_mul_int(receive_amount);
        let protocol_fee = self.protocol_fee_rate.floor_mul_int(receive_amount);
        FeeTake {
            relayer_fee: scalar_to_u128(&relayer_fee),
            protocol_fee: scalar_to_u128(&protocol_fee),
        }
    }
}
