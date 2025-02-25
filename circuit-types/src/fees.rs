//! Fee types for circuits in the Renegade system
#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use serde::{Deserialize, Serialize};

use crate::{fixed_point::FixedPoint, Amount};

#[cfg(feature = "proof-system-types")]
use {
    crate::{
        traits::{
            BaseType, CircuitBaseType, CircuitVarType, MpcBaseType, MpcType,
            MultiproverCircuitBaseType,
        },
        Fabric,
    },
    circuit_macros::circuit_type,
    constants::{AuthenticatedScalar, Scalar, ScalarField},
    mpc_relation::{traits::Circuit, Variable},
};

/// A pair of fee take rates
///
/// Note that these are different from the fee takes, they represent fee rates
/// charged by the relayer and protocol, not the actual fee takes from a match
#[cfg_attr(
    feature = "proof-system-types",
    circuit_type(serde, singleprover_circuit, mpc, multiprover_circuit)
)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeTakeRate {
    /// The relayer fee rate
    pub relayer_fee_rate: FixedPoint,
    /// The protocol fee rate
    pub protocol_fee_rate: FixedPoint,
}

impl FeeTakeRate {
    /// Get the total fee rate
    pub fn total(&self) -> FixedPoint {
        self.relayer_fee_rate + self.protocol_fee_rate
    }
}

/// The fee takes from a match
#[cfg_attr(
    feature = "proof-system-types",
    circuit_type(serde, singleprover_circuit, mpc, multiprover_circuit)
)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeTake {
    /// The fee the relayer takes
    pub relayer_fee: Amount,
    /// The fee the protocol takes
    pub protocol_fee: Amount,
}

impl FeeTake {
    /// Get the total fee
    pub fn total(&self) -> Amount {
        self.relayer_fee + self.protocol_fee
    }
}

#[cfg(feature = "proof-system-types")]
impl AuthenticatedFeeTake {
    /// Get the total fee
    pub fn total(&self) -> AuthenticatedScalar {
        &self.relayer_fee + &self.protocol_fee
    }
}
