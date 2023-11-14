//! Groups the base type and derived types for the `Fee` entity
#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use std::ops::Add;

use circuit_macros::circuit_type;
use constants::{AuthenticatedScalar, Scalar, ScalarField};
use mpc_relation::{ConstraintSystem, Variable};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use crate::{
    biguint_from_hex_string, biguint_to_hex_string,
    fixed_point::FixedPoint,
    traits::{
        BaseType, CircuitBaseType, CircuitVarType, MpcBaseType, MpcType,
        MultiproverCircuitBaseType, SecretShareBaseType, SecretShareType, SecretShareVarType,
    },
    Fabric,
};

// -----------------
// | Fee Base Type |
// -----------------

/// Represents a fee-tuple in the state, i.e. a commitment to pay a relayer for
/// a given match
#[circuit_type(serde, singleprover_circuit, mpc, multiprover_circuit, secret_share)]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fee {
    /// The public settle key of the cluster collecting fees
    #[serde(
        serialize_with = "biguint_to_hex_string",
        deserialize_with = "biguint_from_hex_string"
    )]
    pub settle_key: BigUint,
    /// The mint (ERC-20 Address) of the token used to pay gas
    #[serde(
        serialize_with = "biguint_to_hex_string",
        deserialize_with = "biguint_from_hex_string"
    )]
    pub gas_addr: BigUint,
    /// The amount of the mint token to use for gas
    pub gas_token_amount: u64,
    /// The percentage fee that the cluster may take upon match
    /// For now this is encoded as a u64, which represents a
    /// fixed point rational under the hood
    pub percentage_fee: FixedPoint,
}

impl Fee {
    /// Whether or not the given instance is a default fee
    pub fn is_default(&self) -> bool {
        self.eq(&Fee::default())
    }
}
