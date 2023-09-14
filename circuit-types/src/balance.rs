//! Groups base and derived types for the `Balance` object
#![allow(clippy::missing_docs_in_private_items, missing_docs)]

use std::ops::Add;

use circuit_macros::circuit_type;
use mpc_bulletproof::r1cs::{LinearCombination, Variable};
use mpc_stark::{
    algebra::{
        authenticated_scalar::AuthenticatedScalarResult,
        authenticated_stark_point::AuthenticatedStarkPointOpenResult, scalar::Scalar,
        stark_curve::StarkPoint,
    },
    MpcFabric,
};
use num_bigint::BigUint;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    biguint_from_hex_string, biguint_to_hex_string,
    traits::{
        BaseType, CircuitBaseType, CircuitCommitmentType, CircuitVarType, LinearCombinationLike,
        LinkableBaseType, LinkableType, MpcBaseType, MpcLinearCombinationLike, MpcType,
        MultiproverCircuitBaseType, MultiproverCircuitCommitmentType,
        MultiproverCircuitVariableType, SecretShareBaseType, SecretShareType, SecretShareVarType,
    },
};

/// Represents the base type of a balance in tuple holding a reference to the
/// ERC-20 token and its amount
#[circuit_type(
    serde,
    singleprover_circuit,
    mpc,
    multiprover_circuit,
    linkable,
    secret_share,
    multiprover_linkable
)]
#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Balance {
    /// The mint (ERC-20 token address) of the token in the balance
    #[serde(
        serialize_with = "biguint_to_hex_string",
        deserialize_with = "biguint_from_hex_string"
    )]
    pub mint: BigUint,
    /// The amount of the given token stored in this balance
    pub amount: u64,
    /// The amount currently owed in fees to the protocol
    pub protocol_fee_balance: u64,
    /// The amount currently owned in fees to the managing relayer cluster
    pub relayer_fee_balance: u64,
}

impl Balance {
    /// Whether or not the instance is a default balance
    pub fn is_default(&self) -> bool {
        self.eq(&Balance::default())
    }
}
