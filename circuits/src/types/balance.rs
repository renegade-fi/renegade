//! Groups base and derived types for the `Balance` object
#![allow(clippy::missing_docs_in_private_items, missing_docs)]

use std::ops::Add;

use circuit_macros::circuit_type;
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use mpc_bulletproof::r1cs::{LinearCombination, Variable};
use mpc_ristretto::{
    authenticated_ristretto::AuthenticatedCompressedRistretto,
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource, network::MpcNetwork,
};
use num_bigint::BigUint;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    traits::{
        BaseType, CircuitBaseType, CircuitCommitmentType, CircuitVarType, LinearCombinationLike,
        LinkableBaseType, LinkableType, MpcBaseType, MpcLinearCombinationLike, MpcType,
        MultiproverCircuitBaseType, MultiproverCircuitCommitmentType,
        MultiproverCircuitVariableType, SecretShareBaseType, SecretShareType, SecretShareVarType,
    },
    types::{biguint_from_hex_string, biguint_to_hex_string},
};

/// Represents the base type of a balance in tuple holding a reference to the
/// ERC-20 token and its amount
#[circuit_type(singleprover_circuit, mpc, multiprover_circuit, linkable, secret_share)]
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
}

impl Balance {
    /// Whether or not the instance is a default balance
    pub fn is_default(&self) -> bool {
        self.eq(&Balance::default())
    }
}
