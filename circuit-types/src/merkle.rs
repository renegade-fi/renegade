//! Defines types for in-circuit Merkle tree operations
#![allow(clippy::missing_docs_in_private_items)]
#![allow(missing_docs)]

use circuit_macros::circuit_type;
use constants::Scalar;
use mpc_relation::Variable;
use serde::{Deserialize, Serialize};

use crate::{
    deserialize_array, serialize_array,
    traits::{BaseType, CircuitBaseType, CircuitVarType},
};

/// A type alias for readability
pub type MerkleRoot = Scalar;

/// A fully specified merkle opening from hashed leaf to root
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleOpening<const HEIGHT: usize> {
    /// The opening from the leaf node to the root, i.e. the set of sister nodes
    /// that hash together with the input from the leaf to the root
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    pub elems: [Scalar; HEIGHT],
    /// The opening indices from the leaf node to the root, each value is zero
    /// or one: 0 indicating that the node in the opening at index i is a
    /// left hand child of its parent, 1 indicating it's a right hand child
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    pub indices: [Scalar; HEIGHT],
}

impl<const HEIGHT: usize> Default for MerkleOpening<HEIGHT> {
    fn default() -> Self {
        Self {
            elems: [Scalar::zero(); HEIGHT],
            indices: [Scalar::zero(); HEIGHT],
        }
    }
}
