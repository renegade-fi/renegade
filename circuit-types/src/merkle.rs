//! Defines types for in-circuit Merkle tree operations
#![allow(clippy::missing_docs_in_private_items)]
#![allow(missing_docs)]

use constants::{Scalar, ScalarField};
use serde::{Deserialize, Serialize};

use crate::{deserialize_array, serialize_array};

#[cfg(feature = "proof-system-types")]
use {
    crate::traits::{BaseType, CircuitBaseType, CircuitVarType},
    circuit_macros::circuit_type,
    mpc_relation::{Variable, traits::Circuit},
};

/// A type alias for readability
pub type MerkleRoot = Scalar;

/// A fully specified merkle opening from hashed leaf to root
#[cfg_attr(feature = "proof-system-types", circuit_type(serde, singleprover_circuit))]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleOpening<const HEIGHT: usize> {
    /// The opening from the leaf node to the root, i.e. the set of sister nodes
    /// that hash together with the input from the leaf to the root
    #[serde(serialize_with = "serialize_array", deserialize_with = "deserialize_array")]
    pub elems: [Scalar; HEIGHT],
    /// The opening indices from the leaf node to the root, each value is a bool
    /// representing whether the current node is a left child
    ///
    /// I.e. `true` means that it is a right child, `false` a left
    #[serde(serialize_with = "serialize_array", deserialize_with = "deserialize_array")]
    pub indices: [bool; HEIGHT],
}

impl<const HEIGHT: usize> Default for MerkleOpening<HEIGHT> {
    fn default() -> Self {
        Self { elems: [Scalar::zero(); HEIGHT], indices: [false; HEIGHT] }
    }
}
