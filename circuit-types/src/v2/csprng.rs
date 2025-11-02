//! Circuit types for a CSPRNG's state

#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use renegade_crypto::hash::compute_poseidon_hash;
use serde::{Deserialize, Serialize};
use std::ops::Add;

use constants::Scalar;

#[cfg(feature = "proof-system-types")]
use {
    crate::traits::{
        BaseType, CircuitBaseType, CircuitVarType, SecretShareBaseType, SecretShareType,
        SecretShareVarType,
    },
    circuit_macros::circuit_type,
    constants::ScalarField,
    mpc_relation::{Variable, traits::Circuit},
};

/// A CSPRNG's state
#[cfg_attr(feature = "proof-system-types", circuit_type(serde, singleprover_circuit, secret_share))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PoseidonCSPRNG {
    /// The seed of the CSPRNG
    pub seed: Scalar,
    /// The index into the CSPRNG's stream
    pub index: u64,
}

impl PoseidonCSPRNG {
    /// Constructor
    pub fn new(seed: Scalar) -> Self {
        Self { seed, index: 0 }
    }

    /// Advance the index by the given amount
    pub fn advance_by(&mut self, amount: usize) {
        self.index += amount as u64;
    }

    /// Get the ith value in the stream without mutating the state
    ///
    /// Returns `H(seed || i)` where `H` is the Poseidon hash function
    pub fn get_ith(&self, i: u64) -> Scalar {
        let elts = [self.seed, i.into()];
        compute_poseidon_hash(&elts)
    }
}

impl Iterator for PoseidonCSPRNG {
    type Item = Scalar;

    fn next(&mut self) -> Option<Self::Item> {
        let elts = [self.seed, self.index.into()];
        let hash_res = compute_poseidon_hash(&elts);
        self.index += 1;

        Some(hash_res)
    }
}
