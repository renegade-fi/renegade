//! Circuit types for a CSPRNG's state

#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use renegade_crypto::hash::PoseidonCSPRNG;
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
pub struct CSPRNGState {
    /// The seed of the CSPRNG
    pub seed: Scalar,
    /// The index into the CSPRNG's stream
    pub index: u64,
}

impl CSPRNGState {
    /// Constructor
    pub fn new(seed: Scalar) -> Self {
        Self { seed, index: 0 }
    }
}

impl From<CSPRNGState> for PoseidonCSPRNG {
    fn from(state: CSPRNGState) -> Self {
        let mut csprng = PoseidonCSPRNG::new(state.seed);
        csprng.advance_by(state.index as usize);
        csprng
    }
}
