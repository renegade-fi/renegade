//! A wrapper type for state elements allocated in the darkpool
//!
//! All state elements are endowed with two CSPRNGs:
//! 1. A recovery identifier CSPRNG. This stream leaks one element per update to
//!    enable off-chain indexers to track the state element's evolution on-chain
//! 2. A private share CSPRNG. This CSPRNG backs a stream cipher with which we
//!    encrypt the plaintext data
//!
//! We commit to the entire state wrapper--including the CSPRNG states--but only
//! generate ciphertext for the plaintext data in `state`

#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use serde::{Deserialize, Serialize};

use std::fmt::Debug;

use crate::csprng_state::CSPRNGState;

#[cfg(feature = "proof-system-types")]
use {
    crate::traits::{BaseType, CircuitBaseType, CircuitVarType},
    circuit_macros::circuit_type,
    constants::{Scalar, ScalarField},
    mpc_relation::{Variable, traits::Circuit},
};

/// A wrapper type for state elements allocated in the darkpool
#[cfg_attr(feature = "proof-system-types", circuit_type(serde, singleprover_circuit))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateWrapper<T>
where
    T: CircuitBaseType,
{
    /// The recovery identifier CSPRNG
    pub recovery_stream: CSPRNGState,
    /// The private share CSPRNG
    pub share_stream: CSPRNGState,
    /// The state element
    pub inner: T,
}
