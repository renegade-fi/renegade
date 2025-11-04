//! Defines the circuit types for a withdrawal in the V2 darkpool

#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use alloy_primitives::Address;
use serde::{Deserialize, Serialize};

use crate::Amount;

#[cfg(feature = "proof-system-types")]
use {
    crate::traits::{BaseType, CircuitBaseType, CircuitVarType},
    circuit_macros::circuit_type,
    constants::{Scalar, ScalarField},
    mpc_relation::{Variable, traits::Circuit},
};

/// A withdrawal in the V2 darkpool
///
/// A withdrawal transfer directly from a user's Merkle-ized balance to an
/// external address. As opposed to a deposit, this transfer type requires a
/// user to sign the external transfer to authorize its execution.
#[cfg_attr(feature = "proof-system-types", circuit_type(serde, singleprover_circuit))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Withdrawal {
    /// The address to which to withdraw
    pub to: Address,
    /// The token to withdraw
    pub token: Address,
    /// The amount to withdraw
    pub amount: Amount,
}
