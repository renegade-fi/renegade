//! Defines the circuit types for a deposit in the V2 darkpool

#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use alloy_primitives::Address;
use circuit_macros::circuit_type;
use circuit_types::{Amount, traits::BaseType};
use constants::Scalar;
use serde::{Deserialize, Serialize};

#[cfg(feature = "proof-system-types")]
use {
    circuit_types::traits::{CircuitBaseType, CircuitVarType},
    constants::ScalarField,
    mpc_relation::{Variable, traits::Circuit},
};

/// A deposit in the V2 darkpool
///
/// A deposit transfer directly into a user's Merklized balance.
/// As opposed to a simple transfer, this transfer type requires a user to sign
/// a Permit2 witness transfer permit in order to authorize its execution.
#[cfg_attr(feature = "proof-system-types", circuit_type(serde, singleprover_circuit))]
#[cfg_attr(not(feature = "proof-system-types"), circuit_type(serde))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Deposit {
    /// The address from which to deposit
    pub from: Address,
    /// The token to deposit
    pub token: Address,
    /// The amount to deposit
    pub amount: Amount,
}
