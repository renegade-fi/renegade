//! Defines the circuit types for a balance in the V2 darkpool

#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use std::ops::Add;

use alloy_primitives::Address;
use serde::{Deserialize, Serialize};

use crate::{Amount, csprng_state::CSPRNGState, state_wrapper::StateWrapper};

#[cfg(feature = "proof-system-types")]
use {
    crate::traits::{
        BaseType, CircuitBaseType, CircuitVarType, SecretShareBaseType, SecretShareType,
        SecretShareVarType,
    },
    circuit_macros::circuit_type,
    constants::{Scalar, ScalarField},
    mpc_relation::{Variable, traits::Circuit},
};

/// A balance wrapped in a state wrapper
pub type DarkpoolStateBalance = StateWrapper<Balance>;

/// A balance in the V2 darkpool
#[cfg_attr(feature = "proof-system-types", circuit_type(serde, singleprover_circuit, secret_share))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Balance {
    /// The mint of the token in the balance
    pub mint: Address,
    /// A one-time signing authority for the balance
    ///
    /// This authorizes the balance to be spent by an order for the first time,
    /// the key is leaked in a proof and authorizes the creation of an intent.
    /// Effectively this is a delegated authority for creating intents
    /// capitalized by this balance
    pub one_time_authority: Address,
    /// The relayer fee balance of the balance
    pub relayer_fee_balance: Amount,
    /// The protocol fee balance of the balance
    pub protocol_fee_balance: Amount,
    /// The amount of the token in the balance
    pub amount: Amount,
}
