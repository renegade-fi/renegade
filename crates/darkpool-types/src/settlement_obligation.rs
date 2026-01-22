//! Defines the settlement obligation type
//!
//! A settlement obligation represents the obligation of one party to settle a
//! match.

#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use alloy_primitives::Address;
use circuit_macros::circuit_type;
use circuit_types::{Amount, traits::BaseType};
use constants::Scalar;
use serde::{Deserialize, Serialize};

#[cfg(feature = "rkyv")]
use crate::rkyv_remotes::AddressDef;

#[cfg(feature = "proof-system-types")]
use {
    circuit_types::traits::{
        CircuitBaseType, CircuitVarType, SecretShareBaseType, SecretShareType, SecretShareVarType,
    },
    constants::ScalarField,
    mpc_relation::{Variable, traits::Circuit},
    std::ops::Add,
};

/// A settlement obligation
///
/// Represents the obligation of one party to settle a match, specifying the
/// tokens and amounts involved in the trade.
#[cfg_attr(feature = "proof-system-types", circuit_type(serde, singleprover_circuit, secret_share))]
#[cfg_attr(not(feature = "proof-system-types"), circuit_type(serde))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
pub struct SettlementObligation {
    /// The input token address
    #[cfg_attr(feature = "rkyv", rkyv(with = AddressDef))]
    pub input_token: Address,
    /// The output token address
    #[cfg_attr(feature = "rkyv", rkyv(with = AddressDef))]
    pub output_token: Address,
    /// The amount of the input token to trade
    pub amount_in: Amount,
    /// The amount of the output token to receive, before fees
    pub amount_out: Amount,
}

/// A match result is a pair of settlement obligations; one for each party
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
pub struct MatchResult {
    /// The settlement obligation for the first party
    pub party0_obligation: SettlementObligation,
    /// The settlement obligation for the second party
    pub party1_obligation: SettlementObligation,
}

impl MatchResult {
    /// Creates a new match result from two settlement obligations
    pub fn new(
        party0_obligation: SettlementObligation,
        party1_obligation: SettlementObligation,
    ) -> Self {
        Self { party0_obligation, party1_obligation }
    }

    /// Get the first party's obligation
    pub fn party0_obligation(&self) -> &SettlementObligation {
        &self.party0_obligation
    }

    /// Get the second party's obligation
    pub fn party1_obligation(&self) -> &SettlementObligation {
        &self.party1_obligation
    }
}
