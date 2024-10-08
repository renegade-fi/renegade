//! Groups the type definitions for matches
#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use circuit_macros::circuit_type;
use constants::{AuthenticatedScalar, Scalar, ScalarField};
use mpc_relation::{traits::Circuit, Variable};
use serde::{Deserialize, Serialize};

use crate::{
    order::OrderSide,
    traits::{
        BaseType, CircuitBaseType, CircuitVarType, MpcBaseType, MpcType, MultiproverCircuitBaseType,
    },
    Address, Amount, Fabric,
};

// ----------------
// | Match Result |
// ----------------

/// Represents the match result of a matching MPC in the cleartext
/// in which two tokens are exchanged
#[circuit_type(serde, singleprover_circuit, mpc, multiprover_circuit)]
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchResult {
    /// The mint of the order token in the asset pair being matched
    pub quote_mint: Address,
    /// The mint of the base token in the asset pair being matched
    pub base_mint: Address,
    /// The amount of the quote token exchanged by this match
    pub quote_amount: Amount,
    /// The amount of the base token exchanged by this match
    pub base_amount: Amount,
    /// The direction of the match, `true` implies that party 1 buys the quote
    /// and sells the base, `false` implies that party 1 buys the base and
    /// sells the quote
    pub direction: bool,

    /// The index of the order (0 or 1) that has the minimum amount, i.e. the
    /// order that is completely filled by this match
    ///
    /// This is computed in the MPC and included in the witness as a hint to
    /// accelerate the collaborative proof constraint generation
    ///
    /// We serialize this as a `bool` to automatically constrain it to be 0 or 1
    /// in a circuit. So `false` means 0 and `true` means 1
    pub min_amount_order_index: bool,
}

impl MatchResult {
    /// Get the send mint and amount given a side of the order
    pub fn send_mint_amount(&self, side: OrderSide) -> (Address, Amount) {
        match side {
            // Buy the base, sell the quote
            OrderSide::Buy => (self.quote_mint.clone(), self.quote_amount),
            // Sell the base, buy the quote
            OrderSide::Sell => (self.base_mint.clone(), self.base_amount),
        }
    }

    /// Get the receive mint and amount given a side of the order
    pub fn receive_mint_amount(&self, side: OrderSide) -> (Address, Amount) {
        match side {
            // Buy the base, sell the quote
            OrderSide::Buy => (self.base_mint.clone(), self.base_amount),
            // Sell the base, buy the quote
            OrderSide::Sell => (self.quote_mint.clone(), self.quote_amount),
        }
    }
}

/// The fee takes from a match
#[circuit_type(serde, singleprover_circuit, mpc, multiprover_circuit)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeTake {
    /// The fee the relayer takes
    pub relayer_fee: Amount,
    /// The fee the protocol takes
    pub protocol_fee: Amount,
}

impl FeeTake {
    /// Get the total fee
    pub fn total(&self) -> Amount {
        self.relayer_fee + self.protocol_fee
    }
}

impl AuthenticatedFeeTake {
    /// Get the total fee
    pub fn total(&self) -> AuthenticatedScalar {
        &self.relayer_fee + &self.protocol_fee
    }
}

/// The indices that specify where settlement logic should modify the wallet
/// shares
#[circuit_type(serde, singleprover_circuit, mpc, multiprover_circuit)]
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct OrderSettlementIndices {
    /// The index of the balance that holds the mint that the wallet will
    /// send if a successful match occurs
    pub balance_send: usize,
    /// The index of the balance that holds the mint that the wallet will
    /// receive if a successful match occurs
    pub balance_receive: usize,
    /// The index of the order that is to be matched
    pub order: usize,
}

// -------------------------
// | External Match Result |
// -------------------------

/// The result of an external match settlement
///
/// An external match is one between a darkpool (internal) order and an external
/// order, facilitated directly by token transfers in the contract
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalMatchResult {
    /// The mint of the quote token in the matched asset pair
    pub quote_mint: Address,
    /// The mint of the base token in the matched asset pair
    pub base_mint: Address,
    /// The amount of the quote token exchanged by the match
    pub quote_amount: Amount,
    /// The amount of the base token exchanged by the match
    pub base_amount: Amount,
    /// The direction of the match
    ///
    /// - `true` implies that the internal party buys the quote and sells the
    ///   base
    /// - `false` implies that the internal party buys the base and sells the
    ///   quote
    pub direction: bool,
}
