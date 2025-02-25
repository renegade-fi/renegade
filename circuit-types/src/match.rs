//! Groups the type definitions for matches
#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use serde::{Deserialize, Serialize};

use crate::{fixed_point::FixedPoint, order::OrderSide, Address, Amount};

#[cfg(feature = "proof-system-types")]
use {
    crate::{
        traits::{
            BaseType, CircuitBaseType, CircuitVarType, MpcBaseType, MpcType,
            MultiproverCircuitBaseType,
        },
        Fabric,
    },
    circuit_macros::circuit_type,
    constants::{AuthenticatedScalar, Scalar, ScalarField},
    mpc_relation::{traits::Circuit, Variable},
};

// ----------------
// | Match Result |
// ----------------

/// Represents the match result of a matching MPC in the cleartext
/// in which two tokens are exchanged
#[cfg_attr(
    feature = "proof-system-types",
    circuit_type(serde, singleprover_circuit, mpc, multiprover_circuit)
)]
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
    /// The direction of the match, `true` implies that party 0 buys the quote
    /// and sells the base, `false` implies that party 0 buys the base and
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

/// The indices that specify where settlement logic should modify the wallet
/// shares
#[cfg_attr(
    feature = "proof-system-types",
    circuit_type(serde, singleprover_circuit, mpc, multiprover_circuit)
)]
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
#[cfg_attr(
    feature = "proof-system-types",
    circuit_type(serde, singleprover_circuit, mpc, multiprover_circuit)
)]
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
    ///
    /// In effect, this flag can be thought of as `external_party_buys_base`
    pub direction: bool,
}

impl ExternalMatchResult {
    /// Get the receive mint and amount of the external party
    pub fn external_party_receive(&self) -> (Address, Amount) {
        // If direction is true, the external party buys the base
        if self.direction {
            (self.base_mint.clone(), self.base_amount)
        } else {
            (self.quote_mint.clone(), self.quote_amount)
        }
    }

    /// Get the send mint and amount of the external party
    pub fn external_party_send(&self) -> (Address, Amount) {
        // If direction is true, the external party sells the quote
        if self.direction {
            (self.quote_mint.clone(), self.quote_amount)
        } else {
            (self.base_mint.clone(), self.base_amount)
        }
    }
}

impl From<MatchResult> for ExternalMatchResult {
    fn from(value: MatchResult) -> Self {
        Self {
            quote_mint: value.quote_mint,
            base_mint: value.base_mint,
            quote_amount: value.quote_amount,
            base_amount: value.base_amount,
            direction: value.direction,
        }
    }
}

// ------------------------
// | Bounded Match Result |
// ------------------------

/// A bounded match result is a match result for which the matched amount is
/// unknown at the time of the match, but is allowed to take on any value
/// between the bounds configured by the bounded match
#[cfg_attr(
    feature = "proof-system-types",
    circuit_type(serde, singleprover_circuit, mpc, multiprover_circuit)
)]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundedMatchResult {
    /// The mint of the quote token in the matched asset pair
    pub quote_mint: Address,
    /// The mint of the base token in the matched asset pair
    pub base_mint: Address,
    /// The price at which the match executes
    pub price: FixedPoint,
    /// The minimum base amount that can be matched
    pub min_base_amount: Amount,
    /// The maximum base amount that can be matched
    pub max_base_amount: Amount,
    /// The direction of the match
    ///
    /// - `true` implies that the internal party buys the quote and sells the
    ///   base
    /// - `false` implies that the internal party buys the base and sells the
    ///   quote
    ///
    /// In effect, this flag can be thought of as `external_party_buys_base`
    pub direction: bool,
}
