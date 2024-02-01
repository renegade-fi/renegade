//! Groups the type definitions for matches
#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use circuit_macros::circuit_type;
use constants::{AuthenticatedScalar, Scalar, ScalarField};
use mpc_relation::{traits::Circuit, Variable};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use crate::{
    traits::{
        BaseType, CircuitBaseType, CircuitVarType, MpcBaseType, MpcType, MultiproverCircuitBaseType,
    },
    Fabric,
};

/// Represents the match result of a matching MPC in the cleartext
/// in which two tokens are exchanged
/// TODO: When we convert these values to fixed point rationals, we will need to
/// sacrifice one bit of precision to ensure that the difference in prices is
/// divisible by two
#[circuit_type(serde, singleprover_circuit, mpc, multiprover_circuit)]
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchResult {
    /// The mint of the order token in the asset pair being matched
    pub quote_mint: BigUint,
    /// The mint of the base token in the asset pair being matched
    pub base_mint: BigUint,
    /// The amount of the quote token exchanged by this match
    pub quote_amount: u64,
    /// The amount of the base token exchanged by this match
    pub base_amount: u64,
    /// The direction of the match, `true` implies that party 1 buys the quote
    /// and sells the base, `false` implies that party 1 buys the base and
    /// sells the quote
    pub direction: bool,

    /// The following are supporting variables, derivable from the above, but
    /// useful for shrinking the size of the zero knowledge circuit. As
    /// well, they are computed during the course of the MPC, so it incurs
    /// no extra cost to include them in the witness

    /// The minimum amount of the two orders minus the maximum amount of the two
    /// orders. We include it here to tame some of the non-linearity of the
    /// zk circuit, i.e. we can shortcut some of the computation and
    /// implicitly constrain the match result with this extra value
    pub max_minus_min_amount: u64,
    /// The index of the order (0 or 1) that has the minimum amount, i.e. the
    /// order that is completely filled by this match
    ///
    /// We serialize this as a `bool` to automatically constrain it to be 0 or 1
    /// in a circuit. So `false` means 0 and `true` means 1
    pub min_amount_order_index: bool,
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
