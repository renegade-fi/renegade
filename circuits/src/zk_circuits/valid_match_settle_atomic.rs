//! Defines the VALID MATCH SETTLE ATOMIC circuit which verifies a match
//! between two parties; one internal and one external. An internal party is one
//! with state committed into the darkpool, while an external party is one whose
//! funds sit outside the darkpool, on the host chain.
//!
//! VALID MATCH SETTLE ATOMIC allows the external party to match against a known
//! internal order; emulating the standard deposit, order placement, settlement,
//! and withdrawal flow in a single transaction.

use crate::SingleProverCircuit;
use circuit_macros::circuit_type;
use circuit_types::{
    balance::Balance,
    fixed_point::FixedPoint,
    order::Order,
    r#match::{FeeTake, OrderSettlementIndices},
    traits::{BaseType, CircuitBaseType, CircuitVarType},
    wallet::WalletShare,
    PlonkCircuit,
};
use constants::{Scalar, ScalarField, MAX_BALANCES, MAX_ORDERS};
use mpc_plonk::errors::PlonkError;
use mpc_relation::{errors::CircuitError, proof_linking::GroupLayout, traits::Circuit, Variable};
use serde::{Deserialize, Serialize};

// ----------------------
// | Circuit Definition |
// ----------------------

/// The circuit implementation of `VALID MATCH SETTLE ATOMIC`
pub struct ValidMatchSettleAtomic<const MAX_BALANCES: usize, const MAX_ORDERS: usize>;
/// A `VALID MATCH SETTLE ATOMIC` with default state element sizing
pub type SizedValidMatchSettleAtomic = ValidMatchSettleAtomic<MAX_BALANCES, MAX_ORDERS>;

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize>
    ValidMatchSettleAtomic<MAX_BALANCES, MAX_ORDERS>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// The circuit constraints for `VALID MATCH SETTLE ATOMIC`
    pub fn circuit(
        statement: &ValidMatchSettleAtomicStatementVar<MAX_BALANCES, MAX_ORDERS>,
        witness: &ValidMatchSettleAtomicWitnessVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // TODO: Implement circuit constraints
        Ok(())
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for `VALID MATCH SETTLE ATOMIC`
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidMatchSettleAtomicWitness<const MAX_BALANCES: usize, const MAX_ORDERS: usize>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// The internal party's order
    pub internal_party_order: Order,
    /// The internal party's balance
    pub internal_party_balance: Balance,
    /// The internal party's receive balance
    pub internal_party_receive_balance: Balance,
    /// The internal party's managing relayer fee
    pub relayer_fee: FixedPoint,
    /// The internal party's fee obligations as a result of the match
    pub internal_party_fees: FeeTake,
}

/// A `VALID MATCH SETTLE ATOMIC` witness with default const generic sizing
/// parameters
pub type SizedValidMatchSettleAtomicWitness =
    ValidMatchSettleAtomicWitness<MAX_BALANCES, MAX_ORDERS>;

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for `VALID MATCH SETTLE ATOMIC`
#[circuit_type(singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidMatchSettleAtomicStatement<const MAX_BALANCES: usize, const MAX_ORDERS: usize>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// The modified public shares of the internal party
    pub internal_party_modified_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The indices that settlement should modify in the internal party's wallet
    pub internal_party_indices: OrderSettlementIndices,
    /// The protocol fee used in the match
    pub protocol_fee: FixedPoint,
}

/// A `VALID MATCH SETTLE ATOMIC` statement with default const generic sizing
/// parameters
pub type SizedValidMatchSettleAtomicStatement =
    ValidMatchSettleAtomicStatement<MAX_BALANCES, MAX_ORDERS>;

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize> SingleProverCircuit
    for ValidMatchSettleAtomic<MAX_BALANCES, MAX_ORDERS>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    type Statement = ValidMatchSettleAtomicStatement<MAX_BALANCES, MAX_ORDERS>;
    type Witness = ValidMatchSettleAtomicWitness<MAX_BALANCES, MAX_ORDERS>;

    fn name() -> String {
        format!("Valid Match Settle Atomic ({MAX_BALANCES}, {MAX_ORDERS})")
    }

    fn proof_linking_groups() -> Result<Vec<(String, Option<GroupLayout>)>, PlonkError> {
        // TODO: Implement proof linking groups
        Ok(vec![])
    }

    fn apply_constraints(
        witness_var: ValidMatchSettleAtomicWitnessVar<MAX_BALANCES, MAX_ORDERS>,
        statement_var: ValidMatchSettleAtomicStatementVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), PlonkError> {
        Self::circuit(&statement_var, &witness_var, cs).map_err(PlonkError::CircuitError)
    }
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod test {
    use super::*;

    // TODO: Implement test cases
}
