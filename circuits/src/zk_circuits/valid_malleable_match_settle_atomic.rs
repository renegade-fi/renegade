//! Defines a malleable version of the `VALID MATCH SETTLE ATOMIC` circuit
//!
//! Malleable here means that the match amount is not known at the time the
//! witness and statement are created. Instead, we constrain a valid range of
//! amounts that the internal order and balance can support

// ----------------------
// | Circuit Definition |
// ----------------------

use circuit_macros::circuit_type;
use circuit_types::{
    balance::Balance,
    fees::FeeTakeRate,
    order::Order,
    r#match::BoundedMatchResult,
    traits::{BaseType, CircuitBaseType, CircuitVarType, SingleProverCircuit},
    wallet::WalletShare,
    Address, PlonkCircuit,
};
use constants::{Scalar, ScalarField, MAX_BALANCES, MAX_ORDERS};
use mpc_plonk::errors::PlonkError;
use mpc_relation::{errors::CircuitError, proof_linking::GroupLayout, traits::Circuit, Variable};
use serde::{Deserialize, Serialize};

/// The circuit implementation of `VALID MALLEABLE MATCH SETTLE ATOMIC`
pub struct ValidMalleableMatchSettleAtomic<const MAX_BALANCES: usize, const MAX_ORDERS: usize>;
/// A `VALID MALLEABLE MATCH SETTLE ATOMIC` with default state element sizing
pub type SizedValidMalleableMatchSettleAtomic =
    ValidMalleableMatchSettleAtomic<MAX_BALANCES, MAX_ORDERS>;

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize>
    ValidMalleableMatchSettleAtomic<MAX_BALANCES, MAX_ORDERS>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// The circuit constraints for `VALID MALLEABLE MATCH SETTLE ATOMIC`
    pub fn circuit(
        statement: ValidMalleableMatchSettleAtomicStatementVar<MAX_BALANCES, MAX_ORDERS>,
        witness: ValidMalleableMatchSettleAtomicWitnessVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        todo!("define constraints")
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for `VALID MALLEABLE MATCH SETTLE ATOMIC`
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidMalleableMatchSettleAtomicWitness<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// The internal party's order
    pub internal_party_order: Order,
    /// The internal party's balance
    pub internal_party_balance: Balance,
    /// The internal party's receive balance
    pub internal_party_receive_balance: Balance,
    /// The internal party's public shares before settlement
    pub internal_party_public_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
}

/// The statement type for `VALID MALLEABLE MATCH SETTLE ATOMIC`
#[circuit_type(singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidMalleableMatchSettleAtomicStatement<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// The result of the match
    pub match_result: BoundedMatchResult,
    /// The fee rates charged to the external party
    pub external_fee_rates: FeeTakeRate,
    /// The fee rates charged to the internal party
    pub internal_fee_rates: FeeTakeRate,
    /// The public wallet shares of the internal party
    pub internal_party_public_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The address at which the relayer wishes to receive their fee due from
    /// the external party
    pub relayer_fee_address: Address,
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize> SingleProverCircuit
    for ValidMalleableMatchSettleAtomic<MAX_BALANCES, MAX_ORDERS>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    type Statement = ValidMalleableMatchSettleAtomicStatement<MAX_BALANCES, MAX_ORDERS>;
    type Witness = ValidMalleableMatchSettleAtomicWitness<MAX_BALANCES, MAX_ORDERS>;

    fn name() -> String {
        format!("VALID MALLEABLE MATCH SETTLE ATOMIC ({MAX_BALANCES}, {MAX_ORDERS})")
    }

    fn proof_linking_groups() -> Result<Vec<(String, Option<GroupLayout>)>, PlonkError> {
        Ok(vec![])
    }

    fn apply_constraints(
        witness_var: ValidMalleableMatchSettleAtomicWitnessVar<MAX_BALANCES, MAX_ORDERS>,
        statement_var: ValidMalleableMatchSettleAtomicStatementVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), PlonkError> {
        Self::circuit(statement_var, witness_var, cs).map_err(PlonkError::CircuitError)
    }
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: Add tests
}
