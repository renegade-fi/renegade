//! Defines the VALID MATCH SETTLE ATOMIC circuit which verifies a match
//! between two parties; one internal and one external. An internal party is one
//! with state committed into the darkpool, while an external party is one whose
//! funds sit outside the darkpool, on the host chain.
//!
//! VALID MATCH SETTLE ATOMIC allows the external party to match against a known
//! internal order; emulating the standard deposit, order placement, settlement,
//! and withdrawal flow in a single transaction.

use crate::{
    zk_gadgets::{
        comparators::GreaterThanEqGadget,
        fixed_point::FixedPointGadget,
        select::{CondSelectGadget, CondSelectVectorGadget},
        wallet_operations::{AmountGadget, PriceGadget},
    },
    SingleProverCircuit,
};
use circuit_macros::circuit_type;
use circuit_types::{
    balance::{Balance, BalanceVar},
    fixed_point::{FixedPoint, FixedPointVar},
    order::{Order, OrderVar},
    r#match::{ExternalMatchResult, ExternalMatchResultVar, FeeTake, OrderSettlementIndices},
    traits::{BaseType, CircuitBaseType, CircuitVarType},
    wallet::WalletShare,
    PlonkCircuit, AMOUNT_BITS,
};
use constants::{Scalar, ScalarField, MAX_BALANCES, MAX_ORDERS};
use mpc_plonk::errors::PlonkError;
use mpc_relation::{errors::CircuitError, proof_linking::GroupLayout, traits::Circuit, Variable};
use serde::{Deserialize, Serialize};

use super::valid_match_settle::ValidMatchSettle;

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
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Validate the matching engine
        Self::validate_matching_engine(statement, witness, cs)?;

        // Validate the internal party's settlement
        Self::validate_settlement(statement, witness, cs)
    }

    // --- Matching Engine Constraints --- //

    /// Validate the match result
    fn validate_matching_engine(
        statement: &ValidMatchSettleAtomicStatementVar<MAX_BALANCES, MAX_ORDERS>,
        witness: &ValidMatchSettleAtomicWitnessVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let internal_order = &witness.internal_party_order;
        let match_res = &statement.match_result;

        // Check that the match is on the correct pair, in the correct direction
        cs.enforce_equal(internal_order.quote_mint, match_res.quote_mint)?;
        cs.enforce_equal(internal_order.base_mint, match_res.base_mint)?;
        cs.enforce_equal(internal_order.side.into(), match_res.direction.into())?;

        // Validate the volumes and price at which the match executes
        Self::validate_price(witness.price, &statement.match_result, cs)?;
        AmountGadget::constrain_valid_amount(match_res.quote_amount, cs)?;
        AmountGadget::constrain_valid_amount(match_res.base_amount, cs)?;

        // Check that the matched volume does not exceed the internal party's order and
        // that it is capitalized by the internal party's send balance
        Self::validate_volume_constraints(
            &witness.internal_party_order,
            &witness.internal_party_balance,
            &statement.match_result,
            cs,
        )?;

        // Check that the price is within the user-defined limits
        Self::validate_price_protection(&witness.price, &witness.internal_party_order, cs)
    }

    /// Validate the price that the match executed at
    fn validate_price(
        price: FixedPointVar,
        match_res: &ExternalMatchResultVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // The price must be representable as a fixed point
        PriceGadget::constrain_valid_price(price, cs)?;

        // Check that the price implied by the match matches the price in the witness
        let base_amount = match_res.base_amount;
        let quote_amount = match_res.quote_amount;
        let expected_quote = price.mul_integer(base_amount, cs)?;
        FixedPointGadget::constrain_equal_integer_ignore_fraction(expected_quote, quote_amount, cs)
    }

    /// Validate that the internal party's balance capitalizes their side of the
    /// match
    fn validate_volume_constraints(
        internal_party_order: &OrderVar,
        internal_party_balance: &BalanceVar,
        match_res: &ExternalMatchResultVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Check that the match amount is less than or equal to the internal party's
        // order size
        let order_amount = internal_party_order.amount;
        let match_amount = match_res.base_amount;
        GreaterThanEqGadget::<AMOUNT_BITS>::constrain_greater_than_eq(
            order_amount,
            match_amount,
            cs,
        )?;

        // Check that the internal party's balance covers the amount of the match
        // If the direction of the order is 0 (buy the base) then the balance must
        // cover the amount of the quote token sold in the swap
        // If the direction of the order is 1 (sell the base) then the balance must
        // cover the amount of the base token sold in the swap
        let side = internal_party_order.side;
        let sell_amount =
            CondSelectGadget::select(&match_res.base_amount, &match_res.quote_amount, side, cs)?;

        let new_balance = cs.sub(internal_party_balance.amount, sell_amount)?;
        AmountGadget::constrain_valid_amount(new_balance, cs)
    }

    /// Validate that the execution price is within the user-defined limits
    fn validate_price_protection(
        price: &FixedPointVar,
        order: &OrderVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // If the order is buy side, verify that the execution price is less
        // than the limit price. If the order is sell side, verify that the
        // execution price is greater than the limit price
        let mut gte_terms: Vec<FixedPointVar> = CondSelectVectorGadget::select(
            &[*price, order.worst_case_price],
            &[order.worst_case_price, *price],
            order.side,
            cs,
        )?;

        // Constrain the difference to be representable in the maximum number of bits
        // that a price may take
        let lhs = gte_terms.remove(0);
        let rhs = gte_terms.remove(0);
        let price_improvement = lhs.sub(&rhs, cs);
        PriceGadget::constrain_valid_price(price_improvement, cs)
    }

    // --- Settlement Constraints --- //

    /// Validate the settlement of the atomic match
    fn validate_settlement(
        statement: &ValidMatchSettleAtomicStatementVar<MAX_BALANCES, MAX_ORDERS>,
        witness: &ValidMatchSettleAtomicWitnessVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let match_res = &statement.match_result;
        let (base_amt, quote_amt) = (match_res.base_amount, match_res.quote_amount);
        let send_amt_receive_amt = CondSelectVectorGadget::select(
            &[base_amt, quote_amt],
            &[quote_amt, base_amt],
            match_res.direction,
            cs,
        )?;
        let (send_amt, receive_amt) = (send_amt_receive_amt[0], send_amt_receive_amt[1]);

        // Validate the internal party's settlement directly using the standard
        // settlement logic
        ValidMatchSettle::validate_party_settlement_singleprover(
            send_amt,
            receive_amt,
            base_amt,
            &witness.internal_party_receive_balance,
            witness.relayer_fee,
            statement.protocol_fee,
            &witness.internal_party_fees,
            &statement.internal_party_indices,
            &witness.internal_party_public_shares,
            &statement.internal_party_modified_shares,
            cs,
        )
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
    /// The price at which the match executes
    pub price: FixedPoint,
    /// The internal party's managing relayer fee
    pub relayer_fee: FixedPoint,
    /// The internal party's fee obligations as a result of the match
    pub internal_party_fees: FeeTake,
    /// The internal party's public shares before settlement
    pub internal_party_public_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
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
    /// The result of the match
    pub match_result: ExternalMatchResult,
    /// The external party's fee obligations as a result of the match
    pub external_party_fees: FeeTake,
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
