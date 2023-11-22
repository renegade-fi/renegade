//! The single-prover implementation of `VALID MATCH SETTLE`

use ark_ff::{One, Zero};
use circuit_types::{
    balance::BalanceVar,
    fixed_point::{FixedPointVar, DEFAULT_FP_PRECISION},
    order::OrderVar,
    r#match::MatchResultVar,
    PlonkCircuit, AMOUNT_BITS, PRICE_BITS,
};
use constants::ScalarField;
use mpc_relation::{errors::CircuitError, traits::Circuit};

use crate::zk_gadgets::{
    comparators::{EqGadget, GreaterThanEqGadget, GreaterThanEqZeroGadget},
    fixed_point::FixedPointGadget,
    select::{CondSelectGadget, CondSelectVectorGadget},
};

use super::{ValidMatchSettle, ValidMatchSettleWitnessVar};

// --- Matching Engine --- //

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>
    ValidMatchSettle<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// The order crossing check, for a single prover
    ///
    /// Used to apply constraints to the verifier
    pub(crate) fn validate_matching_engine_singleprover(
        witness: &ValidMatchSettleWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let zero = ScalarField::zero();
        let one = ScalarField::one();

        let zero_var = cs.zero();
        let one_var = cs.one();

        // --- Match Engine Input Validity --- //
        // Check that both orders are for the matched asset pair
        cs.enforce_equal(witness.order1.quote_mint, witness.match_res.quote_mint)?;
        cs.enforce_equal(witness.order1.base_mint, witness.match_res.base_mint)?;
        cs.enforce_equal(witness.order2.quote_mint, witness.match_res.quote_mint)?;
        cs.enforce_equal(witness.order2.base_mint, witness.match_res.base_mint)?;

        // Check that the prices supplied by the parties are equal, these should be
        // agreed upon outside of the circuit
        EqGadget::constrain_eq(&witness.price1, &witness.price2, cs)?;

        // Check that the balances supplied are for the correct mints; i.e. for the mint
        // that each party sells in the settlement
        let mut selected_mints = CondSelectVectorGadget::select(
            &[witness.match_res.base_mint, witness.match_res.quote_mint],
            &[witness.match_res.quote_mint, witness.match_res.base_mint],
            witness.match_res.direction,
            cs,
        )?;

        cs.enforce_equal(witness.balance1.mint, selected_mints.remove(0))?;
        cs.enforce_equal(witness.balance2.mint, selected_mints.remove(0))?;

        // Check that the max amount match supplied by both parties is covered by the
        // balance no greater than the amount specified in the order
        Self::validate_volume_constraints_single_prover(
            &witness.match_res,
            &witness.balance1,
            &witness.order1,
            cs,
        )?;

        Self::validate_volume_constraints_single_prover(
            &witness.match_res,
            &witness.balance2,
            &witness.order2,
            cs,
        )?;

        // --- Match Engine Execution Validity --- //
        // Check that the direction of the match is the same as the first party's
        // direction
        cs.enforce_equal(
            witness.match_res.direction.into(),
            witness.order1.side.into(),
        )?;

        // Check that the orders are on opposite sides of the market. It is assumed that
        // order sides are already constrained to be binary when they are
        // submitted. More broadly it is assumed that orders are well formed,
        // checking this amounts to checking their inclusion in the state tree,
        // which is done in `input_consistency_check`
        cs.lc_gate(
            &[
                witness.order1.side.into(),
                witness.order2.side.into(),
                one_var,
                one_var,
                zero_var,
            ],
            &[one, one, -one, zero],
        )?;

        // Check that the amount of base currency exchanged is equal to the minimum of
        // the two order's amounts

        // 1. Constrain the max_minus_min_amount to be correctly computed with respect
        //    to the argmin
        // witness variable min_amount_order_index
        let max_minus_min1 = cs.sub(witness.amount1, witness.amount2)?;
        let max_minus_min2 = cs.sub(witness.amount2, witness.amount1)?;
        cs.mux_gate(
            witness.match_res.min_amount_order_index,
            max_minus_min1,
            max_minus_min2,
            witness.match_res.max_minus_min_amount, // out wire
        )?;

        // 2. Constrain the max_minus_min_amount value to be positive
        // This, along with the previous check, constrain `max_minus_min_amount` to be
        // computed correctly. I.e. the above constraint forces
        // `max_minus_min_amount` to be either max(amounts) - min(amounts)
        // or min(amounts) - max(amounts).
        // Constraining the value to be positive forces it to be equal to max(amounts) -
        // min(amounts)
        GreaterThanEqZeroGadget::<AMOUNT_BITS>::constrain_greater_than_zero(
            witness.match_res.max_minus_min_amount,
            cs,
        )?;

        // 3. Constrain the executed base amount to be the minimum of the two order
        //    amounts
        // We use the identity
        //      min(a, b) = 1/2 * (a + b - [max(a, b) - min(a, b)])
        // Above we are given max(a, b) - min(a, b), so we can enforce the constraint
        //      2 * executed_amount = amount1 + amount2 - max_minus_min_amount

        let two = ScalarField::from(2u64);
        cs.lc_gate(
            &[
                witness.match_res.base_amount,
                witness.amount1,
                witness.amount2,
                witness.match_res.max_minus_min_amount,
                zero_var, // output
            ],
            &[two, -one, -one, one],
        )?;

        // The quote amount should then equal the price multiplied by the base amount
        let expected_quote_amount = witness
            .price1
            .mul_integer(witness.match_res.base_amount, cs)?;
        FixedPointGadget::constrain_equal_integer_ignore_fraction(
            expected_quote_amount,
            witness.match_res.quote_amount,
            cs,
        )?;

        // --- Price Protection --- //
        Self::verify_price_protection_single_prover(&witness.price1, &witness.order1, cs)?;
        Self::verify_price_protection_single_prover(&witness.price2, &witness.order2, cs)
    }

    /// Check that a balance covers the advertised amount at a given price, and
    /// that the amount is less than the maximum amount allowed by the order
    fn validate_volume_constraints_single_prover(
        match_res: &MatchResultVar,
        balance: &BalanceVar,
        order: &OrderVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError>
    where
        [(); AMOUNT_BITS + DEFAULT_FP_PRECISION]: Sized,
    {
        // Validate that the amount is less than the maximum amount given in the order
        GreaterThanEqGadget::<AMOUNT_BITS>::constrain_greater_than_eq(
            order.amount,
            match_res.base_amount,
            cs,
        )?;

        // Validate that the amount matched is covered by the balance
        // If the direction of the order is 0 (buy the base) then the balance must
        // cover the amount of the quote token sold in the swap
        // If the direction of the order is 1 (sell the base) then the balance must
        // cover the amount of the base token sold in the swap
        let amount_sold = CondSelectGadget::select(
            &match_res.base_amount,
            &match_res.quote_amount,
            order.side,
            cs,
        )?;

        GreaterThanEqGadget::<AMOUNT_BITS>::constrain_greater_than_eq(
            balance.amount,
            amount_sold,
            cs,
        )
    }

    /// Verify the price protection on the orders; i.e. that the executed price
    /// is not worse than some user-defined limit
    fn verify_price_protection_single_prover(
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

        GreaterThanEqGadget::<PRICE_BITS>::constrain_greater_than_eq(
            gte_terms.remove(0).repr,
            gte_terms.remove(0).repr,
            cs,
        )
    }
}

// --- Settlement --- //

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>
    ValidMatchSettle<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// Validate settlement of a match result into the wallets of the two
    /// parties
    #[allow(clippy::needless_pass_by_ref_mut)]
    pub(crate) fn validate_settlement_singleprover(
        witness: &ValidMatchSettleWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        statement: (),
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        Ok(())
    }
}
