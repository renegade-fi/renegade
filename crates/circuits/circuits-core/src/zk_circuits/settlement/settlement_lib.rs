//! Settlement gadget library
//!
//! This module contains helpers for settlement circuits.

use circuit_types::{AMOUNT_BITS, PRICE_BITS, PlonkCircuit};
use darkpool_types::{
    balance::{DarkpoolBalanceVar, PostMatchBalanceShareVar},
    bounded_match_result::BoundedMatchResultVar,
    fee::FeeTakeVar,
    intent::IntentVar,
    settlement_obligation::SettlementObligationVar,
};
use mpc_relation::{Variable, errors::CircuitError, traits::Circuit};

use crate::zk_gadgets::{
    comparators::{EqGadget, GreaterThanEqGadget},
    fee::FeeGadget,
    fixed_point::FixedPointGadget,
    primitives::bitlength::AmountGadget,
};

/// The settlement gadget encapsulates common functionality for settlement
/// circuits
pub struct SettlementGadget;
impl SettlementGadget {
    // --- Intent and Balance <-> Obligation Constraints --- //

    /// Verify the intent and balance constraints on a settlement obligation
    pub fn verify_intent_and_balance_obligation_constraints(
        intent: &IntentVar,
        in_balance: &DarkpoolBalanceVar,
        out_balance: &DarkpoolBalanceVar,
        obligation: &SettlementObligationVar,
        fee_take: &FeeTakeVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Verify the cross constraints which the intent and balances place on the
        // settlement obligation
        Self::verify_intent_constraints(intent, obligation, cs)?;
        Self::verify_in_balance_constraints(in_balance, obligation, cs)?;
        Self::verify_out_balance_constraints(intent, out_balance, fee_take, obligation, cs)
    }

    /// Verify that the intent's constraints are satisfied
    pub fn verify_intent_constraints(
        intent: &IntentVar,
        obligation: &SettlementObligationVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // The settlement obligation's token pair must match that of the intent
        EqGadget::constrain_eq(&obligation.input_token, &intent.in_token, cs)?;
        EqGadget::constrain_eq(&obligation.output_token, &intent.out_token, cs)?;

        // The input amount of the obligation must not exceed the intent's amount
        GreaterThanEqGadget::constrain_greater_than_eq(
            intent.amount_in,
            obligation.amount_in,
            AMOUNT_BITS,
            cs,
        )?;

        // The settlement obligation must exceed the intent's worst case price
        // `intent.min_price` is in units of `out_token/in_token` so we need only clear
        // the denominator
        let min_output_fp =
            FixedPointGadget::mul_integer(intent.min_price, obligation.amount_in, cs)?;
        let min_output = FixedPointGadget::floor(min_output_fp, cs)?;
        GreaterThanEqGadget::constrain_greater_than_eq(
            obligation.amount_out,
            min_output,
            AMOUNT_BITS,
            cs,
        )?;

        Ok(())
    }
    /// Verify that the balance's constraints are satisfied
    ///
    /// We only need to verify that the balance adequately capitalizes the
    /// obligation. The pre-settlement validity proofs will verify that the mint
    /// of the balance matches the mint of the intent, and thereby the
    /// obligation.
    fn verify_in_balance_constraints(
        in_balance: &DarkpoolBalanceVar,
        obligation: &SettlementObligationVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // The balance must exceed the obligation's input amount
        GreaterThanEqGadget::constrain_greater_than_eq(
            in_balance.amount,
            obligation.amount_in,
            AMOUNT_BITS,
            cs,
        )
    }

    /// Verify receive balance constraints
    fn verify_out_balance_constraints(
        intent: &IntentVar,
        out_balance: &DarkpoolBalanceVar,
        fee_take: &FeeTakeVar,
        obligation: &SettlementObligationVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // The output balance's mint must match the obligation's output token
        EqGadget::constrain_eq(&out_balance.mint, &obligation.output_token, cs)?;

        // The output balance must be owned by the intent's owner
        EqGadget::constrain_eq(&out_balance.owner, &intent.owner, cs)?;

        // The output amount must not overflow the receive balance
        let total_fee = FeeGadget::total_fee(fee_take, cs)?;
        let net_receive = cs.sub(obligation.amount_out, total_fee)?;
        let new_bal_amount = cs.add(out_balance.amount, net_receive)?;
        AmountGadget::constrain_valid_amount(new_bal_amount, cs)?;

        let new_relayer_fee_balance =
            cs.add(out_balance.relayer_fee_balance, fee_take.relayer_fee)?;
        let new_protocol_fee_balance =
            cs.add(out_balance.protocol_fee_balance, fee_take.protocol_fee)?;
        AmountGadget::constrain_valid_amount(new_relayer_fee_balance, cs)?;
        AmountGadget::constrain_valid_amount(new_protocol_fee_balance, cs)?;

        Ok(())
    }

    // --- State Update Constraints --- //

    /// Verify the update to the public shares of the state elements after
    /// settlement
    ///
    /// We need to verify the following updates:
    /// - The intent's amount public share should decrease by obligation input
    /// - The input balance's amount should decrease by the obligation input
    /// - The output balance's amount should increase by the obligation output
    /// - The output balance's relayer fee balance should increase by the
    ///   relayer fee; computed from the fee rate
    /// - The output balance's protocol fee balance should increase by the
    ///   protocol fee; computed from the fee rate
    ///
    /// We can rely on the additive homomorphic property of our stream cipher
    /// for each of these updates.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_state_updates(
        fee_take: &FeeTakeVar,
        intent_amount_public_share: Variable,
        new_amount_public_share: Variable,
        in_balance_public_shares: &PostMatchBalanceShareVar,
        new_in_balance_public_shares: &PostMatchBalanceShareVar,
        out_balance_public_shares: &PostMatchBalanceShareVar,
        new_out_balance_public_shares: &PostMatchBalanceShareVar,
        obligation: &SettlementObligationVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Intent update
        let expected_amount_public_share =
            cs.sub(intent_amount_public_share, obligation.amount_in)?;
        EqGadget::constrain_eq(&expected_amount_public_share, &new_amount_public_share, cs)?;

        // Input balance update
        let mut expected_shares = in_balance_public_shares.clone();
        expected_shares.amount = cs.sub(in_balance_public_shares.amount, obligation.amount_in)?;
        EqGadget::constrain_eq(&expected_shares, new_in_balance_public_shares, cs)?;

        // Output balance update
        Self::verify_output_balance_share_updates(
            fee_take,
            out_balance_public_shares,
            new_out_balance_public_shares,
            obligation,
            cs,
        )
    }

    /// Verify the output balance share updates
    ///
    /// This includes verifying the computation of the fees from their rates.
    /// Each trader pays a fee on the receive side of the settlement.
    fn verify_output_balance_share_updates(
        fee_take: &FeeTakeVar,
        old_shares: &PostMatchBalanceShareVar,
        new_shares: &PostMatchBalanceShareVar,
        obligation: &SettlementObligationVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Compute the trader's receive amount net of fees
        let total_fee = FeeGadget::total_fee(fee_take, cs)?;
        let net_receive = cs.sub(obligation.amount_out, total_fee)?;

        // Apply the receive amount and fees to the shares
        let mut expected_shares = old_shares.clone();
        expected_shares.amount = cs.add(old_shares.amount, net_receive)?;
        expected_shares.relayer_fee_balance =
            cs.add(old_shares.relayer_fee_balance, fee_take.relayer_fee)?;
        expected_shares.protocol_fee_balance =
            cs.add(old_shares.protocol_fee_balance, fee_take.protocol_fee)?;
        EqGadget::constrain_eq(&expected_shares, new_shares, cs)
    }
}

/// The bounded settlement gadget encapsulates common functionality for bounded
/// settlement circuits
pub struct BoundedSettlementGadget;
impl BoundedSettlementGadget {
    // --- Intent and Balance <-> Bounded Match Result Constraints --- //

    /// Verify the intent and balance constraints for a bounded match result
    pub fn verify_intent_and_balance_bounded_match_result_constraints(
        intent: &IntentVar,
        in_balance: &DarkpoolBalanceVar,
        out_balance: &DarkpoolBalanceVar,
        bounded_match_result: &BoundedMatchResultVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Verify the cross constraints which the intent and balances place on the
        // bounded match result
        Self::verify_intent_constraints(intent, bounded_match_result, cs)?;
        Self::verify_in_balance_constraints(in_balance, bounded_match_result, cs)?;
        Self::verify_out_balance_constraints(out_balance, intent, bounded_match_result, cs)
    }

    /// Verify that the intent's constraints are satisfied by a bounded match
    /// result
    pub fn verify_intent_constraints(
        intent: &IntentVar,
        bounded_match_result: &BoundedMatchResultVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // The bounded match result's input token must match the intent's input token
        EqGadget::constrain_eq(
            &bounded_match_result.internal_party_input_token,
            &intent.in_token,
            cs,
        )?;
        EqGadget::constrain_eq(
            &bounded_match_result.internal_party_output_token,
            &intent.out_token,
            cs,
        )?;

        // The upper bound of the bounded match result must not exceed the intent's
        // amount. The contract validates that min <= max <= amount_in, so we only
        // need to check the upper bound here.
        GreaterThanEqGadget::constrain_greater_than_eq(
            intent.amount_in,
            bounded_match_result.max_internal_party_amount_in,
            AMOUNT_BITS,
            cs,
        )?;

        // The bounded match result must exceed the intent's worst case price
        // `bounded_match_result.price` has the same units as `intent.min_price`
        GreaterThanEqGadget::constrain_greater_than_eq(
            bounded_match_result.price.repr,
            intent.min_price.repr,
            PRICE_BITS,
            cs,
        )?;

        Ok(())
    }

    /// Verify that the balance's constraints are satisfied by the upper bound
    /// of the bounded match result
    ///
    /// The contract validates that:
    /// - min_internal_party_amount_in <= max_internal_party_amount_in
    ///
    /// Therefore, we only need to check that the balance can capitalize the
    /// upper bound here.
    ///
    /// Note: The balance.mint == intent.in_token constraint is enforced by
    /// the INTENT AND BALANCE VALIDITY proof via proof-linking.
    fn verify_in_balance_constraints(
        in_balance: &DarkpoolBalanceVar,
        bounded_match_result: &BoundedMatchResultVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // The balance must exceed the bounded match result's maximum input amount
        GreaterThanEqGadget::constrain_greater_than_eq(
            in_balance.amount,
            bounded_match_result.max_internal_party_amount_in,
            AMOUNT_BITS,
            cs,
        )
    }

    /// Verify receive balance constraints
    ///
    /// The contract validates that min <= max <= amount_in, so we only need to
    /// check the upper bound here.
    fn verify_out_balance_constraints(
        out_balance: &DarkpoolBalanceVar,
        intent: &IntentVar,
        bounded_match_result: &BoundedMatchResultVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // The output balance's mint must match the bounded match result's output token
        EqGadget::constrain_eq(
            &out_balance.mint,
            &bounded_match_result.internal_party_output_token,
            cs,
        )?;

        // The output balance must be owned by the intent's owner
        EqGadget::constrain_eq(&out_balance.owner, &intent.owner, cs)?;

        // The output amount must not overflow the receive balance
        // We use the price and upper bound of the bounded match result to compute
        // the maximum output amount.
        let max_output_fp = FixedPointGadget::mul_integer(
            bounded_match_result.price,
            bounded_match_result.max_internal_party_amount_in,
            cs,
        )?;
        let max_output = FixedPointGadget::floor(max_output_fp, cs)?;
        let max_bal_amount = cs.add(out_balance.amount, max_output)?;
        AmountGadget::constrain_valid_amount(max_bal_amount, cs)
    }
}
