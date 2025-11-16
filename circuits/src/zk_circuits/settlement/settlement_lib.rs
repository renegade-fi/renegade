//! Settlement gadget library
//!
//! This module contains helpers for settlement circuits.

use circuit_types::{
    AMOUNT_BITS, PlonkCircuit,
    balance::{BalanceVar, PostMatchBalanceShareVar},
    fee::FeeRatesVar,
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
        in_balance: &BalanceVar,
        out_balance: &BalanceVar,
        obligation: &SettlementObligationVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Verify the cross constraints which the intent and balances place on the
        // settlement obligation
        Self::verify_intent_constraints(intent, obligation, cs)?;
        Self::verify_in_balance_constraints(in_balance, obligation, cs)?;
        Self::verify_out_balance_constraints(intent, out_balance, obligation, cs)
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
        in_balance: &BalanceVar,
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
        out_balance: &BalanceVar,
        obligation: &SettlementObligationVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // The output balance's mint must match the obligation's output token
        EqGadget::constrain_eq(&out_balance.mint, &obligation.output_token, cs)?;

        // The output balance must be owned by the intent's owner
        EqGadget::constrain_eq(&out_balance.owner, &intent.owner, cs)?;

        // The output amount must not overflow the receive balance
        let new_bal_amount = cs.add(out_balance.amount, obligation.amount_out)?;
        AmountGadget::constrain_valid_amount(new_bal_amount, cs)
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
        fee_rates: &FeeRatesVar,
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
        // Rather than compute the fee, it is more efficient to compute the implied fee
        // from the output shares, this avoids using the floor gadget directly.
        Self::verify_output_balance_share_updates(
            fee_rates,
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
        fee_rates: &FeeRatesVar,
        old_shares: &PostMatchBalanceShareVar,
        new_shares: &PostMatchBalanceShareVar,
        obligation: &SettlementObligationVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Compute the fee take from the rate
        let fee_take = FeeGadget::compute_fee_take(obligation.amount_out, fee_rates, cs)?;
        let total_fee = FeeGadget::total_fee(&fee_take, cs)?;
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
