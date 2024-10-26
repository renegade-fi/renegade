//! The single-prover implementation of `VALID MATCH SETTLE`

use ark_ff::{One, Zero};
use circuit_types::{
    balance::BalanceVar,
    fixed_point::{FixedPointVar, DEFAULT_FP_PRECISION},
    order::OrderVar,
    r#match::{FeeTakeVar, MatchResultVar, OrderSettlementIndicesVar},
    wallet::WalletShareVar,
    PlonkCircuit, AMOUNT_BITS,
};
use constants::ScalarField;
use mpc_relation::{errors::CircuitError, traits::Circuit, Variable};

use crate::zk_gadgets::{
    comparators::{EqGadget, GreaterThanEqGadget},
    fixed_point::FixedPointGadget,
    select::{CondSelectGadget, CondSelectVectorGadget},
    wallet_operations::{AmountGadget, PriceGadget},
};

use super::{ValidMatchSettle, ValidMatchSettleStatementVar, ValidMatchSettleWitnessVar};

// --- Matching Engine --- //

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize> ValidMatchSettle<MAX_BALANCES, MAX_ORDERS>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// The order crossing check, for a single prover
    ///
    /// Used to apply constraints to the verifier
    pub(crate) fn validate_matching_engine_singleprover(
        witness: &ValidMatchSettleWitnessVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let zero = ScalarField::zero();
        let one = ScalarField::one();

        let zero_var = cs.zero();
        let one_var = cs.one();

        // --- Order Crossing Constraints --- //
        // Check that both orders are for the matched asset pair
        cs.enforce_equal(witness.order0.quote_mint, witness.match_res.quote_mint)?;
        cs.enforce_equal(witness.order0.base_mint, witness.match_res.base_mint)?;
        cs.enforce_equal(witness.order1.quote_mint, witness.match_res.quote_mint)?;
        cs.enforce_equal(witness.order1.base_mint, witness.match_res.base_mint)?;

        // Check that the prices supplied by the parties are equal, these should be
        // agreed upon outside of the circuit
        EqGadget::constrain_eq(&witness.price0, &witness.price1, cs)?;
        // Validate that the price is valid, i.e. representable in a small enough number
        // of bits to avoid overflow
        PriceGadget::constrain_valid_price(witness.price0, cs)?;

        // The orders must be on opposite sides of the market
        // i.e. one must be a buy order and the other a sell order
        //     o1.side + o2.side == 1
        //
        // Note that the orders are constrained binary by their allocation as a
        // `BoolVar`
        cs.lc_gate(
            &[witness.order0.side.into(), witness.order1.side.into(), zero_var, zero_var, one_var],
            &[one, one, zero, zero],
        )?;

        // Check that the direction of the match is the same as the first party's
        // direction
        cs.enforce_equal(witness.match_res.direction.into(), witness.order0.side.into())?;

        // --- Match Volume Constraints --- //
        // Constrain that the pledged amount of each party is a valid amount
        AmountGadget::constrain_valid_amount(witness.amount0, cs)?;
        AmountGadget::constrain_valid_amount(witness.amount1, cs)?;

        let max_minus_min1 = cs.sub(witness.amount0, witness.amount1)?;
        let max_minus_min2 = cs.sub(witness.amount1, witness.amount0)?;
        let max_minus_min_amount = CondSelectGadget::select(
            &max_minus_min1,
            &max_minus_min2,
            witness.match_res.min_amount_order_index,
            cs,
        )?;

        // Constrain the `max_minus_min_amount` value to be in [0, 2^AMOUNT_BITS]
        // This effectively constrains this value to be correctly computed. As if
        // instead it were min(a, b) - max(a, b), then this value would be
        // negative.
        //
        // This constraint then also implicitly constrains the `min_amount_order_index`
        // value to be correct. This value is separately constrained to be 0 or
        // 1, as it is a `BoolVar`
        AmountGadget::constrain_valid_amount(max_minus_min_amount, cs)?;

        // Validate that the swapped amounts correctly reflect the minimum order amount
        // Order amounts are specified in the base asset, so the swapped base amount
        // should be the minimum of the two order amounts
        let min_amount = CondSelectGadget::select(
            &witness.amount1,
            &witness.amount0,
            witness.match_res.min_amount_order_index,
            cs,
        )?;
        cs.enforce_equal(witness.match_res.base_amount, min_amount)?;

        // The quote amount swapped should equal the price multiplied by the base amount
        // Here we round down to the nearest integer
        let expected_quote_amount =
            witness.price1.mul_integer(witness.match_res.base_amount, cs)?;
        FixedPointGadget::constrain_equal_floor(
            expected_quote_amount,
            witness.match_res.quote_amount,
            cs,
        )?;

        // --- Order & Balance Volume Constraints --- //

        // Check that the max amount match supplied by both parties is covered by the
        // balance and no greater than the amount specified in the order
        Self::validate_volume_constraints_single_prover(
            &witness.match_res,
            &witness.balance0,
            &witness.order0,
            cs,
        )?;

        Self::validate_volume_constraints_single_prover(
            &witness.match_res,
            &witness.balance1,
            &witness.order1,
            cs,
        )?;

        // --- Price Protection --- //
        // Check that the execution price is within the user-defined limits
        Self::verify_price_protection_single_prover(&witness.price0, &witness.order0, cs)?;
        Self::verify_price_protection_single_prover(&witness.price1, &witness.order1, cs)
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

        let new_balance = cs.sub(balance.amount, amount_sold)?;
        AmountGadget::constrain_valid_amount(new_balance, cs)
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

        // Constrain the difference to be representable in the maximum number of bits
        // that a price may take
        let lhs = gte_terms.remove(0);
        let rhs = gte_terms.remove(0);
        let price_improvement = lhs.sub(&rhs, cs);
        PriceGadget::constrain_valid_price(price_improvement, cs)
    }
}

// --- Settlement --- //

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize> ValidMatchSettle<MAX_BALANCES, MAX_ORDERS>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// The circuit representing `VALID SETTLE`
    pub fn validate_settlement_singleprover(
        statement: &ValidMatchSettleStatementVar<MAX_BALANCES, MAX_ORDERS>,
        witness: &ValidMatchSettleWitnessVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Select the balances received by each party
        let (base_amt, quote_amt) = (witness.match_res.base_amount, witness.match_res.quote_amount);
        let party0_party1_received = CondSelectGadget::select(
            &[quote_amt, base_amt],
            &[base_amt, quote_amt],
            witness.match_res.direction,
            cs,
        )?;

        let party0_received_amount = party0_party1_received[0];
        let party1_received_amount = party0_party1_received[1];

        // Party 0 settlement
        Self::validate_party_settlement_singleprover(
            party1_received_amount,
            party0_received_amount,
            base_amt,
            &witness.balance_receive0,
            witness.relayer_fee0,
            statement.protocol_fee,
            &witness.party0_fees,
            &statement.party0_indices,
            &witness.party0_public_shares,
            &statement.party0_modified_shares,
            cs,
        )?;

        // Party 1 settlement
        Self::validate_party_settlement_singleprover(
            party0_received_amount,
            party1_received_amount,
            base_amt,
            &witness.balance_receive1,
            witness.relayer_fee1,
            statement.protocol_fee,
            &witness.party1_fees,
            &statement.party1_indices,
            &witness.party1_public_shares,
            &statement.party1_modified_shares,
            cs,
        )
    }

    /// Validate the settlement of a single party
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_party_settlement_singleprover(
        send_amount: Variable,
        receive_amount: Variable,
        base_amount: Variable,
        receive_balance: &BalanceVar,
        relayer_fee: FixedPointVar,
        protocol_fee: FixedPointVar,
        fees: &FeeTakeVar,
        indices: &OrderSettlementIndicesVar,
        pre_update_shares: &WalletShareVar<MAX_BALANCES, MAX_ORDERS>,
        post_update_shares: &WalletShareVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Validate the fee take
        Self::validate_fee_take_singleprover(receive_amount, relayer_fee, protocol_fee, fees, cs)?;

        // Validate the balance updates
        Self::validate_balance_updates_singleprover(
            send_amount,
            receive_amount,
            receive_balance,
            fees,
            indices,
            pre_update_shares,
            post_update_shares,
            cs,
        )?;

        // Validate the order updates
        Self::validate_order_updates_singleprover(
            base_amount,
            indices,
            pre_update_shares,
            post_update_shares,
            cs,
        )?;

        // Validate the fees, keys, and blinders
        Self::validate_fees_keys_blinder_updates_singleprover(
            pre_update_shares,
            post_update_shares,
            cs,
        )
    }

    /// Validate a fee take for a given relayer fee and protocol fee
    fn validate_fee_take_singleprover(
        received_amount: Variable,
        relayer_fee: FixedPointVar,
        protocol_fee: FixedPointVar,
        fee_take: &FeeTakeVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let expected_relayer_fee = relayer_fee.mul_integer(received_amount, cs)?;
        let expected_protocol_fee = protocol_fee.mul_integer(received_amount, cs)?;

        FixedPointGadget::constrain_equal_floor(expected_relayer_fee, fee_take.relayer_fee, cs)?;
        FixedPointGadget::constrain_equal_floor(expected_protocol_fee, fee_take.protocol_fee, cs)
    }

    /// Verify that the balance updates to a wallet are valid
    ///
    /// That is, all balances in the settled wallet are the same as in the
    /// pre-settle wallet except for the balance sent and the balance
    /// received, which have the correct amounts applied from the match
    #[allow(clippy::too_many_arguments)]
    fn validate_balance_updates_singleprover(
        send_amount: Variable,
        received_amount: Variable,
        receive_balance: &BalanceVar,
        fees: &FeeTakeVar,
        indices: &OrderSettlementIndicesVar,
        pre_update_shares: &WalletShareVar<MAX_BALANCES, MAX_ORDERS>,
        post_update_shares: &WalletShareVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let one = ScalarField::one();
        let zero = ScalarField::zero();
        let zero_var = cs.zero();

        // Compute the trader's take net of their fee obligations
        let trader_take = cs.lc(
            &[received_amount, fees.relayer_fee, fees.protocol_fee, zero_var],
            &[one, -one, -one, zero],
        )?;

        // Check that no overflow occurs in the receive balance
        Self::validate_no_receive_overflow_singleprover(trader_take, receive_balance, fees, cs)?;

        // Check that the balances are updated correctly
        let mut curr_index = cs.zero();
        for (pre_update_balance, post_update_balance) in
            pre_update_shares.balances.iter().zip(post_update_shares.balances.iter())
        {
            // Mask the send term
            let send_term_index_mask = EqGadget::eq(&indices.balance_send, &curr_index, cs)?;
            let masked_send = cs.mul_with_coeff(send_term_index_mask.into(), send_amount, &-one)?;

            // Mask the receive term, this includes the fee takes of the match
            let receive_term_index_mask = EqGadget::eq(&indices.balance_receive, &curr_index, cs)?;
            let masked_receive = cs.mul(receive_term_index_mask.into(), trader_take)?;
            let masked_relayer_fee = cs.mul(receive_term_index_mask.into(), fees.relayer_fee)?;
            let masked_protocol_fee = cs.mul(receive_term_index_mask.into(), fees.protocol_fee)?;

            // Add in masked update terms to the pre-update balance
            let expected_balance_amount =
                cs.sum(&[pre_update_balance.amount, masked_send, masked_receive])?;
            let expected_balance_relayer_fee =
                cs.add(pre_update_balance.relayer_fee_balance, masked_relayer_fee)?;
            let expected_balance_protocol_fee =
                cs.add(pre_update_balance.protocol_fee_balance, masked_protocol_fee)?;

            // Ensure that the post-update balance is equal to the expected balance
            let mut expected_balance_shares = pre_update_balance.clone();
            expected_balance_shares.amount = expected_balance_amount;
            expected_balance_shares.relayer_fee_balance = expected_balance_relayer_fee;
            expected_balance_shares.protocol_fee_balance = expected_balance_protocol_fee;

            EqGadget::constrain_eq(&expected_balance_shares, post_update_balance, cs)?;

            // Increment the index
            curr_index = cs.add(curr_index, cs.one())?;
        }

        Ok(())
    }

    /// Validate that the receive balance amounts after update do not overflow
    fn validate_no_receive_overflow_singleprover(
        trader_take: Variable,
        receive_balance: &BalanceVar,
        fees: &FeeTakeVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let post_update_amount = cs.add(receive_balance.amount, trader_take)?;
        let post_update_relayer_fee =
            cs.add(receive_balance.relayer_fee_balance, fees.relayer_fee)?;
        let post_update_protocol_fee =
            cs.add(receive_balance.protocol_fee_balance, fees.protocol_fee)?;

        AmountGadget::constrain_valid_amount(post_update_amount, cs)?;
        AmountGadget::constrain_valid_amount(post_update_relayer_fee, cs)?;
        AmountGadget::constrain_valid_amount(post_update_protocol_fee, cs)
    }

    /// Verify that order updates to a wallet are valid
    ///
    /// The orders should all be equal except that the amount of the matched
    /// order should be decremented by the amount of the base token swapped
    fn validate_order_updates_singleprover(
        base_amount_swapped: Variable,
        indices: &OrderSettlementIndicesVar,
        pre_update_shares: &WalletShareVar<MAX_BALANCES, MAX_ORDERS>,
        post_update_shares: &WalletShareVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let one = ScalarField::one();

        let mut curr_index = cs.zero();
        for (pre_update_order, post_update_order) in
            pre_update_shares.orders.iter().zip(post_update_shares.orders.iter())
        {
            // Mask with the index
            let index_mask = EqGadget::eq(&indices.order, &curr_index, cs)?;
            let delta_term = cs.mul_with_coeff(index_mask.into(), base_amount_swapped, &-one)?;

            // Constrain the order update to be correct
            let expected_volume = cs.add(pre_update_order.amount, delta_term)?;
            let mut expected_order_shares = pre_update_order.clone();
            expected_order_shares.amount = expected_volume;

            EqGadget::constrain_eq(&expected_order_shares, post_update_order, cs)?;

            // Increment the index
            curr_index = cs.add(curr_index, cs.one())?;
        }

        Ok(())
    }

    /// Validate that fees, keys, and blinders remain the same in the pre and
    /// post wallet shares
    fn validate_fees_keys_blinder_updates_singleprover(
        pre_update_shares: &WalletShareVar<MAX_BALANCES, MAX_ORDERS>,
        post_update_shares: &WalletShareVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        EqGadget::constrain_eq(
            &pre_update_shares.managing_cluster,
            &post_update_shares.managing_cluster,
            cs,
        )?;
        EqGadget::constrain_eq(&pre_update_shares.match_fee, &post_update_shares.match_fee, cs)?;
        EqGadget::constrain_eq(&pre_update_shares.keys, &post_update_shares.keys, cs)?;
        EqGadget::constrain_eq(&pre_update_shares.blinder, &post_update_shares.blinder, cs)
    }
}
