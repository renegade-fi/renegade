use ark_ff::PrimeField;
use ark_r1cs_std::{prelude::{EqGadget, Boolean, FieldVar}, uint8::UInt8, uint64::UInt64, select::CondSelectGadget, fields::fp::FpVar};
use ark_relations::r1cs::SynthesisError;
use std::marker::PhantomData;

use crate::types::{SingleMatchResultVar, BalanceVar, OrderVar, MatchVariable, Match};

use super::{util::GreaterThanEqGadget, poseidon::u64_to_field_element};

/**
 * Groups gadgets for checking whether a match is covered by balances and orders
 */

/**
 * Gadget
 */
// Validates that a match is internally consistent and valid with respect to
// given orders and balances
pub struct ValidMatchGadget<F: PrimeField> {
    _phantom: PhantomData<F>
}

impl<F: PrimeField> ValidMatchGadget<F> {
    pub fn enforce_valid(
        single_match: &SingleMatchResultVar<F>,
    ) -> Result<(), SynthesisError> {
        // Enforce that buy and sell sides line up
        single_match.buy_side1
            .side
            .enforce_equal(&UInt8::constant(0))?;
        
        single_match.buy_side2
            .side
            .enforce_equal(&UInt8::constant(0))?;
        
        single_match.sell_side1
            .side
            .enforce_equal(&UInt8::constant(1))?;
        
        single_match.sell_side2
            .side
            .enforce_equal(&UInt8::constant(1))?;
        
        // Enforce that mints are consistent across order sides
        single_match.buy_side1
            .mint
            .enforce_equal(&single_match.sell_side2.mint)?;
        
        single_match.buy_side2
            .mint
            .enforce_equal(&single_match.sell_side1.mint)?;
        
        // Enforce that amounts are consistent across order sides
        single_match.buy_side1
            .amount
            .enforce_equal(&single_match.sell_side2.amount)?;
        
        single_match.buy_side2
            .amount
            .enforce_equal(&single_match.sell_side1.amount)?;
        
        Ok(())
    }

    // Validates that the balances cover both sides of the order
    pub fn enforce_valid_balances(
        single_match: &SingleMatchResultVar<F>,
        balance1: &BalanceVar<F>,
        balance2: &BalanceVar<F>
    ) -> Result<(), SynthesisError> {
        // Mints must be equal and balances must be larger than transferred amount
        single_match.sell_side1
            .mint
            .enforce_equal(&balance1.mint)?;
        
        GreaterThanEqGadget::greater_than_u64(
            &balance1.amount, &single_match.sell_side1.amount
        )?.enforce_equal(&Boolean::TRUE)?;

        single_match.sell_side2
            .mint
            .enforce_equal(&balance2.mint)?;
        
        GreaterThanEqGadget::greater_than_u64(
            &balance2.amount, &single_match.sell_side2.amount
        )?.enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }

    // Validates that the match is the result of a valid pair of orders
    // Assumes the match is internally valid, i.e. enforce_valid should be
    // called separately
    pub fn enforce_valid_orders(
        single_match: &SingleMatchResultVar<F>,
        order1: &OrderVar<F>,
        order2: &OrderVar<F>,
    ) -> Result<(), SynthesisError> {
        let buy_amount1_fp = u64_to_field_element(&single_match.buy_side1.amount)?;
        let buy_amount2_fp = u64_to_field_element(&single_match.buy_side2.amount)?;
        let sell_amount1_fp = u64_to_field_element(&single_match.sell_side1.amount)?;
        let sell_amount2_fp = u64_to_field_element(&single_match.sell_side2.amount)?;
        
        let execution_price1 = buy_amount1_fp.mul_by_inverse(&sell_amount1_fp)?;
        let execution_price2 = buy_amount2_fp.mul_by_inverse(&sell_amount2_fp)?;

        // The buy order buys the base currency, select the execution price of the sell order
        // in units of quote/base
        let order1_buy = order1.side.is_eq(&UInt8::constant(0))?;
        let execution_price = FpVar::conditionally_select(
            &order1_buy, &execution_price2, &execution_price1
        )?;

        // Enforce for each order in the match that the price is favorable and the mints align
        Self::enforce_order_at_price(
            &execution_price, 
            &single_match.buy_side1,
            &single_match.sell_side1, 
            &order1,
        )?;

        Self::enforce_order_at_price(
            &execution_price, 
            &single_match.buy_side2, 
            &single_match.sell_side2, 
            &order2
        )?;

        Ok(())
    }

    fn enforce_order_at_price(
        price: &FpVar<F>,
        buy_side_match: &MatchVariable<F>,
        sell_side_match: &MatchVariable<F>,
        order: &OrderVar<F>
    ) -> Result<(), SynthesisError> {
        let is_buy = order.side.is_eq(&UInt8::constant(0))?;

        // Enforce that the mints are properly aligned with the match
        let buy_mint = UInt64::conditionally_select(
            &is_buy,
            &order.base_mint,
            &order.quote_mint
        )?;

        let sell_mint = UInt64::conditionally_select(
            &is_buy, 
            &order.quote_mint, 
            &order.base_mint
        )?;

        buy_side_match.mint.enforce_equal(&buy_mint)?;
        sell_side_match.mint.enforce_equal(&sell_mint)?;

        // Enforce that the price is equal or better than the limit in the order
        let order_price_fp = Boolean::le_bits_to_fp_var(&order.price.to_bits_le())?;
        let greater_than_order = GreaterThanEqGadget::greater_than(&price, &order_price_fp)?;
        let less_than_order = GreaterThanEqGadget::greater_than(&order_price_fp, &price)?;

        // For sell orders, the execution price should be >= to the limit price, for buy orders we use <= 
        Boolean::conditionally_select(
            &is_buy, 
            &less_than_order, 
            &greater_than_order
        )?.enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}
