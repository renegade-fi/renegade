use ark_ed_on_bn254;
use ark_ff::PrimeField;
use ark_relations::{
    r1cs::{Field, Namespace, SynthesisError}
};
use ark_r1cs_std::{
    bits::{
        boolean::Boolean,
        uint64::UInt64,
        uint8::UInt8
    },
    prelude::{AllocVar, EqGadget}, 
    R1CSVar, ToBitsGadget
};
use serde::__private::de;
use std::{borrow::Borrow, marker::PhantomData};

use super::MAX_ORDERS;
use crate::circuits::gadgets::{
    GreaterThanEqGadget,
    MaskGadget,
    MinGadget
};

/**
 * Groups logic for arkworks gadets related to wallet commitments
 */

// The scalar field used throughout the proof system
pub type SystemField = ark_ed_on_bn254::Fr;

/**
 * Constraint system variables
 */

// Represents a wallet and its analog in the constraint system
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wallet {
    pub balances: Vec<Balance>,
    pub orders: Vec<Order>
}

#[derive(Debug)]
pub struct WalletVar<F: PrimeField> {
    pub balances: Vec<BalanceVar<F>>,
    pub orders: Vec<OrderVar<F>>
}

impl<F: PrimeField> AllocVar<Wallet, F> for WalletVar<F> {
    // Allocates a new variable in the given CS
    fn new_variable<T: Borrow<Wallet>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {

        // Map each balance into a constraint variable
        f().and_then(|wallet| {
            let cs = cs.into();
            let wallet: &Wallet = wallet.borrow();
            let balances: Vec<BalanceVar<F>> = wallet.balances
                .iter()
                .map(|balance| {
                    BalanceVar::new_variable(cs.clone(), || Ok(balance), mode)
                })
                .collect::<Result<Vec<BalanceVar<F>>, SynthesisError>>()?;
            
            let orders: Vec<OrderVar<F>> = wallet.orders
                .iter()
                .map(|order| {
                    OrderVar::new_variable(cs.clone(), || Ok(order), mode)
                })
                .collect::<Result<Vec<OrderVar<F>>, SynthesisError>>()?;

            Ok(Self { balances, orders })
        }) 
    }
}

impl<F: PrimeField> R1CSVar<F> for WalletVar<F> {
    type Value = Wallet;

    fn cs(&self) -> ark_relations::r1cs::ConstraintSystemRef<F> {
        self.balances.cs()
    }

    fn is_constant(&self) -> bool {
        self.balances.is_constant()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let balances = self.balances
            .iter()
            .map(|balance| {
                balance.value()
            })
            .collect::<Result<Vec<Balance>, SynthesisError>>()?;
        
        let orders = self.orders
            .iter()
            .map(|order| order.value())
            .collect::<Result<Vec<Order>, SynthesisError>>()?;
        
        Ok(Self::Value { balances, orders })
    }
}

// Represents a balance tuple and its analog in the constraint system
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Balance {
    mint: u64,
    amount: u64 
}

#[derive(Debug)]
pub struct BalanceVar<F: PrimeField> {
    pub mint: UInt64<F>,
    pub amount: UInt64<F>
}

impl<F: PrimeField> AllocVar<Balance, F> for BalanceVar<F> {
    fn new_variable<T: Borrow<Balance>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|balance| {
            let cs = cs.into();
            let mint = UInt64::new_variable(
                cs.clone(), 
                || Ok(balance.borrow().mint), 
                mode
            )?;

            let amount = UInt64::new_variable(
                cs.clone(), 
                || Ok(balance.borrow().amount), 
                mode
            )?;

            Ok(Self { mint, amount })
        })
    }
}

impl<F: PrimeField> R1CSVar<F> for BalanceVar<F> {
    type Value = Balance;

    fn cs(&self) -> ark_relations::r1cs::ConstraintSystemRef<F> {
        self.amount.cs()
    }

    fn is_constant(&self) -> bool {
        self.amount.is_constant()
    }

    fn value(&self) -> Result<Self::Value, ark_relations::r1cs::SynthesisError> {
        Ok(
            Balance {
                mint: self.mint.value()?,
                amount: self.amount.value()?
            }
        )
    }
}

// Represents an order and its analog in the consraint system
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Order {
    pub quote_mint: u64,
    pub base_mint: u64,
    pub side: OrderSide,
    pub price: u64,
    pub amount: u64
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrderSide {
    Buy = 0,
    Sell 
}

#[derive(Debug)]
pub struct OrderVar<F: PrimeField> {
    quote_mint: UInt64<F>,
    base_mint: UInt64<F>,
    side: UInt8<F>,
    price: UInt64<F>,
    amount: UInt64<F>,
}

impl<F: PrimeField> AllocVar<Order, F> for OrderVar<F> {
    fn new_variable<T: Borrow<Order>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|order| {
            let cs = cs.into();
            let quote_mint = UInt64::new_variable(
                cs.clone(), 
                || Ok(order.borrow().quote_mint), 
                mode
            )?;

            let base_mint = UInt64::new_variable(
                cs.clone(),
                || Ok(order.borrow().base_mint), 
                mode
            )?;

            let side = UInt8::new_variable(
                cs.clone(), 
                || {
                    match &order.borrow().side {
                        OrderSide::Buy => { Ok(0) },
                        OrderSide::Sell => { Ok(1) }
                    }
                }, 
                mode
            )?;

            let price = UInt64::new_variable(
                cs.clone(), 
                || Ok(order.borrow().price), 
                mode
            )?;

            let amount = UInt64::new_variable(
                cs.clone(), 
                || Ok(order.borrow().amount), 
                mode
            )?;

            Ok(OrderVar { quote_mint, base_mint, side, price, amount })
        })
    }
}

impl<F: PrimeField> R1CSVar<F> for OrderVar<F> {
    type Value = Order;

    fn cs(&self) -> ark_relations::r1cs::ConstraintSystemRef<F> {
        self.amount.cs()
    }

    fn is_constant(&self) -> bool {
        self.amount.is_constant()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(
            Order { 
                quote_mint: self.quote_mint.value()?,
                base_mint: self.base_mint.value()?,
                side: match self.side.value()? {
                    0 => { Ok(OrderSide::Buy) },
                    1 => { Ok(OrderSide::Sell) }
                    _ => { Err(SynthesisError::Unsatisfiable) }
                }?,
                price: self.price.value()?,
                amount: self.price.value()?
            }
        )
    }
}

// The result of a matches operation and its constraint system analog
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchResult {
    pub matches1: Vec<Match>,
    pub matches2: Vec<Match>
}

#[derive(Debug)]
pub struct MatchResultVariable<F: PrimeField> {
    pub matches1: Vec<MatchVariable<F>>,
    pub matches2: Vec<MatchVariable<F>>
}

impl<F: PrimeField> MatchResultVariable<F> {
    pub fn new() -> Self {
        Self { matches1: Vec::new(), matches2: Vec::new() }
    } 
}

impl<F: PrimeField> R1CSVar<F> for MatchResultVariable<F> {
    type Value = MatchResult;

    fn cs(&self) -> ark_relations::r1cs::ConstraintSystemRef<F> {
        self.matches1[0].cs()
    } 

    fn is_constant(&self) -> bool {
        self.matches1[0].is_constant()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let matches1 = self.matches1
            .iter()
            .map(|match_var| match_var.value())
            .collect::<Result<Vec<Match>, SynthesisError>>()?;
        
        let matches2 = self.matches2
            .iter()
            .map(|match_var| match_var.value())
            .collect::<Result<Vec<Match>, SynthesisError>>()?;
        
        Ok ( MatchResult { matches1, matches2 } )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    mint: u64,
    amount: u64,
    side: OrderSide
}

#[derive(Debug, Clone)]
pub struct MatchVariable<F: PrimeField> {
    mint: UInt64<F>,
    amount: UInt64<F>,
    side: UInt8<F>
}

impl<F: PrimeField> R1CSVar<F> for MatchVariable<F> {
    type Value = Match;

    fn cs(&self) -> ark_relations::r1cs::ConstraintSystemRef<F> {
        self.mint.cs()
    }

    fn is_constant(&self) -> bool {
        self.mint.is_constant()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(
            Match {
                mint: self.mint.value()?,
                amount: self.amount.value()?,
                side: match self.side.value()? {
                    0 => { Ok(OrderSide::Buy) },
                    1 => { Ok(OrderSide::Sell) },
                    _ => { Err(SynthesisError::Unsatisfiable) }
                }?
            }
        )
    }
}

/**
 * Gadgets
 */

pub struct OrderOverlapGadget<F: PrimeField> {
    _phantom: PhantomData<F>
}

impl<F: PrimeField> OrderOverlapGadget<F> {
    // Returns side1 * price1 >= side2 * price2
    pub fn is_overlapping(
        side1: &UInt8<F>,
        price1: &UInt64<F>,
        side2: &UInt8<F>,
        price2: &UInt64<F>
    ) -> Result<Boolean<F>, SynthesisError> {
        // Convert to Fp elements
        let side1_fp = Boolean::le_bits_to_fp_var(&side1.to_bits_le()?)?;
        let price1_fp = Boolean::le_bits_to_fp_var(&price1.to_bits_le())?;
        let side2_fp = Boolean::le_bits_to_fp_var(&side2.to_bits_le()?)?;
        let price2_fp = Boolean::le_bits_to_fp_var(&price2.to_bits_le())?;

        // side_2 * price_1 >= side_2 * price_2
        let check1 = GreaterThanEqGadget::greater_than(
            side2_fp.clone() * price1_fp.clone(),
            side2_fp.clone() * price2_fp.clone()
        )?;

        // side_1 * price_2 >= side_1 * price_1
        let check2 = GreaterThanEqGadget::greater_than(
            side1_fp.clone() * price2_fp.clone(),
            side1_fp.clone() * price1_fp.clone()
        )?;

        check1.and(&check2)
    }
}


pub struct MatchGadget<F: PrimeField> {
    _phantom: PhantomData<F>
}

impl<F: PrimeField> MatchGadget<F> {
    pub fn compute_matches(
        wallet1: &WalletVar<F>,
        wallet2: &WalletVar<F>
    ) -> Result<MatchResultVariable<F>, SynthesisError> {
        let mut result = MatchResultVariable::<F>::new(); 
        let zero_u8 = UInt8::new_constant(wallet1.cs(), 0)?;

        for i in 0..wallet1.orders.len() {
            for j in 0..wallet2.orders.len() {
                let order1 = wallet1.orders[i].borrow();
                let order2 = wallet2.orders[j].borrow();

                let quote_mints_equal = order1.quote_mint.is_eq(&order2.quote_mint)?;
                let base_mints_equal = order1.base_mint.is_eq(&order2.base_mint)?;

                // Check that counterparties are on opposite sides of the market
                let opposite_sides = order1.side
                    .xor(&order2.side)?
                    .is_eq(&zero_u8)?;

                // Checks that order_2_side * order_1_price >= order_2_side * order_2_price
                let overlap1 = OrderOverlapGadget::is_overlapping(
                    &order2.side, 
                    &order1.price, 
                    &order2.side, 
                    &order2.price
                )?;

                // Checks that order_2_side * order_1_price >= order_1_side * order_1_price
                let overlap2 = OrderOverlapGadget::is_overlapping(
                    &order2.side, 
                    &order1.price, 
                    &order1.side, 
                    &order1.price
                )?;

                // Aggregate all checks together
                let aggregated_checks = quote_mints_equal
                    .and(&base_mints_equal)?
                    .and(&opposite_sides)?
                    .and(&overlap1)?
                    .and(&overlap2)?;
                
                // Convert to integer for operations 
                // let check_mask = UInt64::from_bits_le(&[aggregated_checks]);
                
                // Find the execution price (midpoint) and mask it with the checks
                // (price1 + price2) / 2
                // Rotate right to emulate a shift right
                // then xor with 1 << 63 to mask the top bit
                let execution_price = UInt64::addmany(
                    &[order1.price.clone(), order2.price.clone()]
                )?
                    .rotr(1) 
                    .xor(&UInt64::<F>::constant(1 << 63))?;
                
                let base_swapped = MinGadget::min_uint64(order1.amount.clone(), order2.amount.clone())?;

                // Compute the amount of quote token swapped
                // Convert to field element then back to int
                let base_swapped_fp = Boolean::le_bits_to_fp_var(&base_swapped.to_bits_le())?;
                let execution_price_fp = Boolean::le_bits_to_fp_var(&execution_price.to_bits_le())?;
                
                let quote_swapped_fp = base_swapped_fp * execution_price_fp;
                let quote_swapped = UInt64::from_bits_le(&quote_swapped_fp.to_bits_le()?[..64]);

                // Mask output if the checks failed
                let quote_mint_masked = MaskGadget::mask_uint64(&order1.quote_mint, &aggregated_checks)?;
                let base_mint_masked = MaskGadget::mask_uint64(&order1.base_mint, &aggregated_checks)?;

                let base_swapped_masked = MaskGadget::mask_uint64(&base_swapped, &aggregated_checks)?;
                let quote_swapped_masked = MaskGadget::mask_uint64(&quote_swapped, &aggregated_checks)?;

                let side1_masked = MaskGadget::mask_uint8(&order1.side, &aggregated_checks)?;
                let side2_masked = MaskGadget::mask_uint8(&order2.side, &aggregated_checks)?;
                
                // For each party; add a match for the delta in quote token and the delta in base token
                // Instead of doing 1 - side; we simply use the other party's side as we have constrained them to be opposite
                result.matches1.push(
                    MatchVariable { 
                        mint: quote_mint_masked.clone(), 
                        amount: quote_swapped_masked.clone(), 
                        side: side2_masked.clone()
                    }
                );

                result.matches1.push(
                    MatchVariable { 
                        mint: base_mint_masked.clone(),
                        amount: base_swapped_masked.clone(),
                        side: side1_masked.clone()
                    }
                );

                result.matches2.push(
                    MatchVariable { 
                        mint: quote_mint_masked, 
                        amount: quote_swapped_masked,
                        side: side1_masked
                    }
                );

                result.matches2.push(
                    MatchVariable { 
                        mint: base_mint_masked,
                        amount: base_swapped_masked, 
                        side: side2_masked 
                    }
                );
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod overlap_test {
    use ark_ff::PrimeField;
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
    use ark_r1cs_std::{
        prelude::{AllocVar, EqGadget, Boolean}, 
        uint8::UInt8, 
        uint64::UInt64
    };
    use super::{SystemField, OrderOverlapGadget};

    type OverlapGadget = OrderOverlapGadget<SystemField>;

    fn setup_prices<F: PrimeField>(
        buy_price: u64, 
        sell_price: u64,
        cs: ConstraintSystemRef<F>
    ) -> (UInt8<F>, UInt64<F>, UInt8<F>, UInt64<F>) {
        // Buy side
        let side1_var = UInt8::new_witness(
            ark_relations::ns!(cs, "side1"), || Ok(0)  
        ).unwrap();
        let price1_var = UInt64::new_witness(
            ark_relations::ns!(cs, "price1"), || Ok(buy_price)
        ).unwrap();

        // Sell side
        let side2_var = UInt8::new_witness(
            ark_relations::ns!(cs, "side2"), || Ok(1)
        ).unwrap();
        let price2_var = UInt64::new_witness(
            ark_relations::ns!(cs, "price2"), || Ok(sell_price)
        ).unwrap();

        (side1_var, price1_var, side2_var, price2_var)
    }

    #[test]
    fn test_overlap_gadget_no_overlap() {
        let cs = ConstraintSystem::<SystemField>::new_ref();
        let (side1_var, price1_var, side2_var, price2_var) = setup_prices(
            100 /* buy_price */, 200 /* sell_price */, cs.clone(),
        );

        let result_var = OverlapGadget::is_overlapping(
            &side1_var, &price1_var, &side2_var, &price2_var
        ).unwrap();

        result_var.enforce_equal(&Boolean::TRUE).unwrap();
        assert!(!cs.is_satisfied().unwrap())
    }

    #[test]
    fn test_overlap_gadget_with_overlap() {
        let cs = ConstraintSystem::<SystemField>::new_ref();
        let (side1_var, price1_var, side2_var, price2_var) = setup_prices(
            200 /* buy_price */, 100 /* sell_price */, cs.clone()
        );

        let result_var = OverlapGadget::is_overlapping(
            &side1_var, &price1_var, &side2_var, &price2_var
        ).unwrap();

        result_var.enforce_equal(&Boolean::TRUE).unwrap();
        println!("Which unsatisfied: {:?}", cs.which_is_unsatisfied().unwrap());
        assert!(cs.is_satisfied().unwrap())
    }

    #[test]
    fn test_overlap_prices_equal() {
        let cs = ConstraintSystem::<SystemField>::new_ref();
        let (side1_var, price1_var, side2_var, price2_var) = setup_prices(
            100 /* buy_price */, 100 /* sell_price */, cs.clone()
        );

        let result_var = OverlapGadget::is_overlapping(
            &side1_var, &price1_var, &side2_var, &price2_var
        ).unwrap();

        result_var.enforce_equal(&Boolean::TRUE).unwrap();
        assert!(cs.is_satisfied().unwrap())
    }
}

#[cfg(test)]
mod match_test {
    use ark_r1cs_std::{prelude::AllocVar, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;

    use super::{Match, MatchGadget, Order, OrderSide, Wallet, WalletVar, SystemField};

    fn has_nonzero_match(matches_list: Vec<Match>) -> bool {
        matches_list.iter()
            .any(|match_res| {
                match_res.amount != 0 || match_res.mint != 0 || match_res.side == OrderSide::Sell // Sell side is 1
            })
    }

    #[test]
    fn test_match_different_mints() {
        // Build the wallets
        let wallet1 = Wallet {
            balances: vec![],
            orders: vec![
                Order { base_mint: 1, quote_mint: 2, price: 10, amount: 1, side: OrderSide::Buy }
            ]
        };

        let wallet2 = Wallet {
            balances: vec![],
            orders: vec![
                Order { base_mint: 3, quote_mint: 4, price: 10, amount: 1, side: OrderSide::Sell }
            ]
        };

        // Build the constraint system and variables
        let cs = ConstraintSystem::<SystemField>::new_ref();

        let wallet1_var = WalletVar::new_witness(cs.clone(), || Ok(wallet1)).unwrap();
        let wallet2_var = WalletVar::new_witness(cs.clone(), || Ok(wallet2)).unwrap();

        let res = MatchGadget::compute_matches(&wallet1_var, &wallet2_var)
            .unwrap()
            .value()
            .unwrap();
        
        // Both matches lists should be all zeroed
        assert!(!has_nonzero_match(res.matches1));
        assert!(!has_nonzero_match(res.matches2));
    }
}