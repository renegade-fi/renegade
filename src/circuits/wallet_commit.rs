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
    prelude::{AllocVar, EqGadget}, R1CSVar, ToBitsGadget, ToBytesGadget,
};
use std::{borrow::Borrow, marker::PhantomData};

use super::MAX_ORDERS;
use crate::circuits::comparators::GreaterThanEqGadget;

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

#[derive(Clone, Debug)]
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
#[derive(Debug)]
pub struct MatchesResult<F: Field> {
    pub matches: Vec<MatchVariable<F>>
}

impl<F: Field> MatchesResult<F> {
    pub fn new() -> Self {
        Self { matches: Vec::new() }
    } 
}

#[derive(Debug)]
pub struct MatchVariable<F: Field> {
    mint: UInt64<F>,
    amount: UInt64<F>,
    side: Boolean<F>
}

/**
 * Gadgets
 */

pub struct MatchGadget<F: PrimeField> {
    _phantom: PhantomData<F>
}

impl<F: PrimeField> MatchGadget<F> {
    pub fn compute_matches(
        wallet1: &WalletVar<F>,
        wallet2: &WalletVar<F>
    ) -> Result<MatchesResult<F>, SynthesisError> {
        let result = MatchesResult::<F>::new(); 
        let zero_u8 = UInt8::new_constant(wallet1.cs(), 0)?;

        for i in 0..MAX_ORDERS {
            for j in 0..MAX_ORDERS {
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
                
                // Find the execution price and mask it with the checks
            }
        }

        Err(SynthesisError::AssignmentMissing)
    }
}

// Checks one half of an order price overlap
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

#[cfg(test)]
mod overlap_test {
    use ark_ff::PrimeField;
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
    use ark_r1cs_std::{
        prelude::{AllocVar, EqGadget, Boolean}, 
        uint8::UInt8, 
        uint64::UInt64, R1CSVar
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
            200, 100, cs.clone()
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
            100, 100, cs.clone()
        );

        let result_var = OverlapGadget::is_overlapping(
            &side1_var, &price1_var, &side2_var, &price2_var
        ).unwrap();

        result_var.enforce_equal(&Boolean::TRUE).unwrap();
        assert!(cs.is_satisfied().unwrap())
    }
}