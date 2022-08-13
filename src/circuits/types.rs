use std::borrow::Borrow;

use ark_ff::PrimeField;
use ark_r1cs_std::{prelude::AllocVar, R1CSVar, uint64::UInt64, uint8::UInt8};
use ark_relations::r1cs::{SynthesisError, Namespace};

/**
 * Groups types definitions common to the circuit module
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
    pub quote_mint: UInt64<F>,
    pub base_mint: UInt64<F>,
    pub side: UInt8<F>,
    pub price: UInt64<F>,
    pub amount: UInt64<F>,
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
