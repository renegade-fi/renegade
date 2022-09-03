
use ark_bn254::{Fr as Bn254Fr, Parameters};
use ark_ec::bn::Bn;
use ark_ff::{PrimeField, ToBytes};
use ark_r1cs_std::{prelude::AllocVar, R1CSVar, uint64::UInt64, uint8::UInt8};
use ark_relations::r1cs::{SynthesisError, Namespace};
use ark_sponge::{poseidon::PoseidonSponge, CryptographicSponge};
use num_bigint::BigUint;
use std::borrow::Borrow;
use std::io::{Result as IOResult, Write};

use crate::constants::{MAX_BALANCES, MAX_ORDERS};
use crate::gadgets::poseidon::PoseidonSpongeWrapperVar;

/**
 * Groups types definitions common to the circuit module
 */

// The scalar field used in the circuits
pub type SystemField = Bn254Fr;
// The pairing engine used throughout the proof system
pub type SystemPairingEngine = Bn<Parameters>;
// The depth of wallet state trees
pub const WALLET_TREE_DEPTH: usize = 8;

// Represents a wallet and its analog in the constraint system
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Wallet {
    pub balances: Vec<Balance>,
    pub orders: Vec<Order>,
    // The maximum number of orders to pad up to when matching, used
    // to shrink the complexity of unit tests
    _max_orders: usize,
    _max_balances: usize,
}

impl Wallet {
    pub fn new(balances: Vec<Balance>, orders: Vec<Order>) -> Self {
        Self::new_with_bounds(balances, orders, MAX_BALANCES, MAX_ORDERS)
    }

    // Allocates a new wallet but allows the caller to specify _max_orders and _max_balances
    // Used in tests to limit the complexity of the match computation
    pub fn new_with_bounds(
        balances: Vec<Balance>,
        orders: Vec<Order>,
        max_balances: usize,
        max_orders: usize
    ) -> Self {
        Self { balances, orders, _max_balances: max_balances, _max_orders: max_orders }
    }

    // Sets the maximum orders that this wallet is padded to when translated
    // into a WalletVar.
    // Used in unit tests to limit the complexity
    pub fn set_max_orders(&mut self, max_orders: usize) {
        assert!(max_orders >= self.orders.len());
        self._max_orders = max_orders;
    }

    pub fn set_max_balances(&mut self, max_balances: usize) {
        assert!(max_balances >= self.balances.len());
        self._max_balances = max_balances;
    }

    // Poseidon hash of the wallet
    pub fn hash(&self) -> BigUint {
        // Convert wallet to a vector of u64
        let mut hash_input = Vec::<u64>::new();
        for balance in self.balances.iter() {
            hash_input.append(&mut vec![balance.amount, balance.mint])
        }

        // Append empty balances up to MAX_BALANCES
        for _ in 0..(self._max_balances - self.balances.len()) {
            hash_input.append(&mut vec![0, 0])
        }

        for order in self.orders.iter() {
            hash_input.append(&mut vec![order.base_mint, order.quote_mint, order.side.clone() as u64, order.price, order.amount]);
        }

        // Append empty orders up to MAX_ORDERS
        for _ in 0..(self._max_orders - self.orders.len()) {
            hash_input.append(&mut vec![0, 0, 0, 0, 0])
        }

        let mut sponge = PoseidonSponge::<SystemField>::new(&PoseidonSpongeWrapperVar::default_params());
        for input in hash_input.iter() {
            sponge.absorb(input)
        }

        let sponge_out = sponge.squeeze_field_elements::<SystemField>(1)[0];

        // Convert to BigUInt
        sponge_out.into()
 
    }

    // Poseidon hash of the orders only 
    pub fn hash_orders(&self) -> BigUint {
        // Convert wallet to a vector of u64
        let mut hash_input = Vec::<u64>::new();
        for order in self.orders.iter() {
            hash_input.append(&mut vec![order.base_mint, order.quote_mint, order.side.clone() as u64, order.price, order.amount]);
        }

        // Append empty orders up to MAX_ORDERS
        for _ in 0..(MAX_ORDERS - self.orders.len()) {
            hash_input.append(&mut vec![0, 0, 0, 0, 0])
        }

        let mut sponge = PoseidonSponge::<SystemField>::new(&PoseidonSpongeWrapperVar::default_params());
        for input in hash_input.iter() {
            sponge.absorb(input)
        }

        let sponge_out = sponge.squeeze_field_elements::<SystemField>(1)[0];

        // Convert to BigUInt
        sponge_out.into()
    }
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
            let mut balances: Vec<BalanceVar<F>> = wallet.balances
                .iter()
                .map(|balance| {
                    BalanceVar::new_variable(cs.clone(), || Ok(balance), mode)
                })
                .collect::<Result<Vec<BalanceVar<F>>, SynthesisError>>()?;

            // Pad to the size of MAX_BALANCES with empty balances
            for _ in 0..(wallet._max_balances - wallet.balances.len()) {
                balances.push(
                    BalanceVar::new_variable(cs.clone(), || Ok(Balance::default()), mode)?
                )
            }
            
            let mut orders: Vec<OrderVar<F>> = wallet.orders
                .iter()
                .map(|order| {
                    OrderVar::new_variable(cs.clone(), || Ok(order), mode)
                })
                .collect::<Result<Vec<OrderVar<F>>, SynthesisError>>()?;
            
            // Pad to the size of MAX_ORDERS with empty orders
            for _ in 0..(wallet._max_orders - wallet.orders.len()) {
                orders.push(
                    OrderVar::new_variable(cs.clone(), || Ok(Order::default()), mode)?
                )
            }

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
        
        Ok(Self::Value::new(balances, orders))
    }
}

// Represents a balance tuple and its analog in the constraint system
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Balance {
    pub mint: u64,
    pub amount: u64 
}

impl Balance {
    pub fn hash(&self) -> BigUint {
        let hash_input = vec![self.mint, self.amount];

        let mut sponge = PoseidonSponge::<SystemField>::new(&PoseidonSpongeWrapperVar::default_params());
        for input in hash_input.iter() {
            sponge.absorb(input)
        }

        let sponge_out = sponge.squeeze_field_elements::<SystemField>(1)[0];

        // Convert to BigUInt
        sponge_out.into()
    }
}

impl ToBytes for Balance {
    fn write<W: Write>(&self, writer: W) -> IOResult<()> {
        vec![self.mint, self.amount].write(writer)
    }
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
                cs, 
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
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Order {
    pub quote_mint: u64,
    pub base_mint: u64,
    pub side: OrderSide,
    pub price: u64,
    pub amount: u64
}

impl Order {
    pub fn hash(&self) -> BigUint {
        let mut hash_input = Vec::<u64>::new();
        hash_input.append(&mut vec![
            self.quote_mint,
            self.base_mint,
            self.side.clone() as u64,
            self.price,
            self.amount
        ]);

        let mut sponge = PoseidonSponge::<SystemField>::new(&PoseidonSpongeWrapperVar::default_params());
        for input in hash_input.iter() {
            sponge.absorb(input)
        }

        let sponge_out = sponge.squeeze_field_elements::<SystemField>(1)[0];

        // Convert to BigUInt
        sponge_out.into()
    }
}

impl ToBytes for Order {
    fn write<W: Write>(&self, writer: W) -> IOResult<()> {
        vec![
            self.quote_mint, 
            self.base_mint, 
            self.side.clone() as u64, 
            self.price, 
            self.amount
        ].write(writer)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrderSide {
    Buy = 0,
    Sell 
}

// Default for an empty order is buy
impl Default for OrderSide {
    fn default() -> Self {
        OrderSide::Buy
    }
}

impl From<OrderSide> for u64 {
    fn from(order_side: OrderSide) -> Self {
        u8::from(order_side) as u64
    }
}

impl From<OrderSide> for u8 {
    fn from(order_side: OrderSide) -> Self {
        match order_side {
            OrderSide::Buy => { 0 }
            OrderSide::Sell => { 1 }
        }
    }
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
                cs, 
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
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MatchResult {
    pub matches1: Vec<Match>,
    pub matches2: Vec<Match>
}

#[derive(Clone, Debug)]
pub struct MatchResultVariable<F: PrimeField> {
    pub matches1: Vec<MatchVariable<F>>,
    pub matches2: Vec<MatchVariable<F>>
}

impl<F: PrimeField> AllocVar<MatchResult, F> for MatchResultVariable<F> {
    fn new_variable<T: Borrow<MatchResult>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> 
    {
        f().and_then(|match_result| {
            let cs = cs.into();
            let match_result: &MatchResult = match_result.borrow();
            let matches1 = match_result.matches1
                .iter()
                .map(|m| {
                    MatchVariable::new_variable(cs.clone(), || { Ok(m) }, mode)
                })
                .collect::<Result<Vec<MatchVariable<F>>, SynthesisError>>()?;

            let matches2 = match_result.matches2
                .iter()
                .map(|m| {
                    MatchVariable::new_variable(cs.clone(), || { Ok(m) }, mode)
                })
                .collect::<Result<Vec<MatchVariable<F>>, SynthesisError>>()?;

            Ok(Self { matches1, matches2 })
        })    
    }
}

impl<F: PrimeField> MatchResultVariable<F> {
    pub fn new() -> Self {
        Self { matches1: Vec::new(), matches2: Vec::new() }
    } 
}

impl<F: PrimeField> Default for MatchResultVariable<F> {
    fn default() -> Self {
        Self::new()
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

// Represents a match on a single set of orders overlapping
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SingleMatchResult {
    // Specifies the asset party 1 buys
    pub buy_side1: Match,
    // Specifies the asset party 1 sell
    pub sell_side1: Match,
    // Specifies the asset party 2 buys
    pub buy_side2: Match,
    // Specifies the asset party 2 sells
    pub sell_side2: Match,
}

pub struct SingleMatchResultVar<F: PrimeField> {
    pub buy_side1: MatchVariable<F>,
    pub sell_side1: MatchVariable<F>,
    pub buy_side2: MatchVariable<F>,
    pub sell_side2: MatchVariable<F>,
}

impl<F: PrimeField> AllocVar<SingleMatchResult, F> for SingleMatchResultVar<F> {
    fn new_variable<T: Borrow<SingleMatchResult>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|single_match| {
            let cs = cs.into();
            let single_match: &SingleMatchResult = single_match.borrow();

            Ok(
                Self { 
                    buy_side1: MatchVariable::new_variable(cs.clone(), || { Ok (single_match.buy_side1.clone()) }, mode)?,
                    sell_side1: MatchVariable::new_variable(cs.clone(), || { Ok(single_match.sell_side1.clone()) }, mode)?,
                    buy_side2: MatchVariable::new_variable(cs.clone(), || { Ok(single_match.buy_side2.clone()) }, mode)?,
                    sell_side2: MatchVariable::new_variable(cs, || { Ok(single_match.sell_side2.clone()) }, mode)?
                }
            )
        })
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Match {
    pub mint: u64,
    pub amount: u64,
    pub side: OrderSide
}

#[derive(Debug, Clone)]
pub struct MatchVariable<F: PrimeField> {
    pub mint: UInt64<F>,
    pub amount: UInt64<F>,
    pub side: UInt8<F>
}

impl<F: PrimeField> AllocVar<Match, F> for MatchVariable<F> {
    fn new_variable<T: Borrow<Match>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|match_| {
            let cs = cs.into();
            let match_: &Match = match_.borrow();
            Ok(
                Self {
                    mint: UInt64::new_variable(cs.clone(), || { Ok(match_.mint) }, mode)?,
                    amount: UInt64::new_variable(cs.clone(), || { Ok(match_.amount) }, mode)?,
                    side: match match_.side {
                        OrderSide::Buy => { UInt8::new_variable(cs, || { Ok(0) }, mode)? }
                        OrderSide::Sell => { UInt8::new_variable(cs, || { Ok(1) }, mode)? }
                    }
                }
            )
        })
    }
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
