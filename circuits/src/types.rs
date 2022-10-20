use curve25519_dalek::scalar::Scalar;
use mpc_ristretto::beaver::SharedValueSource;

use crate::{
    constants::{MAX_BALANCES, MAX_ORDERS},
    errors::MpcError,
    mpc::SharedScalar,
};

/**
 * Groups types definitions common to the circuit module
 */

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
        max_orders: usize,
    ) -> Self {
        Self {
            balances,
            orders,
            _max_balances: max_balances,
            _max_orders: max_orders,
        }
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
}

// Represents a balance tuple and its analog in the constraint system
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Balance {
    pub mint: u64,
    pub amount: u64,
}

// Represents an order and its analog in the consraint system
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Order {
    /// The mint (ERC-20 contract address) of the quote token
    pub quote_mint: u64,
    /// The mint (ERC-20 contract address) of the base token
    pub base_mint: u64,
    /// The side this order is for (0 = buy, 1 = sell)
    pub side: OrderSide,
    /// The limit price to be executed at, in units of quote
    pub price: u64,
    /// The amount of base currency to buy or sell
    pub amount: u64,
}

/// Convert an order to a vector of u64s
/// This is useful for sharing the points in an MPC circuit
impl From<&Order> for Vec<u64> {
    fn from(o: &Order) -> Self {
        vec![o.quote_mint, o.base_mint, o.side.into(), o.price, o.amount]
    }
}

/// Represents an order that has been allocated in an MPC network
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedOrder<S: SharedValueSource<Scalar>> {
    /// The mint (ERC-20 contract address) of the quote token
    pub quote_mint: SharedScalar<S>,
    /// The mint (ERC-20 contract address) of the base token
    pub base_mint: SharedScalar<S>,
    /// The side this order is for (0 = buy, 1 = sell)
    pub side: SharedScalar<S>,
    /// The limit price to be executed at, in units of quote
    pub price: SharedScalar<S>,
    /// The amount of base currency to buy or sell
    pub amount: SharedScalar<S>,
}

/// Attempt to parse an authenticated order from a vector of authenticated scalars
impl<S: SharedValueSource<Scalar>> TryFrom<Vec<SharedScalar<S>>> for AuthenticatedOrder<S> {
    type Error = MpcError;

    fn try_from(value: Vec<SharedScalar<S>>) -> Result<Self, Self::Error> {
        if value.len() != 5 {
            return Err(MpcError::SerializationError(format!(
                "Expected 5 elements, got {}",
                value.len()
            )));
        }

        Ok(Self {
            quote_mint: value[0].clone(),
            base_mint: value[1].clone(),
            side: value[2].clone(),
            price: value[3].clone(),
            amount: value[4].clone(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrderSide {
    Buy = 0,
    Sell,
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
            OrderSide::Buy => 0,
            OrderSide::Sell => 1,
        }
    }
}

// The result of a matches operation and its constraint system analog
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MatchResult {
    pub matches1: Vec<Match>,
    pub matches2: Vec<Match>,
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

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Match {
    pub mint: u64,
    pub amount: u64,
    pub side: OrderSide,
}
