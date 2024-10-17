//! Wallet helpers for orders in the wallet

use circuit_types::{
    biguint_from_hex_string, biguint_to_hex_addr,
    fixed_point::FixedPoint,
    max_price,
    order::{Order as CircuitOrder, OrderSide},
    validate_amount_bitlength, validate_price_bitlength, Amount,
};
use constants::MAX_ORDERS;
use itertools::Itertools;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use crate::keyed_list::KeyedList;

use super::{OrderIdentifier, Wallet};

/// Error message emitted when the orders of a wallet are full
const ERR_ORDERS_FULL: &str = "orders full";
/// Error message when an order amount is too large
const ERR_ORDER_AMOUNT_TOO_LARGE: &str = "amount is too large";
/// Error message when an order worst case price is too large
const ERR_ORDER_WORST_CASE_PRICE_TOO_LARGE: &str = "worst case price is too large";

// --------------
// | Order Type |
// --------------

/// An order in the wallet
///
/// This is a different type from the `CircuitOrder` type which includes fields
/// like `min_fill_size` that are not validated in-circuit, but are used in the
/// matching engine
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Order {
    /// The mint (ERC-20 contract address) of the quote token
    #[serde(serialize_with = "biguint_to_hex_addr", deserialize_with = "biguint_from_hex_string")]
    pub quote_mint: BigUint,
    /// The mint (ERC-20 contract address) of the base token
    #[serde(serialize_with = "biguint_to_hex_addr", deserialize_with = "biguint_from_hex_string")]
    pub base_mint: BigUint,
    /// The side this order is for (0 = buy, 1 = sell)
    pub side: OrderSide,
    /// The amount of base currency to buy or sell
    pub amount: Amount,
    /// The worse case price the user is willing to accept on this order
    ///
    /// If the order is a buy, this is the maximum price the user is willing to
    /// pay If the order is a sell, this is the minimum price the user is
    /// willing to accept
    pub worst_case_price: FixedPoint,
    /// The minimum fill size for the order
    #[serde(default)]
    pub min_fill_size: Amount,
    /// Whether or not to allow external matches for the order
    ///
    /// When set to true, the relayer will allow the external matching engine to
    /// run on the order. If an external match is found, the relayer will
    /// forward the match bundle to the external party. Clients may opt-in to
    /// this in order to source external crossing liquidity
    #[serde(default)]
    pub allow_external_matches: bool,
}

impl From<Order> for CircuitOrder {
    fn from(order: Order) -> Self {
        CircuitOrder {
            quote_mint: order.quote_mint,
            base_mint: order.base_mint,
            side: order.side,
            amount: order.amount,
            worst_case_price: order.worst_case_price,
        }
    }
}

impl From<CircuitOrder> for Order {
    fn from(order: CircuitOrder) -> Self {
        Order {
            quote_mint: order.quote_mint,
            base_mint: order.base_mint,
            side: order.side,
            amount: order.amount,
            worst_case_price: order.worst_case_price,
            min_fill_size: 0,
            allow_external_matches: false,
        }
    }
}

impl Order {
    /// Create a new order
    pub fn new(
        quote_mint: BigUint,
        base_mint: BigUint,
        side: OrderSide,
        amount: Amount,
        worst_case_price: FixedPoint,
        min_fill_size: Amount,
        allow_external_matches: bool,
    ) -> Result<Self, String> {
        // Validate the range of the amount and worst case price
        let order = Self::new_unchecked(
            quote_mint,
            base_mint,
            side,
            amount,
            worst_case_price,
            min_fill_size,
            allow_external_matches,
        );
        order.validate()?;

        Ok(order)
    }

    /// Create a new order without validating it
    pub fn new_unchecked(
        quote_mint: BigUint,
        base_mint: BigUint,
        side: OrderSide,
        amount: Amount,
        worst_case_price: FixedPoint,
        min_fill_size: Amount,
        allow_external_matches: bool,
    ) -> Self {
        Self {
            quote_mint,
            base_mint,
            side,
            amount,
            worst_case_price,
            min_fill_size,
            allow_external_matches,
        }
    }

    /// Validate the order
    pub fn validate(&self) -> Result<(), String> {
        if !validate_amount_bitlength(self.amount) {
            return Err(ERR_ORDER_AMOUNT_TOO_LARGE.to_string());
        }

        if !validate_price_bitlength(self.worst_case_price) {
            return Err(ERR_ORDER_WORST_CASE_PRICE_TOO_LARGE.to_string());
        }

        Ok(())
    }

    /// Whether or not this is the zero'd order
    pub fn is_default(&self) -> bool {
        self.eq(&Self::default())
    }

    /// Whether or not this order is for zero volume
    pub fn is_zero(&self) -> bool {
        self.amount == 0
    }

    /// The mint of the token sent by the creator of this order in the event
    /// that the order is matched
    pub fn send_mint(&self) -> &BigUint {
        match self.side {
            OrderSide::Buy => &self.quote_mint,
            OrderSide::Sell => &self.base_mint,
        }
    }

    /// The mint of the token received by the creator of this order in the event
    /// that the order is matched
    pub fn receive_mint(&self) -> &BigUint {
        match self.side {
            OrderSide::Buy => &self.base_mint,
            OrderSide::Sell => &self.quote_mint,
        }
    }

    /// Determines whether the given price is within the allowable range for the
    /// order
    pub fn price_in_range(&self, price: FixedPoint) -> bool {
        match self.side {
            OrderSide::Buy => price.to_f64() <= self.worst_case_price.to_f64(),
            OrderSide::Sell => price.to_f64() >= self.worst_case_price.to_f64(),
        }
    }

    /// Update an order from a circuit order
    pub fn update_from_circuit_order(&mut self, order: &CircuitOrder) {
        self.quote_mint.clone_from(&order.quote_mint);
        self.base_mint.clone_from(&order.base_mint);
        self.side = order.side;
        self.amount = order.amount;
        self.worst_case_price = order.worst_case_price;
    }
}

// ----------------
// | Builder Type |
// ----------------

/// Builder for creating an Order
#[allow(clippy::missing_docs_in_private_items)]
#[derive(Default)]
pub struct OrderBuilder {
    quote_mint: Option<BigUint>,
    base_mint: Option<BigUint>,
    side: Option<OrderSide>,
    amount: Option<Amount>,
    worst_case_price: Option<FixedPoint>,
    min_fill_size: Option<Amount>,
    allow_external_matches: Option<bool>,
}

impl OrderBuilder {
    /// Create a new order builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the quote mint
    pub fn quote_mint(mut self, quote_mint: BigUint) -> Self {
        self.quote_mint = Some(quote_mint);
        self
    }

    /// Set the base mint
    pub fn base_mint(mut self, base_mint: BigUint) -> Self {
        self.base_mint = Some(base_mint);
        self
    }

    /// Set the side
    pub fn side(mut self, side: OrderSide) -> Self {
        self.side = Some(side);
        self
    }

    /// Set the amount
    pub fn amount(mut self, amount: Amount) -> Self {
        self.amount = Some(amount);
        self
    }

    /// Set the worst case price
    pub fn worst_case_price(mut self, worst_case_price: FixedPoint) -> Self {
        self.worst_case_price = Some(worst_case_price);
        self
    }

    /// Set the minimum fill size
    pub fn min_fill_size(mut self, min_fill_size: Amount) -> Self {
        self.min_fill_size = Some(min_fill_size);
        self
    }

    /// Set whether or not to allow external matches
    pub fn allow_external_matches(mut self, allow: bool) -> Self {
        self.allow_external_matches = Some(allow);
        self
    }

    /// Build the order
    pub fn build(self) -> Result<Order, String> {
        let quote_mint = self.quote_mint.ok_or("Quote mint is required")?;
        let base_mint = self.base_mint.ok_or("Base mint is required")?;
        let side = self.side.ok_or("Side is required")?;
        let amount = self.amount.ok_or("Amount is required")?;
        let worst_case_price = self.worst_case_price.unwrap_or_else(|| match side {
            OrderSide::Buy => max_price(),
            OrderSide::Sell => FixedPoint::from_integer(0),
        });
        let min_fill_size = self.min_fill_size.unwrap_or(0);
        let allow_external_matches = self.allow_external_matches.unwrap_or(false);

        Ok(Order {
            quote_mint,
            base_mint,
            side,
            amount,
            worst_case_price,
            min_fill_size,
            allow_external_matches,
        })
    }
}

// ------------------------
// | Wallet Order Methods |
// ------------------------

impl Wallet {
    // -----------
    // | Getters |
    // -----------

    /// Whether or not the wallet contains an order with the given identifier
    pub fn contains_order(&self, order_id: &OrderIdentifier) -> bool {
        self.orders.contains_key(order_id)
    }

    /// Get the given order
    pub fn get_order(&self, order_id: &OrderIdentifier) -> Option<&Order> {
        self.orders.get(order_id)
    }

    /// Get a mutable reference to the given order
    pub fn get_order_mut(&mut self, order_id: &OrderIdentifier) -> Option<&mut Order> {
        self.orders.get_mut(order_id)
    }

    /// Get a list of orders in order in their circuit representation
    pub fn get_orders_list(&self) -> [Order; MAX_ORDERS] {
        self.orders
            .clone()
            .into_values()
            .chain(std::iter::repeat(Order::default()))
            .take(MAX_ORDERS)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    /// Get the non-zero orders in the wallet
    pub fn get_nonzero_orders(&self) -> KeyedList<OrderIdentifier, Order> {
        self.orders.iter().filter(|(_id, order)| !order.is_zero()).cloned().collect()
    }

    /// Get the list of orders that are eligible for matching
    ///
    /// An order is ready to match if it is non-zero and has a non-zero sell
    /// balance backing it
    pub fn get_matchable_orders(&self) -> Vec<(OrderIdentifier, Order)> {
        self.orders
            .iter()
            .filter(|(_id, order)| {
                let send_mint = order.send_mint();
                let has_balance = match self.get_balance(send_mint) {
                    Some(balance) => balance.amount > 0,
                    None => false,
                };

                let receive_mint = order.receive_mint();
                let has_receive_balance =
                    self.get_balance(receive_mint).is_some() || self.has_empty_balance();

                !order.is_zero() && has_balance && has_receive_balance
            })
            .cloned()
            .collect_vec()
    }

    // -----------
    // | Setters |
    // -----------

    /// Add an order to the wallet, replacing the first default order if the
    /// wallet is full
    pub fn add_order(&mut self, id: OrderIdentifier, order: Order) -> Result<(), String> {
        // Validate the order
        order.validate()?;

        // Append if the orders are not full
        if let Some(index) = self.find_first_replaceable_order() {
            self.orders.replace_at_index(index, id, order);
        } else if self.orders.len() < MAX_ORDERS {
            self.orders.append(id, order)
        } else {
            return Err(ERR_ORDERS_FULL.to_string());
        }

        Ok(())
    }

    /// Find the first default order in the wallet
    fn find_first_replaceable_order(&self) -> Option<usize> {
        self.orders.iter().position(|(_, order)| order.is_zero())
    }

    /// Remove an order from the wallet, replacing it with a default order
    pub fn remove_order(&mut self, id: &OrderIdentifier) -> Option<Order> {
        self.orders.remove(id)
    }
}
