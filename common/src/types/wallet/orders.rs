//! Wallet helpers for orders in the wallet

use circuit_types::order::Order;
use constants::MAX_ORDERS;
use itertools::Itertools;

use crate::keyed_list::KeyedList;

use super::{OrderIdentifier, Wallet};

/// Error message emitted when the orders of a wallet are full
const ERR_ORDERS_FULL: &str = "orders full";

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
