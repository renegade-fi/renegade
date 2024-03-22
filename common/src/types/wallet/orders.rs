//! Wallet helpers for orders in the wallet

use circuit_types::order::Order;
use constants::MAX_ORDERS;

use super::{OrderIdentifier, Wallet};

/// Error message emitted when the orders of a wallet are full
const ERR_ORDERS_FULL: &str = "orders full";

impl Wallet {
    // -----------
    // | Getters |
    // -----------

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

    /// Returns whether any of the orders in the wallet are eligible for
    /// matching
    ///
    /// This amounts to non-default orders with non-zero balances to cover them
    pub fn has_orders_to_match(&self) -> bool {
        for order in self.orders.values() {
            let send_mint = order.send_mint();
            let has_balance = match self.balances.get(send_mint) {
                Some(balance) => balance.amount > 0,
                None => false,
            };

            // If a single non-default order has a non-zero balance, we can match on it
            if !order.is_default() && has_balance {
                return true;
            }
        }

        false
    }

    // -----------
    // | Setters |
    // -----------

    /// Add an order to the wallet, replacing the first default order if the
    /// wallet is full
    pub fn add_order(&mut self, id: OrderIdentifier, order: Order) -> Result<(), String> {
        // Append if the orders are not full
        if self.orders.len() >= MAX_ORDERS {
            return Err(ERR_ORDERS_FULL.to_string());
        }

        self.orders.append(id, order);
        Ok(())
    }

    /// Remove an order from the wallet, replacing it with a default order
    pub fn remove_order(&mut self, id: &OrderIdentifier) -> Option<Order> {
        self.orders.remove(id)
    }
}
