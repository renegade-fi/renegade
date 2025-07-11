//! Wallet helpers for balances in the wallet

use std::iter;

use circuit_types::{Amount, balance::Balance};
use constants::MAX_BALANCES;
use itertools::Itertools;
use num_bigint::BigUint;

use super::{Order, Wallet};

/// Error message emitted when a balance overflows
const ERR_BALANCE_OVERFLOW: &str = "balance overflowed";
/// Error message emitted when the balances of a wallet are full
const ERR_BALANCES_FULL: &str = "balances full";
/// Error message emitted when a wallet has insufficient balance for a
/// withdrawal
const ERR_INSUFFICIENT_BALANCE: &str = "insufficient balance";

impl Wallet {
    // -----------
    // | Getters |
    // -----------

    /// Get the balance for a given mint
    pub fn get_balance(&self, mint: &BigUint) -> Option<&Balance> {
        self.balances.get(mint)
    }

    /// Get the index a given balance is at
    pub fn get_balance_index(&self, mint: &BigUint) -> Option<usize> {
        self.balances.index_of(mint)
    }

    /// Get a mutable reference to the balance for a given mint
    pub fn get_balance_mut(&mut self, mint: &BigUint) -> Option<&mut Balance> {
        self.balances.get_mut(mint)
    }

    /// Get a balance or default to an empty balance
    pub fn get_balance_or_default(&self, mint: &BigUint) -> Balance {
        self.get_balance(mint).cloned().unwrap_or_else(|| Balance::new_from_mint(mint.clone()))
    }

    /// Get a mutable reference to the balance for the given mint or add a
    /// zero'd balance if one does not exist
    pub fn get_balance_mut_or_default(&mut self, mint: &BigUint) -> &mut Balance {
        if !self.balances.contains_key(mint) {
            let bal = Balance::new_from_mint(mint.clone());
            self.add_balance(bal).unwrap();
        }

        self.balances.get_mut(mint).unwrap()
    }

    /// Get a list of balances in order in their circuit representation
    pub fn get_balances_list(&self) -> [Balance; MAX_BALANCES] {
        self.balances
            .clone()
            .into_values()
            .chain(iter::repeat(Balance::default()))
            .take(MAX_BALANCES)
            .collect_vec()
            .try_into()
            .unwrap()
    }

    /// Get the balance that covers the side sold by the given order
    pub fn get_balance_for_order(&self, order: &Order) -> Option<Balance> {
        // Find a balance and fee to associate with this order
        let order_mint = order.send_mint();
        let balance = self.get_balance(order_mint)?.clone();

        Some(balance)
    }

    /// Get the matchable amount for a given order, in terms of the order's
    /// sell asset
    pub fn get_matchable_amount_for_order(&self, order: &Order) -> Amount {
        let order_mint = order.send_mint();
        let amount = self.get_balance(order_mint).map(|b| b.amount).unwrap_or_default();

        amount
    }

    /// Return whether the wallet has any fees to pay
    pub fn has_outstanding_fees(&self) -> bool {
        self.balances.values().any(|balance| balance.fees().total() > 0)
    }

    /// Whether the wallet has any zero'd balances that may be used for
    /// receiving a new mint
    pub fn has_empty_balance(&self) -> bool {
        self.balances.len() < MAX_BALANCES
            || self.balances.values().any(|balance| balance.is_zero())
    }

    // -----------
    // | Setters |
    // -----------

    /// Add a balance to the wallet, replacing the first default balance
    pub fn add_balance(&mut self, balance: Balance) -> Result<(), String> {
        // If the balance exists, increment it
        if let Some(bal) = self.balances.get_mut(&balance.mint) {
            bal.amount =
                bal.amount.checked_add(balance.amount).ok_or(ERR_BALANCE_OVERFLOW.to_string())?;
            return Ok(());
        }

        let mint = balance.mint.clone();
        if let Some(index) = self.find_first_replaceable_balance() {
            self.balances.replace_at_index(index, mint.clone(), balance);
        } else if self.balances.len() < MAX_BALANCES {
            self.balances.append(mint.clone(), balance);
        } else {
            return Err(ERR_BALANCES_FULL.to_string());
        }

        // Validate the balance after update
        let bal = self.balances.get(&mint).unwrap();
        bal.validate()
    }

    /// Find the first replaceable balance
    fn find_first_replaceable_balance(&self) -> Option<usize> {
        self.balances.iter().position(|(_, balance)| balance.is_zero())
    }

    /// Withdraw an amount from the balance for the given mint
    pub fn withdraw(&mut self, mint: &BigUint, amount: Amount) -> Result<(), String> {
        let bal = self.get_balance_mut(mint).ok_or(ERR_INSUFFICIENT_BALANCE.to_string())?;
        if bal.amount < amount {
            return Err(ERR_INSUFFICIENT_BALANCE.to_string());
        }

        bal.amount = bal.amount.saturating_sub(amount);
        Ok(())
    }

    /// Remove a balance from the wallet, replacing it with a default balance
    pub fn remove_balance(&mut self, mint: &BigUint) -> Option<Balance> {
        // Replace the balance with a default balance to preserve the balance order for
        // wallet update proofs
        let bal = self.get_balance_mut(mint)?;
        *bal = Balance::default();

        Some(bal.clone())
    }
}
