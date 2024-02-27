//! Wallet helpers for balances in the wallet

use std::iter;

use circuit_types::{balance::Balance, fee::Fee, order::Order};
use constants::MAX_BALANCES;
use itertools::Itertools;
use num_bigint::BigUint;

use super::Wallet;

/// Error message emitted when a balance overflows
const ERR_BALANCE_OVERFLOW: &str = "balance overflowed";
/// Error message emitted when the balances of a wallet are full
const ERR_BALANCES_FULL: &str = "balances full";

impl Wallet {
    // -----------
    // | Getters |
    // -----------

    /// Get the balance for a given mint
    pub fn get_balance(&self, mint: &BigUint) -> Option<&Balance> {
        self.balances.get(mint)
    }

    /// Get a mutable reference to the balance for a given mint
    pub fn get_balance_mut(&mut self, mint: &BigUint) -> Option<&mut Balance> {
        self.balances.get_mut(mint)
    }

    /// Get a mutable reference to the balance for the given mint or add a
    /// zero'd balance if one does not exist
    pub fn get_balance_mut_or_default(&mut self, mint: &BigUint) -> &mut Balance {
        if !self.balances.contains_key(mint) {
            let bal = Balance { mint: mint.clone(), amount: 0 };
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

    /// Get the balance, fee, and fee_balance for an order by specifying the
    /// order directly
    ///
    /// We allow orders to be matched when undercapitalized; i.e. the respective
    /// balance does not cover the full volume of the order.
    pub fn get_balance_and_fee_for_order(&self, order: &Order) -> Option<(Balance, Fee, Balance)> {
        // Find a balance and fee to associate with this order
        let order_mint = order.send_mint();
        let balance = self.get_balance(order_mint)?;

        // Choose the first non-default fee for simplicity
        let fee = self.fees.iter().find(|fee| !fee.is_default())?;
        let fee_balance = self.get_balance(&fee.gas_addr)?;
        if fee_balance.amount < fee.gas_token_amount {
            return None;
        }

        Some((balance.clone(), fee.clone(), fee_balance.clone()))
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

        // Otherwise, add the balance
        if self.balances.len() < MAX_BALANCES {
            self.balances.insert(balance.mint.clone(), balance);
            return Ok(());
        }

        // If the balances are full, try to find a balance to overwrite
        let idx = self
            .balances
            .iter()
            .enumerate()
            .find_map(|(i, (_, balance))| balance.is_zero().then_some(i))
            .ok_or_else(|| ERR_BALANCES_FULL.to_string())?;
        self.balances.replace_at_index(idx, balance.mint.clone(), balance);

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
