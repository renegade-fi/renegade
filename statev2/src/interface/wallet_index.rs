//! Helpers for proposing wallet index changes and reading the index

use circuit_types::order::Order;
use common::types::wallet::{OrderIdentifier, Wallet, WalletIdentifier};
use util::res_some;

use crate::{error::StateError, notifications::ProposalWaiter, State, StateTransition};

impl State {
    // -----------
    // | Getters |
    // -----------

    /// Get the wallet with the given id
    pub fn get_wallet(&self, id: &WalletIdentifier) -> Result<Option<Wallet>, StateError> {
        let tx = self.db.new_read_tx()?;
        let wallet = tx.get_wallet(id)?;
        tx.commit()?;

        Ok(wallet)
    }

    /// Get the plaintext order for a locally managed order ID
    pub fn get_managed_order(&self, id: &OrderIdentifier) -> Result<Option<Order>, StateError> {
        let tx = self.db.new_read_tx()?;
        let wallet_id = res_some!(tx.get_wallet_for_order(id)?);
        let wallet = res_some!(tx.get_wallet(&wallet_id)?);
        tx.commit()?;

        Ok(wallet.orders.get(id).cloned())
    }

    /// Get the wallet that contains the given order ID
    pub fn get_wallet_for_order(
        &self,
        order_id: &OrderIdentifier,
    ) -> Result<Option<WalletIdentifier>, StateError> {
        let tx = self.db.new_read_tx()?;
        let wallet_id = tx.get_wallet_for_order(order_id)?;
        tx.commit()?;

        Ok(wallet_id)
    }

    /// Get the ids of all wallets managed by the local relayer
    pub fn get_all_wallets(&self) -> Result<Vec<Wallet>, StateError> {
        let tx = self.db.new_read_tx()?;
        let wallets = tx.get_all_wallets()?;
        tx.commit()?;

        Ok(wallets)
    }

    // -----------
    // | Setters |
    // -----------

    /// Propose a new wallet to be added to the index
    pub fn new_wallet(&self, wallet: Wallet) -> Result<ProposalWaiter, StateError> {
        self.send_proposal(StateTransition::AddWallet { wallet })
    }

    /// Update a wallet in the index
    pub fn update_wallet(&self, wallet: Wallet) -> Result<ProposalWaiter, StateError> {
        self.send_proposal(StateTransition::UpdateWallet { wallet })
    }
}
