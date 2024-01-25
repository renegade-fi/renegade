//! Helpers for proposing wallet index changes and reading the index

use common::types::wallet::{Wallet, WalletIdentifier};

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
