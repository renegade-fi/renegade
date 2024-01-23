//! Helpers for proposing wallet index changes and reading the index

use common::types::wallet::{Wallet, WalletIdentifier};

use crate::{
    applicator::WALLETS_TABLE, error::StateError, notifications::ProposalWaiter, State,
    StateTransition,
};

impl State {
    // -----------
    // | Getters |
    // -----------

    /// Get the wallet with the given id
    pub fn get_wallet(&self, id: &WalletIdentifier) -> Result<Option<Wallet>, StateError> {
        let db = self.db.clone();

        let tx = db.new_read_tx().map_err(StateError::Db)?;
        let wallet = tx.read(WALLETS_TABLE, id).map_err(StateError::Db)?;
        tx.commit().map_err(StateError::Db)?;

        Ok(wallet)
    }

    // -----------
    // | Setters |
    // -----------

    /// Propose a new wallet to be added to the index
    pub fn new_wallet(&self, wallet: Wallet) -> Result<ProposalWaiter, StateError> {
        self.send_proposal(StateTransition::AddWallet { wallet })
    }
}
