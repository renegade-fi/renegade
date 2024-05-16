//! Descriptor for the new wallet task

use serde::{Deserialize, Serialize};

use crate::types::wallet::Wallet;

use super::{TaskDescriptor, INVALID_WALLET_SHARES};

/// The task descriptor containing only the parameterization of the `NewWallet`
/// task
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewWalletTaskDescriptor {
    /// The wallet to create
    pub wallet: Wallet,
}

impl NewWalletTaskDescriptor {
    /// Constructor
    pub fn new(wallet: Wallet) -> Result<Self, String> {
        // Validate that the wallet shares are well formed
        if !wallet.check_wallet_shares() {
            return Err(INVALID_WALLET_SHARES.to_string());
        }

        Ok(NewWalletTaskDescriptor { wallet })
    }
}

impl From<NewWalletTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: NewWalletTaskDescriptor) -> Self {
        TaskDescriptor::NewWallet(descriptor)
    }
}
