//! Descriptor for the new wallet task

use constants::Scalar;
use serde::{Deserialize, Serialize};

use crate::types::wallet::Wallet;

use super::{INVALID_WALLET_SHARES, TaskDescriptor};

/// The task descriptor containing only the parameterization of the `NewWallet`
/// task
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewWalletTaskDescriptor {
    /// The wallet to create
    pub wallet: Wallet,
    /// The blinder seed to use for the new wallet
    #[serde(default)]
    pub blinder_seed: Scalar,
}

impl NewWalletTaskDescriptor {
    /// Constructor
    pub fn new(wallet: Wallet, blinder_seed: Scalar) -> Result<Self, String> {
        // Validate that the wallet shares are well formed
        if !wallet.check_wallet_shares() {
            return Err(INVALID_WALLET_SHARES.to_string());
        }

        Ok(NewWalletTaskDescriptor { wallet, blinder_seed })
    }
}

impl From<NewWalletTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: NewWalletTaskDescriptor) -> Self {
        TaskDescriptor::NewWallet(descriptor)
    }
}
