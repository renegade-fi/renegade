//! Descriptor for the refresh wallet task
//!
//! This task is responsible for refreshing the wallet from on-chain state

use serde::{Deserialize, Serialize};

use crate::types::wallet::WalletIdentifier;

use super::TaskDescriptor;

/// The descriptor for the refresh wallet task
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct RefreshWalletTaskDescriptor {
    /// The wallet to refresh
    pub wallet_id: WalletIdentifier,
}

impl RefreshWalletTaskDescriptor {
    /// Create a new refresh wallet task descriptor
    pub fn new(wallet_id: WalletIdentifier) -> Self {
        Self { wallet_id }
    }
}

impl From<RefreshWalletTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: RefreshWalletTaskDescriptor) -> Self {
        Self::RefreshWallet(descriptor)
    }
}
