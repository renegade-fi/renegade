//! Descriptor for the lookup wallet task

use constants::Scalar;
use serde::{Deserialize, Serialize};

use crate::types::wallet::{KeyChain, WalletIdentifier};

use super::TaskDescriptor;

/// The task descriptor containing only the parameterization of the
/// `LookupWallet` task
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LookupWalletTaskDescriptor {
    /// The ID to provision for the wallet
    pub wallet_id: WalletIdentifier,
    /// The CSPRNG seed for the blinder stream
    pub blinder_seed: Scalar,
    /// The CSPRNG seed for the secret share stream
    pub secret_share_seed: Scalar,
    /// The keychain to manage the wallet with
    pub key_chain: KeyChain,
}

impl LookupWalletTaskDescriptor {
    /// Constructor
    pub fn new(
        wallet_id: WalletIdentifier,
        blinder_seed: Scalar,
        secret_share_seed: Scalar,
        key_chain: KeyChain,
    ) -> Result<Self, String> {
        Ok(LookupWalletTaskDescriptor { wallet_id, blinder_seed, secret_share_seed, key_chain })
    }
}

impl From<LookupWalletTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: LookupWalletTaskDescriptor) -> Self {
        TaskDescriptor::LookupWallet(descriptor)
    }
}
