//! Descriptor for the lookup wallet task

use constants::Scalar;
use serde::{Deserialize, Serialize};

use crate::types::wallet::{keychain::PrivateKeyChain, WalletIdentifier};

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
    /// The secret keys used to manage the wallet when it is found
    pub secret_keys: PrivateKeyChain,
}

impl LookupWalletTaskDescriptor {
    /// Constructor
    pub fn new(
        wallet_id: WalletIdentifier,
        blinder_seed: Scalar,
        secret_share_seed: Scalar,
        secret_keys: PrivateKeyChain,
    ) -> Result<Self, String> {
        Ok(LookupWalletTaskDescriptor { wallet_id, blinder_seed, secret_share_seed, secret_keys })
    }
}

impl From<LookupWalletTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: LookupWalletTaskDescriptor) -> Self {
        TaskDescriptor::LookupWallet(descriptor)
    }
}
