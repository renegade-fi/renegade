//! Descriptor for the update merkle proof task

use serde::{Deserialize, Serialize};

use crate::types::wallet::Wallet;

use super::TaskDescriptor;

/// The task descriptor containing only the parameterization of the
/// `UpdateMerkleProof` task
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateMerkleProofTaskDescriptor {
    /// The wallet to update
    pub wallet: Wallet,
}

impl UpdateMerkleProofTaskDescriptor {
    /// Constructor
    pub fn new(wallet: Wallet) -> Result<Self, String> {
        Ok(UpdateMerkleProofTaskDescriptor { wallet })
    }
}

impl From<UpdateMerkleProofTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: UpdateMerkleProofTaskDescriptor) -> Self {
        TaskDescriptor::UpdateMerkleProof(descriptor)
    }
}
