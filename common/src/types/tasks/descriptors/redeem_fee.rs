//! Task descriptor to redeem an offline relayer fee

use circuit_types::{elgamal::DecryptionKey, note::Note};
use serde::{Deserialize, Serialize};

use crate::types::wallet::WalletIdentifier;

use super::TaskDescriptor;

/// The task descriptor for redeeming a relayer note
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RedeemFeeTaskDescriptor {
    /// The wallet ID of the relayer's wallet
    ///
    /// Technically this should be static and not needed here, but we include it
    /// to allow the descriptor struct to compute its own task queue key
    pub wallet_id: WalletIdentifier,
    /// The decryption key that authorizes the redemption of the note into the
    /// wallet
    pub decryption_key: DecryptionKey,
    /// The note to redeem
    pub note: Note,
}

impl RedeemFeeTaskDescriptor {
    /// Constructor
    pub fn new(
        wallet_id: WalletIdentifier,
        note: Note,
        decryption_key: DecryptionKey,
    ) -> Result<Self, String> {
        Ok(RedeemFeeTaskDescriptor { wallet_id, note, decryption_key })
    }
}

impl From<RedeemFeeTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: RedeemFeeTaskDescriptor) -> Self {
        TaskDescriptor::RedeemFee(descriptor)
    }
}
