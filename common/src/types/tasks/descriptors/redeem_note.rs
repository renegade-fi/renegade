//! Descriptor for the redeem note task
//!
//! n.b. Notes are encrypted and running this task requires access to the
//! decryption key. Many actors will choose not to trust a relayer with this key
//! and will instead opt to manually redeem. This task exists mostly to allow
//! actors to redeem fees through their _own_ relayer

use circuit_types::elgamal::DecryptionKey;
use serde::{Deserialize, Serialize};

use crate::types::wallet::WalletIdentifier;

use super::TaskDescriptor;

/// The task descriptor parameterizing the `RedeemNote` task
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RedeemNoteTaskDescriptor {
    /// The id of the wallet to redeem the note into
    pub wallet_id: WalletIdentifier,
    /// The tx hash of the note to redeem
    pub tx_hash: String,
    /// The decryption key to decrypt the note
    pub decryption_key: DecryptionKey,
}

impl RedeemNoteTaskDescriptor {
    /// Construct a new task descriptor
    pub fn new(
        wallet_id: WalletIdentifier,
        tx_hash: String,
        decryption_key: DecryptionKey,
    ) -> Self {
        Self { wallet_id, tx_hash, decryption_key }
    }
}

impl From<RedeemNoteTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: RedeemNoteTaskDescriptor) -> Self {
        TaskDescriptor::RedeemNote(descriptor)
    }
}
