//! Task descriptor to redeem an offline relayer fee

use circuit_types::note::Note;
use serde::{Deserialize, Serialize};

use crate::types::wallet::WalletIdentifier;

use super::TaskDescriptor;

/// The task descriptor for redeeming a relayer note
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RedeemRelayerFeeTaskDescriptor {
    /// The wallet ID of the relayer's wallet
    ///
    /// Technically this should be static and not needed here, but we include it
    /// to allow the descriptor struct to compute its own task queue key
    pub wallet_id: WalletIdentifier,
    /// The note to redeem
    pub note: Note,
}

impl RedeemRelayerFeeTaskDescriptor {
    /// Constructor
    pub fn new(wallet_id: WalletIdentifier, note: Note) -> Result<Self, String> {
        Ok(RedeemRelayerFeeTaskDescriptor { wallet_id, note })
    }
}

impl From<RedeemRelayerFeeTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: RedeemRelayerFeeTaskDescriptor) -> Self {
        TaskDescriptor::RedeemRelayerFee(descriptor)
    }
}
