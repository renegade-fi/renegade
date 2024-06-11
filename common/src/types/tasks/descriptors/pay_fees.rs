//! Task descriptors for paying fees

use circuit_types::{balance::Balance, Amount};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use crate::types::wallet::WalletIdentifier;

use super::TaskDescriptor;

/// The task descriptor for the offline fee payment task
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PayOfflineFeeTaskDescriptor {
    /// Whether the fee is a protocol fee or a relayer fee
    pub is_protocol_fee: bool,
    /// The wallet to pay fees for
    pub wallet_id: WalletIdentifier,
    /// The balance to pay fees for
    pub mint: BigUint,
    /// The amount of the mint paid as a fee
    ///
    /// For now, this is always set to the full balance and is only used for
    /// informational purposes in API queries
    pub amount: Amount,
}

impl PayOfflineFeeTaskDescriptor {
    /// Constructor for the relayer fee payment task
    pub fn new_relayer_fee(wallet_id: WalletIdentifier, balance: Balance) -> Result<Self, String> {
        Ok(PayOfflineFeeTaskDescriptor {
            is_protocol_fee: false,
            wallet_id,
            mint: balance.mint,
            amount: balance.relayer_fee_balance,
        })
    }

    /// Constructor for the protocol fee payment task
    pub fn new_protocol_fee(wallet_id: WalletIdentifier, balance: Balance) -> Result<Self, String> {
        Ok(PayOfflineFeeTaskDescriptor {
            is_protocol_fee: true,
            wallet_id,
            mint: balance.mint,
            amount: balance.protocol_fee_balance,
        })
    }
}

impl From<PayOfflineFeeTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: PayOfflineFeeTaskDescriptor) -> Self {
        TaskDescriptor::OfflineFee(descriptor)
    }
}

/// The task descriptor for the relayer fee payment task
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PayRelayerFeeTaskDescriptor {
    /// The wallet to pay fees for
    pub wallet_id: WalletIdentifier,
    /// The balance to pay fees for
    pub balance_mint: BigUint,
}

impl PayRelayerFeeTaskDescriptor {
    /// Constructor
    pub fn new(wallet_id: WalletIdentifier, balance_mint: BigUint) -> Result<Self, String> {
        Ok(PayRelayerFeeTaskDescriptor { wallet_id, balance_mint })
    }
}

impl From<PayRelayerFeeTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: PayRelayerFeeTaskDescriptor) -> Self {
        TaskDescriptor::RelayerFee(descriptor)
    }
}
