//! Descriptor for the wallet update task

use circuit_types::{keychain::PublicSigningKey, order::Order, Amount};
use constants::GLOBAL_MATCHING_POOL;
use contracts_common::custom_serde::BytesSerializable;
use ethers::core::types::Signature;
use ethers::utils::{keccak256, public_key_to_address};
use k256::ecdsa::VerifyingKey as K256VerifyingKey;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use crate::types::wallet::OrderIdentifier;
use crate::types::MatchingPoolName;
use crate::types::{
    transfer_auth::ExternalTransferWithAuth,
    wallet::{Wallet, WalletIdentifier},
};

use super::{TaskDescriptor, INVALID_WALLET_SHARES};

/// A type representing a description of an update wallet task
///
/// Differentiates between order vs balance updates, and holds fields for
/// display
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WalletUpdateType {
    /// Deposit a balance
    Deposit {
        /// The deposited mint
        mint: BigUint,
        /// The amount deposited
        amount: Amount,
    },
    /// Withdraw a balance
    Withdraw {
        /// The withdrawn mint
        mint: BigUint,
        /// The amount withdrawn
        amount: Amount,
    },
    /// Place an order
    PlaceOrder {
        /// The order to place
        order: Order,
        /// The ID of the order
        id: OrderIdentifier,
        /// The matching pool to assign the order to
        matching_pool: MatchingPoolName,
    },
    /// Cancel an order
    CancelOrder {
        /// The order that was cancelled
        order: Order,
    },
}

impl WalletUpdateType {
    /// Get a human-readable description of the wallet update type
    pub fn display_description(&self) -> String {
        match self {
            WalletUpdateType::Deposit { .. } => "Deposit",
            WalletUpdateType::Withdraw { .. } => "Withdraw",
            WalletUpdateType::PlaceOrder { .. } => "Place order",
            WalletUpdateType::CancelOrder { .. } => "Cancel order",
        }
        .to_string()
    }
}

/// The task descriptor containing only the parameterization of the
/// `UpdateWallet` task
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateWalletTaskDescriptor {
    /// A description of the update task, maintained for historical state
    pub description: WalletUpdateType,
    /// The external transfer & auth data, if one exists
    pub transfer: Option<ExternalTransferWithAuth>,
    /// The old wallet before update
    pub wallet_id: WalletIdentifier,
    /// The new wallet after update
    pub new_wallet: Wallet,
    /// A signature of the `VALID WALLET UPDATE` statement by the wallet's root
    /// key, the contract uses this to authorize the update
    pub wallet_update_signature: Vec<u8>,
}

impl UpdateWalletTaskDescriptor {
    /// Base constructor
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(
        description: WalletUpdateType,
        transfer_with_auth: Option<ExternalTransferWithAuth>,
        old_wallet: Wallet,
        new_wallet: Wallet,
        wallet_update_signature: Vec<u8>,
    ) -> Result<Self, String> {
        // Check that the new wallet is properly reblinded
        if !new_wallet.check_wallet_shares() {
            return Err(INVALID_WALLET_SHARES.to_string());
        }

        // Check the signature on the updated shares commitment
        let key = &old_wallet.key_chain.public_keys.pk_root;
        verify_wallet_update_signature(&new_wallet, key, &wallet_update_signature)
            .map_err(|e| format!("invalid wallet update sig: {e}"))?;

        Ok(UpdateWalletTaskDescriptor {
            description,
            transfer: transfer_with_auth,
            wallet_id: old_wallet.wallet_id,
            new_wallet,
            wallet_update_signature,
        })
    }

    /// A new deposit
    pub fn new_deposit(
        transfer_with_auth: ExternalTransferWithAuth,
        old_wallet: Wallet,
        new_wallet: Wallet,
        wallet_update_signature: Vec<u8>,
    ) -> Result<Self, String> {
        let transfer = &transfer_with_auth.external_transfer;
        let desc =
            WalletUpdateType::Deposit { mint: transfer.mint.clone(), amount: transfer.amount };

        Self::new(desc, Some(transfer_with_auth), old_wallet, new_wallet, wallet_update_signature)
    }

    /// A new withdrawal
    pub fn new_withdrawal(
        transfer_with_auth: ExternalTransferWithAuth,
        old_wallet: Wallet,
        new_wallet: Wallet,
        wallet_update_signature: Vec<u8>,
    ) -> Result<Self, String> {
        let transfer = &transfer_with_auth.external_transfer;
        let desc =
            WalletUpdateType::Withdraw { mint: transfer.mint.clone(), amount: transfer.amount };

        Self::new(desc, Some(transfer_with_auth), old_wallet, new_wallet, wallet_update_signature)
    }

    /// A new order placement in the global matching pool
    pub fn new_order(
        order: Order,
        id: OrderIdentifier,
        old_wallet: Wallet,
        new_wallet: Wallet,
        wallet_update_signature: Vec<u8>,
    ) -> Result<Self, String> {
        let desc = WalletUpdateType::PlaceOrder {
            order,
            id,
            matching_pool: GLOBAL_MATCHING_POOL.to_string(),
        };
        Self::new(desc, None, old_wallet, new_wallet, wallet_update_signature)
    }

    /// A new order placement in the given matching pool
    pub fn new_order_in_matching_pool(
        order: Order,
        id: OrderIdentifier,
        old_wallet: Wallet,
        new_wallet: Wallet,
        wallet_update_signature: Vec<u8>,
        matching_pool: MatchingPoolName,
    ) -> Result<Self, String> {
        let desc = WalletUpdateType::PlaceOrder { order, id, matching_pool };
        Self::new(desc, None, old_wallet, new_wallet, wallet_update_signature)
    }

    /// A new order cancellation
    pub fn new_order_cancellation(
        order: Order,
        old_wallet: Wallet,
        new_wallet: Wallet,
        wallet_update_signature: Vec<u8>,
    ) -> Result<Self, String> {
        let desc = WalletUpdateType::CancelOrder { order };
        Self::new(desc, None, old_wallet, new_wallet, wallet_update_signature)
    }
}

impl From<UpdateWalletTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: UpdateWalletTaskDescriptor) -> Self {
        TaskDescriptor::UpdateWallet(descriptor)
    }
}

// -----------
// | Helpers |
// -----------

/// Verify a signature of a wallet update
pub fn verify_wallet_update_signature(
    wallet: &Wallet,
    key: &PublicSigningKey,
    wallet_update_signature: &[u8],
) -> Result<(), String> {
    let key: K256VerifyingKey = key.into();
    let new_wallet_comm = wallet.get_wallet_share_commitment();

    // Serialize the commitment, uses the contract's serialization here:
    //  https://github.com/renegade-fi/renegade-contracts/blob/main/contracts-common/src/custom_serde.rs#L82-L87
    let comm_bytes = new_wallet_comm.inner().serialize_to_bytes();
    let digest = keccak256(comm_bytes);

    // Verify the signature
    let addr = public_key_to_address(&key);
    let sig = Signature::try_from(wallet_update_signature).map_err(|e| e.to_string())?;
    sig.verify(digest, addr).map_err(|e| e.to_string())
}
