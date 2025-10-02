//! Descriptor for the wallet update task

use alloy::primitives::keccak256;
use alloy::signers::Signature;
use alloy::signers::utils::public_key_to_address;
use circuit_types::{Amount, keychain::PublicSigningKey};
use constants::Scalar;
use k256::ecdsa::VerifyingKey as K256VerifyingKey;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use crate::types::MatchingPoolName;
use crate::types::wallet::{Order, OrderIdentifier};
use crate::types::{
    transfer_auth::ExternalTransferWithAuth,
    wallet::{Wallet, WalletIdentifier},
};

use super::{INVALID_WALLET_SHARES, TaskDescriptor};

/// The error message emitted for an invalid wallet update signature
const ERR_INVALID_SIGNATURE: &str = "invalid signature";

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
        /// The matching pool to assign the order to.
        /// If `None`, the order is placed in the global pool.
        matching_pool: Option<MatchingPoolName>,
        /// Whether to precompute a cancellation proof for the order
        precompute_cancellation_proof: bool,
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

        // Check that if the root key has rotated, the nonce has been incremented
        let old_pkeys = &old_wallet.key_chain.public_keys;
        let new_pkeys = &new_wallet.key_chain.public_keys;
        let expected_nonce = old_pkeys.nonce + Scalar::one();
        if old_pkeys.pk_root != new_pkeys.pk_root && new_pkeys.nonce != expected_nonce {
            return Err("nonce must be incremented when the root key rotates".to_string());
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

    /// A new order placement with no matching pool
    pub fn new_order_placement(
        id: OrderIdentifier,
        order: Order,
        old_wallet: Wallet,
        new_wallet: Wallet,
        wallet_update_signature: Vec<u8>,
        precompute_cancellation_proof: bool,
    ) -> Result<Self, String> {
        Self::new_order_with_maybe_pool(
            id,
            order,
            old_wallet,
            new_wallet,
            wallet_update_signature,
            None, // matching_pool
            precompute_cancellation_proof,
        )
    }

    /// A new order placement, optionally in a non-global matching pool
    pub fn new_order_with_maybe_pool(
        id: OrderIdentifier,
        order: Order,
        old_wallet: Wallet,
        new_wallet: Wallet,
        wallet_update_signature: Vec<u8>,
        matching_pool: Option<MatchingPoolName>,
        precompute_cancellation_proof: bool,
    ) -> Result<Self, String> {
        let desc = WalletUpdateType::PlaceOrder {
            order,
            id,
            matching_pool,
            precompute_cancellation_proof,
        };
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
    // The `to_bytes_be` method is used to match the contract's serialization, with
    // appropriate padding
    let comm_bytes = new_wallet_comm.to_bytes_be();
    let digest = keccak256(comm_bytes);

    // Verify the signature by recovering the address
    let addr = public_key_to_address(&key);
    let sig = Signature::try_from(wallet_update_signature).map_err(|e| e.to_string())?;
    let recovered_addr = sig.recover_address_from_prehash(&digest).map_err(|e| e.to_string())?;
    if recovered_addr != addr {
        return Err(ERR_INVALID_SIGNATURE.to_string());
    }

    Ok(())
}
