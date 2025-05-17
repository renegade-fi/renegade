//! Arbitrum implementation of transfer auth

use alloy::signers::local::PrivateKeySigner;
use alloy_primitives::Address;
use circuit_types::{
    keychain::PublicSigningKey,
    transfers::{ExternalTransfer, ExternalTransferDirection},
};
use common::types::transfer_auth::{ExternalTransferWithAuth, WithdrawalAuth};

use crate::{
    arbitrum::{
        contract_types::conversion::to_contract_external_transfer, helpers::serialize_calldata,
    },
    errors::DarkpoolClientError,
};

// Re-export the deposit auth builder under the `arbitrum` module
pub use super::common::build_deposit_auth;
use super::common::sign_bytes;

/// Generates an external transfer augmented with auth data
pub fn build_transfer_auth(
    wallet: &PrivateKeySigner,
    pk_root: &PublicSigningKey,
    permit2_address: Address,
    darkpool_address: Address,
    chain_id: u64,
    transfer: ExternalTransfer,
) -> Result<ExternalTransferWithAuth, DarkpoolClientError> {
    match transfer.direction {
        ExternalTransferDirection::Deposit => build_deposit_auth(
            wallet,
            pk_root,
            transfer,
            permit2_address,
            darkpool_address,
            chain_id,
        ),
        ExternalTransferDirection::Withdrawal => build_withdrawal_auth(wallet, transfer),
    }
}

/// Generate a withdrawal payload with proper auth data
pub fn build_withdrawal_auth(
    wallet: &PrivateKeySigner,
    transfer: ExternalTransfer,
) -> Result<ExternalTransferWithAuth, DarkpoolClientError> {
    let contract_transfer = to_contract_external_transfer(&transfer)?;
    let transfer_bytes = serialize_calldata(&contract_transfer)?;
    let sig_bytes = sign_bytes(wallet, &transfer_bytes)?;

    Ok(ExternalTransferWithAuth::withdrawal(
        transfer.account_addr,
        transfer.mint,
        transfer.amount,
        WithdrawalAuth { external_transfer_signature: sig_bytes },
    ))
}
