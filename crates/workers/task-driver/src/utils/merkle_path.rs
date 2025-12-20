//! Helpers for finding Merkle authentication paths

use alloy::rpc::types::TransactionReceipt;
use common::types::wallet::{Wallet, WalletAuthenticationPath};
use darkpool_client::errors::DarkpoolClientError;

use crate::traits::TaskContext;

/// Find the merkle authentication path of a wallet
pub(crate) async fn find_merkle_path(
    wallet: &Wallet,
    ctx: &TaskContext,
) -> Result<WalletAuthenticationPath, DarkpoolClientError> {
    // The contract indexes the wallet by its commitment to the public and private
    // secret shares, find this in the Merkle tree
    ctx.darkpool_client.find_merkle_authentication_path(wallet.get_wallet_share_commitment()).await
}

/// Find the merkle authentication path of a wallet given an updating
/// transaction
pub(crate) fn find_merkle_path_with_tx(
    wallet: &Wallet,
    tx: &TransactionReceipt,
    ctx: &TaskContext,
) -> Result<WalletAuthenticationPath, DarkpoolClientError> {
    let commitment = wallet.get_wallet_share_commitment();
    ctx.darkpool_client.find_merkle_authentication_path_with_tx(commitment, tx)
}
