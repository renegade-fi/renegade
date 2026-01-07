//! Helpers for finding Merkle authentication paths

use alloy::rpc::types::TransactionReceipt;
use circuit_types::Commitment;
use darkpool_client::errors::DarkpoolClientError;
use types_account::account::WalletAuthenticationPath;

use crate::traits::TaskContext;

/// Find the merkle authentication path of a commitment
pub(crate) async fn find_merkle_path(
    _commitment: Commitment,
    _ctx: &TaskContext,
) -> Result<WalletAuthenticationPath, DarkpoolClientError> {
    todo!("implement find_merkle_path")
}

/// Find the merkle authentication path of a commitment given an updating
/// transaction
pub(crate) fn find_merkle_path_with_tx(
    _commitment: Commitment,
    _tx: &TransactionReceipt,
    _ctx: &TaskContext,
) -> Result<WalletAuthenticationPath, DarkpoolClientError> {
    todo!("implement find_merkle_path_with_tx")
}
