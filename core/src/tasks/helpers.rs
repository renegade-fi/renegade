//! Helpers for common functionality across tasks

use crate::{
    starknet_client::{client::StarknetClient, error::StarknetClientError},
    state::wallet::{Wallet, WalletAuthenticationPath},
};

/// Find the merkle authentication path of a wallet
pub(super) async fn find_merkle_path(
    wallet: &Wallet,
    starknet_client: &StarknetClient,
) -> Result<WalletAuthenticationPath, StarknetClientError> {
    // Find the authentication path of the wallet's private shares
    let private_merkle_auth_path = starknet_client
        .find_merkle_authentication_path(wallet.get_private_share_commitment())
        .await?;

    // Find the authentication path of the wallet's public shares
    let public_merkle_auth_path = starknet_client
        .find_merkle_authentication_path(wallet.get_public_share_commitment())
        .await?;

    Ok(WalletAuthenticationPath {
        public_share_path: public_merkle_auth_path,
        private_share_path: private_merkle_auth_path,
    })
}
