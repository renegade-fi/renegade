//! Helper functions for darkpool client integration tests

use circuit_types::{
    native_helpers::compute_wallet_commitment_from_private, traits::BaseType,
    wallet::WalletShareStateCommitment, SizedWalletShare,
};
use common::types::proof_bundles::mocks::dummy_valid_wallet_create_bundle;
use constants::Scalar;
use darkpool_client::client::DarkpoolClient;
use eyre::{eyre, Result};
use rand::thread_rng;
use std::iter;
use tracing::warn;

use crate::PreAllocatedState;

/// Create a set of random wallet shares
pub fn random_wallet_shares() -> SizedWalletShare {
    let mut rng = thread_rng();
    SizedWalletShare::from_scalars(&mut iter::repeat_with(|| Scalar::random(&mut rng)))
}

/// Deploy a new wallet and return the commitment to the wallet and the
/// public shares of the wallet
pub async fn deploy_new_wallet(
    client: &DarkpoolClient,
) -> Result<(WalletShareStateCommitment, SizedWalletShare)> {
    let mut valid_wallet_create_bundle = dummy_valid_wallet_create_bundle();
    valid_wallet_create_bundle.statement.public_wallet_shares = random_wallet_shares();

    let statement = valid_wallet_create_bundle.statement.clone();

    client.new_wallet(&valid_wallet_create_bundle).await?;

    // The contract will compute the full commitment and insert it into the Merkle
    // tree; we repeat the same computation here for consistency
    let full_commitment = compute_wallet_commitment_from_private(
        &statement.public_wallet_shares,
        statement.private_shares_commitment,
    );
    Ok((full_commitment, statement.public_wallet_shares))
}

/// Sets up pre-allocated state used by the integration tests
pub async fn setup_pre_allocated_state(client: &mut DarkpoolClient) -> Result<PreAllocatedState> {
    // Clear the state of the Merkle tree contract
    clear_merkle(client).await?;

    // Reset the deploy block
    client.reset_deploy_block().await?;

    // Insert three new wallets into the contract
    let (index0_commitment, index0_shares) = deploy_new_wallet(client).await?;
    let (index1_commitment, index1_shares) = deploy_new_wallet(client).await?;
    let (index2_commitment, index2_shares) = deploy_new_wallet(client).await?;

    Ok(PreAllocatedState {
        index0_commitment,
        index1_commitment,
        index2_commitment,
        index0_public_wallet_shares: index0_shares,
        index1_public_wallet_shares: index1_shares,
        index2_public_wallet_shares: index2_shares,
    })
}

/// Clears the state of the Merkle tree contract, resetting it to a blank tree
/// w/ the default values for the leaves
pub async fn clear_merkle(client: &DarkpoolClient) -> Result<()> {
    warn!("Clearing Merkle contract state");
    client
        .send_tx(client.darkpool_client().clearMerkle())
        .await
        .map(|_| ())
        .map_err(|e| eyre!(e.to_string()))
}
