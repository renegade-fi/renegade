//! Helper functions for Arbitrum client integration tests

use arbitrum_client::client::ArbitrumClient;
use circuit_types::{
    native_helpers::compute_wallet_commitment_from_private, traits::BaseType,
    wallet::WalletShareStateCommitment, SizedWalletShare,
};
use common::types::proof_bundles::mocks::dummy_valid_wallet_create_bundle;
use constants::Scalar;
use eyre::{eyre, Result};
use rand::thread_rng;
use std::{fs::File, io::Read, iter};

use crate::constants::DEPLOYMENTS_KEY;

/// Parse the address of the deployed contract from the `deployments.json` file
pub fn parse_addr_from_deployments_file(file_path: &str, contract_key: &str) -> Result<String> {
    let mut file_contents = String::new();
    File::open(file_path)?.read_to_string(&mut file_contents)?;

    let parsed_json = json::parse(&file_contents)?;
    parsed_json[DEPLOYMENTS_KEY][contract_key]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| eyre!("Could not parse darkpool address from deployments file"))
}

/// Create a set of random wallet shares
pub fn random_wallet_shares() -> SizedWalletShare {
    let mut rng = thread_rng();
    SizedWalletShare::from_scalars(&mut iter::repeat_with(|| Scalar::random(&mut rng)))
}

/// Deploy a new wallet and return the commitment to the wallet and the
/// public shares of the wallet
pub async fn deploy_new_wallet(
    client: &ArbitrumClient,
) -> Result<(WalletShareStateCommitment, SizedWalletShare)> {
    let mut valid_wallet_create_bundle = dummy_valid_wallet_create_bundle();
    valid_wallet_create_bundle.statement.public_wallet_shares = random_wallet_shares();

    let statement = valid_wallet_create_bundle.statement.clone();

    client.new_wallet(valid_wallet_create_bundle).await?;

    // The contract will compute the full commitment and insert it into the Merkle
    // tree; we repeat the same computation here for consistency
    let full_commitment = compute_wallet_commitment_from_private(
        &statement.public_wallet_shares,
        statement.private_shares_commitment,
    );
    Ok((full_commitment, statement.public_wallet_shares))
}
