//! Helper functions for Arbitrum client integration tests

use arbitrum_client::{client::ArbitrumClient, types::ContractValidWalletCreateStatement};
use circuit_types::{
    native_helpers::compute_wallet_commitment_from_private, traits::SingleProverCircuit,
    wallet::WalletShareStateCommitment,
};
use circuits::zk_circuits::{
    test_helpers::SizedWalletShare,
    valid_wallet_create::{test_helpers::create_default_witness_statement, ValidWalletCreate},
};
use eyre::{eyre, Result};
use std::{fs::File, io::Read};

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

/// Deploy a new wallet and return the commitment to the wallet and the
/// public shares of the wallet
pub async fn deploy_new_wallet(
    client: &ArbitrumClient,
) -> Result<(WalletShareStateCommitment, SizedWalletShare)> {
    let (witness, statement) = create_default_witness_statement();
    let proof = ValidWalletCreate::prove(witness, statement.clone())?;
    let contract_statement: ContractValidWalletCreateStatement = statement.clone().into();

    client
        .new_wallet(
            statement.public_wallet_shares.blinder,
            contract_statement,
            proof,
        )
        .await?;

    // The contract will compute the full commitment and insert it into the Merkle
    // tree; we repeat the same computation here for consistency
    let full_commitment = compute_wallet_commitment_from_private(
        &statement.public_wallet_shares,
        statement.private_shares_commitment,
    );
    Ok((full_commitment, statement.public_wallet_shares))
}
