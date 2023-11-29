//! Helper functions for Arbitrum client integration tests

use arbitrum_client::{client::ArbitrumClient, types::NUM_WIRE_TYPES};
use circuit_types::{
    native_helpers::compute_wallet_commitment_from_private, traits::BaseType,
    wallet::WalletShareStateCommitment, PlonkProof, SizedWalletShare,
};
use circuits::zk_circuits::valid_wallet_create::SizedValidWalletCreateStatement;
use common::types::proof_bundles::GenericValidWalletCreateBundle;
use constants::Scalar;
use eyre::{eyre, Result};
use mpc_plonk::proof_system::structs::ProofEvaluations;
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

/// Create a dummy wallet share that is a random value repeated
pub fn dummy_wallet_share() -> SizedWalletShare {
    let mut rng = thread_rng();
    SizedWalletShare::from_scalars(&mut iter::repeat(Scalar::random(&mut rng)))
}

/// Create a dummy proof
pub fn dummy_proof() -> PlonkProof {
    PlonkProof {
        wires_poly_comms: vec![Default::default(); NUM_WIRE_TYPES],
        prod_perm_poly_comm: Default::default(),
        split_quot_poly_comms: vec![Default::default(); NUM_WIRE_TYPES],
        opening_proof: Default::default(),
        shifted_opening_proof: Default::default(),
        poly_evals: ProofEvaluations {
            wires_evals: vec![Default::default(); NUM_WIRE_TYPES],
            wire_sigma_evals: vec![Default::default(); NUM_WIRE_TYPES - 1],
            perm_next_eval: Default::default(),
        },
        plookup_proof: Default::default(),
    }
}

/// Deploy a new wallet and return the commitment to the wallet and the
/// public shares of the wallet
pub async fn deploy_new_wallet(
    client: &ArbitrumClient,
) -> Result<(WalletShareStateCommitment, SizedWalletShare)> {
    let mut rng = thread_rng();
    let statement =
        SizedValidWalletCreateStatement::from_scalars(&mut iter::repeat(Scalar::random(&mut rng)));

    let proof = dummy_proof();

    let valid_wallet_create_bundle =
        Box::new(GenericValidWalletCreateBundle { statement: statement.clone(), proof });

    client.new_wallet(valid_wallet_create_bundle).await?;

    // The contract will compute the full commitment and insert it into the Merkle
    // tree; we repeat the same computation here for consistency
    let full_commitment = compute_wallet_commitment_from_private(
        &statement.public_wallet_shares,
        statement.private_shares_commitment,
    );
    Ok((full_commitment, statement.public_wallet_shares))
}
