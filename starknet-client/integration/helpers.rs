//! Helpers for `starknet-client` integration tests

use std::iter;

use circuit_types::{
    native_helpers::compute_wallet_commitment_from_private,
    traits::{BaseType, CircuitCommitmentType},
    wallet::WalletShareStateCommitment,
    SizedWalletShare,
};
use circuits::zk_circuits::valid_wallet_create::{
    ValidWalletCreateStatement, ValidWalletCreateWitnessCommitment,
};
use common::types::proof_bundles::{mocks::dummy_r1cs_proof, ValidWalletCreateBundle};
use eyre::Result;
use mpc_stark::algebra::{scalar::Scalar, stark_curve::StarkPoint};
use rand::thread_rng;
use starknet_client::client::StarknetClient;

/// Deploy a new wallet and return the commitment to the wallet and the
/// public shares of the wallet
pub async fn deploy_new_wallet(
    client: &StarknetClient,
) -> Result<(WalletShareStateCommitment, SizedWalletShare)> {
    let mut rng = thread_rng();
    let private_shares_commitment = Scalar::random(&mut rng);
    let public_shares = dummy_wallet_share();

    let tx_hash = client
        .new_wallet(
            private_shares_commitment,
            public_shares.clone(),
            ValidWalletCreateBundle {
                statement: ValidWalletCreateStatement {
                    private_shares_commitment,
                    public_wallet_shares: public_shares.clone(),
                },
                commitment: ValidWalletCreateWitnessCommitment::from_commitments(
                    &mut iter::repeat(StarkPoint::identity()),
                ),
                proof: dummy_r1cs_proof(),
            },
        )
        .await?;
    client.poll_transaction_completed(tx_hash).await?;

    // The contract will compute the full commitment and insert it into the Merkle tree;
    // we repeat the same computation here for consistency
    let full_commitment =
        compute_wallet_commitment_from_private(public_shares.clone(), private_shares_commitment);
    Ok((full_commitment, public_shares))
}

/// Create a dummy wallet share that is a random value repeated
pub fn dummy_wallet_share() -> SizedWalletShare {
    let mut rng = thread_rng();
    SizedWalletShare::from_scalars(&mut iter::repeat(Scalar::random(&mut rng)))
}
