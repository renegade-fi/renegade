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
use common::types::proof_bundles::ValidWalletCreateBundle;
use eyre::Result;
use mpc_bulletproof::{r1cs::R1CSProof, InnerProductProof};
use mpc_stark::algebra::{scalar::Scalar, stark_curve::StarkPoint};
use rand::thread_rng;
use starknet_client::client::StarknetClient;

/// Deploy a new wallet and return the commitment inserted into the state tree
pub async fn deploy_new_wallet(
    client: &StarknetClient,
) -> Result<(WalletShareStateCommitment, SizedWalletShare)> {
    let mut rng = thread_rng();
    let private_shares_commitment = Scalar::random(&mut rng);
    let public_shares = SizedWalletShare::from_scalars(&mut iter::repeat(Scalar::random(&mut rng)));

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

/// Create a dummy R1CS proof
fn dummy_r1cs_proof() -> R1CSProof {
    R1CSProof {
        A_I1: StarkPoint::identity(),
        A_O1: StarkPoint::identity(),
        S1: StarkPoint::identity(),
        A_I2: StarkPoint::identity(),
        A_O2: StarkPoint::identity(),
        S2: StarkPoint::identity(),
        T_1: StarkPoint::identity(),
        T_3: StarkPoint::identity(),
        T_4: StarkPoint::identity(),
        T_5: StarkPoint::identity(),
        T_6: StarkPoint::identity(),
        t_x: Scalar::one(),
        t_x_blinding: Scalar::one(),
        e_blinding: Scalar::one(),
        ipp_proof: dummy_ip_proof(),
    }
}

/// Create a dummy inner product proof
fn dummy_ip_proof() -> InnerProductProof {
    InnerProductProof {
        L_vec: vec![StarkPoint::identity()],
        R_vec: vec![StarkPoint::identity()],
        a: Scalar::one(),
        b: Scalar::one(),
    }
}
