//! Helpers for `starknet-client` integration tests

use std::{iter, sync::Arc};

use circuit_types::{
    native_helpers::compute_wallet_commitment_from_private,
    traits::{BaseType, CircuitCommitmentType},
    wallet::WalletShareStateCommitment,
    SizedWalletShare,
};
use circuits::zk_circuits::{
    valid_commitments::{ValidCommitmentsStatement, ValidCommitmentsWitnessCommitment},
    valid_match_mpc::ValidMatchMpcWitnessCommitment,
    valid_reblind::{ValidReblindStatement, ValidReblindWitnessCommitment},
    valid_settle::{ValidSettleStatement, ValidSettleWitnessCommitment},
    valid_wallet_create::{ValidWalletCreateStatement, ValidWalletCreateWitnessCommitment},
    valid_wallet_update::{ValidWalletUpdateStatement, ValidWalletUpdateWitnessCommitment},
};
use common::types::proof_bundles::{
    OrderValidityProofBundle, ValidCommitmentsBundle, ValidMatchMpcBundle, ValidReblindBundle,
    ValidSettleBundle, ValidWalletCreateBundle, ValidWalletUpdateBundle,
};
use eyre::Result;
use mpc_bulletproof::{r1cs::R1CSProof, InnerProductProof};
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

/// Create a dummy proof bundle for `VALID WALLET UPDATE`
pub fn dummy_valid_wallet_update_bundle() -> ValidWalletUpdateBundle {
    let statement = ValidWalletUpdateStatement::from_scalars(&mut iter::repeat(Scalar::one()));
    let commitment = ValidWalletUpdateWitnessCommitment::from_commitments(&mut iter::repeat(
        StarkPoint::identity(),
    ));
    let proof = dummy_r1cs_proof();

    ValidWalletUpdateBundle {
        statement,
        commitment,
        proof,
    }
}

/// Create a dummy proof bundle for `VALID REBLIND`
pub fn dummy_valid_reblind_bundle() -> ValidReblindBundle {
    let statement = ValidReblindStatement::from_scalars(&mut iter::repeat(Scalar::one()));
    let commitment =
        ValidReblindWitnessCommitment::from_commitments(&mut iter::repeat(StarkPoint::identity()));

    ValidReblindBundle {
        statement,
        commitment,
        proof: dummy_r1cs_proof(),
    }
}

/// Create a dummy proof bundle for `VALID COMMITMENTS`
pub fn dummy_valid_commitments_bundle() -> ValidCommitmentsBundle {
    let statement = ValidCommitmentsStatement::from_scalars(&mut iter::repeat(Scalar::one()));
    let commitment = ValidCommitmentsWitnessCommitment::from_commitments(&mut iter::repeat(
        StarkPoint::identity(),
    ));

    ValidCommitmentsBundle {
        statement,
        commitment,
        proof: dummy_r1cs_proof(),
    }
}

/// Create a dummy validity proof bundle
pub fn dummy_validity_proof_bundle() -> OrderValidityProofBundle {
    OrderValidityProofBundle {
        reblind_proof: Arc::new(dummy_valid_reblind_bundle()),
        commitment_proof: Arc::new(dummy_valid_commitments_bundle()),
    }
}

/// Create a dummy proof bundle for `VALID MATCH MPC`
pub fn dummy_valid_match_mpc_bundle() -> ValidMatchMpcBundle {
    let commitment =
        ValidMatchMpcWitnessCommitment::from_commitments(&mut iter::repeat(StarkPoint::identity()));

    ValidMatchMpcBundle {
        commitment,
        statement: (),
        proof: dummy_r1cs_proof(),
    }
}

/// Create a dummy proof bundle ofr `VALID SETTLE`
pub fn dummy_valid_settle_bundle() -> ValidSettleBundle {
    let statement = ValidSettleStatement::from_scalars(&mut iter::repeat(Scalar::one()));
    let commitment =
        ValidSettleWitnessCommitment::from_commitments(&mut iter::repeat(StarkPoint::identity()));

    ValidSettleBundle {
        statement,
        commitment,
        proof: dummy_r1cs_proof(),
    }
}

/// Create a dummy wallet share that is a random value repeated
pub fn dummy_wallet_share() -> SizedWalletShare {
    let mut rng = thread_rng();
    SizedWalletShare::from_scalars(&mut iter::repeat(Scalar::random(&mut rng)))
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
