//! Groups tests for zero knowledge proof gadgets
mod arithmetic;
mod poseidon;

use circuits::{mpc::SharedFabric, MultiProverCircuit};
use curve25519_dalek::scalar::Scalar;
use itertools::Itertools;
use merlin::Transcript;
use mpc_bulletproof::{
    r1cs::Verifier,
    r1cs_mpc::{MpcProver, MultiproverError},
    PedersenGens,
};
use mpc_ristretto::{
    authenticated_ristretto::AuthenticatedCompressedRistretto, beaver::SharedValueSource,
    network::MpcNetwork,
};

const TRANSCRIPT_SEED: &str = "test";

/**
 * Helpers
 */

/// Abstracts over the flow of collaboratively proving and locally verifying
/// the statement specified by a given circuit
pub(crate) fn multiprover_prove_and_verify<'a, N, S, C>(
    witness: C::Witness,
    statement: C::Statement,
    fabric: SharedFabric<N, S>,
) -> Result<(), MultiproverError>
where
    N: MpcNetwork + Send,
    S: SharedValueSource<Scalar>,
    C: MultiProverCircuit<'a, N, S>,
{
    let mut transcript = Transcript::new(TRANSCRIPT_SEED.as_bytes());
    let pc_gens = PedersenGens::default();
    let prover = MpcProver::new_with_fabric(fabric.0.clone(), &mut transcript, &pc_gens);

    // Prove the statement
    let (witness_commitments, proof) =
        C::prove(witness, statement.clone(), prover, fabric).unwrap();

    // Open the proof and commitments
    let opened_proof = proof.open()?;
    let opened_commits =
        AuthenticatedCompressedRistretto::batch_open_and_authenticate(&witness_commitments)
            .map_err(MultiproverError::Mpc)?
            .iter()
            .map(|comm| comm.value())
            .collect_vec();

    // Verify the statement with a fresh transcript
    let mut verifier_transcript = Transcript::new(TRANSCRIPT_SEED.as_bytes());
    let verifier = Verifier::new(&pc_gens, &mut verifier_transcript);

    C::verify(&opened_commits, statement, opened_proof, verifier)
        .map_err(MultiproverError::ProverError)
}
