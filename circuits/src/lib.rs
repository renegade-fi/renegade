//! Groups circuits for MPC and zero knowledge execution

#![feature(generic_const_exprs)]
#![allow(incomplete_features)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(unsafe_code)]

use circuit_types::{
    errors::{ProverError, VerifierError},
    traits::{
        CircuitBaseType, MultiProverCircuit, MultiproverCircuitBaseType,
        MultiproverCircuitCommitmentType, SingleProverCircuit,
    },
};
use merlin::HashChainTranscript as Transcript;
use mpc_bulletproof::{
    r1cs::{Prover, R1CSProof, Verifier},
    r1cs_mpc::{MpcProver, PartiallySharedR1CSProof},
    PedersenGens,
};

pub mod mpc_circuits;
pub mod mpc_gadgets;
mod tracing;
pub mod zk_circuits;
pub mod zk_gadgets;

/// The highest possible set bit in the Dalek scalar field
pub(crate) const SCALAR_MAX_BITS: usize = 253;
/// The seed for a fiat-shamir transcript
pub(crate) const TRANSCRIPT_SEED: &str = "merlin seed";
/// The maximum bit index that may be set in a positive `Scalar`
pub(crate) const POSITIVE_SCALAR_MAX_BITS: usize = 250;

// ----------
// | Macros |
// ----------

/// A debug macro used for printing wires in a single-prover circuit during execution
#[allow(unused)]
macro_rules! print_wire {
    ($x:expr, $cs:ident) => {{
        use crypto::fields::scalar_to_biguint;
        use tracing::log;
        let x_eval = $cs.eval(&$x.into());
        log::info!("eval({}): {x_eval}", stringify!($x));
    }};
}

/// A debug macro used for printing wires in a raw MPC circuit during execution
#[allow(unused)]
macro_rules! print_mpc_wire {
    ($x:expr) => {{
        use crypto::fields::scalar_to_biguint;
        use tracing::log;
        let x_eval = $x.open().unwrap().to_scalar();
        log::info!("eval({}): {:?}", stringify!($x), scalar_to_biguint(&x_eval));
    }};
}

/// A debug macro used for printing wires in an MPC-ZK circuit during execution
#[allow(unused)]
macro_rules! print_multiprover_wire {
    ($x:expr, $cs:ident) => {{
        use futures::executor::block_on;
        use mpc_stark::algebra::authenticated_scalar::AuthenticatedScalarResult;
        use tracing::log;

        let x_eval = block_on(AuthenticatedScalarResult::open(&$cs.eval(&$x.into())));
        log::info!("eval({}): {x_eval}", stringify!($x));
    }};
}

use mpc_stark::{algebra::scalar::Scalar, MpcFabric};
#[allow(unused)]
pub(crate) use print_mpc_wire;
#[allow(unused)]
pub(crate) use print_multiprover_wire;
#[allow(unused)]
pub(crate) use print_wire;

// ------------------
// | Helper Methods |
// ------------------

/// Represents 2^m as a scalar
pub fn scalar_2_to_m(m: usize) -> Scalar {
    if m >= SCALAR_MAX_BITS {
        return Scalar::zero();
    }
    if (128..SCALAR_MAX_BITS).contains(&m) {
        Scalar::from(1u128 << 127) * Scalar::from(1u128 << (m - 127))
    } else {
        Scalar::from(1u128 << m)
    }
}

/// Abstracts over the flow of proving a single-prover circuit
pub fn singleprover_prove<C: SingleProverCircuit>(
    witness: C::Witness,
    statement: C::Statement,
) -> Result<(<C::Witness as CircuitBaseType>::CommitmentType, R1CSProof), ProverError> {
    let mut transcript = Transcript::new(TRANSCRIPT_SEED.as_bytes());
    let pc_gens = PedersenGens::default();
    let prover = Prover::new(&pc_gens, &mut transcript);

    C::prove(witness, statement, prover)
}

/// Abstracts over the flow of collaboratively proving a generic circuit
#[allow(clippy::type_complexity)]
pub fn multiprover_prove<C>(
    witness: C::Witness,
    statement: C::Statement,
    fabric: MpcFabric,
) -> Result<
    (
        <C::Witness as MultiproverCircuitBaseType>::MultiproverCommType,
        PartiallySharedR1CSProof,
    ),
    ProverError,
>
where
    C: MultiProverCircuit,
{
    let transcript = Transcript::new(TRANSCRIPT_SEED.as_bytes());
    let pc_gens = PedersenGens::default();
    let prover = MpcProver::new_with_fabric(fabric.clone(), transcript, pc_gens);

    // Prove the statement
    C::prove(witness, statement, fabric, prover)
}

/// Abstracts over the flow of verifying a proof for a single-prover proved circuit
pub fn verify_singleprover_proof<C: SingleProverCircuit>(
    statement: C::Statement,
    witness_commitment: <C::Witness as CircuitBaseType>::CommitmentType,
    proof: R1CSProof,
) -> Result<(), VerifierError> {
    // Verify the statement with a fresh transcript
    let mut verifier_transcript = Transcript::new(TRANSCRIPT_SEED.as_bytes());
    let pc_gens = PedersenGens::default();
    let verifier = Verifier::new(&pc_gens, &mut verifier_transcript);

    C::verify(witness_commitment, statement, proof, verifier)
}

/// Abstracts over the flow of verifying a proof for a collaboratively proved circuit
pub fn verify_collaborative_proof<C>(
    statement: <C::Statement as MultiproverCircuitBaseType>::BaseType,
    witness_commitment: <
        <C::Witness as MultiproverCircuitBaseType>::MultiproverCommType as MultiproverCircuitCommitmentType
        >::BaseCommitType,
    proof: R1CSProof,
) -> Result<(), VerifierError>
where
    C: MultiProverCircuit,
{
    // Verify the statement with a fresh transcript
    let mut verifier_transcript = Transcript::new(TRANSCRIPT_SEED.as_bytes());
    let pc_gens = PedersenGens::default();
    let verifier = Verifier::new(&pc_gens, &mut verifier_transcript);

    C::verify(witness_commitment, statement, proof, verifier)
}

// ----------------
// | Test Helpers |
// ----------------
#[cfg(test)]
pub(crate) mod test_helpers {
    use circuit_types::{errors::VerifierError, traits::SingleProverCircuit};
    use env_logger::{Builder, Env, Target};
    use merlin::HashChainTranscript as Transcript;
    use mpc_bulletproof::{
        r1cs::{Prover, Verifier},
        PedersenGens,
    };
    use tracing::log::LevelFilter;

    const TRANSCRIPT_SEED: &str = "test";

    // ---------
    // | Setup |
    // ---------

    /// Constructor to initialize logging in tests
    #[ctor::ctor]
    fn setup() {
        init_logger()
    }

    pub fn init_logger() {
        let env = Env::default().filter_or("MY_CRATE_LOG", "trace");

        let mut builder = Builder::from_env(env);
        builder.target(Target::Stdout);
        builder.filter_level(LevelFilter::Info);

        builder.init();
    }

    // -----------
    // | Helpers |
    // -----------

    /// Abstracts over the flow of proving and verifying a circuit given
    /// a valid statement + witness assignment
    pub fn bulletproof_prove_and_verify<C: SingleProverCircuit>(
        witness: C::Witness,
        statement: C::Statement,
    ) -> Result<(), VerifierError> {
        let mut transcript = Transcript::new(TRANSCRIPT_SEED.as_bytes());
        let pc_gens = PedersenGens::default();
        let prover = Prover::new(&pc_gens, &mut transcript);

        // Prove the statement
        let (witness_commitment, proof) = C::prove(witness, statement.clone(), prover).unwrap();

        // Verify the statement with a fresh transcript
        let mut verifier_transcript = Transcript::new(TRANSCRIPT_SEED.as_bytes());
        let verifier = Verifier::new(&pc_gens, &mut verifier_transcript);

        C::verify(witness_commitment, statement, proof, verifier)
    }
}

#[cfg(test)]
mod circuits_test {
    use num_bigint::BigInt;
    use rand::{thread_rng, Rng};
    use renegade_crypto::fields::bigint_to_scalar;

    use crate::scalar_2_to_m;

    #[test]
    fn test_scalar_2_to_m() {
        let rand_m: usize = thread_rng().gen_range(0..256);
        let res = scalar_2_to_m(rand_m);

        let expected = bigint_to_scalar(&(BigInt::from(1u64) << rand_m));
        assert_eq!(res, expected);
    }
}
