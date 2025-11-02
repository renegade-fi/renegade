//! Groups circuits for MPC and zero knowledge execution

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(unsafe_code)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![allow(incomplete_features)]
#![feature(inherent_associated_types)]

use circuit_types::{
    CollaborativePlonkProof, Fabric, MpcProofLinkingHint, PlonkProof, ProofLinkingHint,
    errors::{ProverError, VerifierError},
    traits::{MpcType, MultiProverCircuit, SingleProverCircuit},
};
use constants::Scalar;

pub mod mpc_circuits;
pub mod mpc_gadgets;
pub mod zk_circuits;
pub mod zk_gadgets;

// -------------
// | Constants |
// -------------

/// The number of bits in a `Scalar`
pub(crate) const SCALAR_MAX_BITS: usize = 254;
/// The number of bits in a `Scalar` minus two
///
/// Used to truncate values to the range of positive integers in our field
pub(crate) const SCALAR_BITS_MINUS_TWO: usize = SCALAR_MAX_BITS - 2;

// ----------
// | Macros |
// ----------

/// A debug macro used for printing wires in a single-prover circuit during
/// execution
#[allow(unused)]
macro_rules! print_wire {
    ($x:expr, $cs:ident) => {{
        use circuit_types::traits::CircuitVarType;
        let x_eval = $x.eval($cs);
        println!("eval({}): {x_eval}", stringify!($x));
    }};
}

/// A debug macro used for printing wires in a single-prover circuit during
/// execution. Uses a debug format string to print the value.
#[allow(unused)]
macro_rules! print_wire_debug {
    ($x:expr, $cs:ident) => {{
        use circuit_types::traits::CircuitVarType;
        let x_eval = $x.eval($cs);
        println!("eval({}): {x_eval:?}", stringify!($x));
    }};
}

/// A debug macro used for printing wires in a raw MPC circuit during execution
#[allow(unused)]
macro_rules! print_mpc_wire {
    ($x:expr) => {{
        use circuit_types::traits::MpcType;
        use futures::executor::block_on;
        use renegade_crypto::fields::scalar_to_biguint;

        let x_eval = block_on($x.open());
        if $x.fabric().party_id() == 0 {
            info!("eval({}): {:?}", stringify!($x), scalar_to_biguint(&x_eval));
        }
    }};
}

/// A debug macro used for printing wires in an MPC-ZK circuit during execution
#[allow(unused)]
macro_rules! print_multiprover_wire {
    ($x:expr, $cs:ident) => {{
        use circuit_types::traits::CircuitVarType;
        use constants::AuthenticatedScalar;
        use futures::executor::block_on;

        let eval: AuthenticatedScalar = $x.eval_multiprover($cs);
        let x_eval = block_on(eval.open());
        println!("eval({}): {x_eval}", stringify!($x));
    }};
}

#[allow(unused)]
pub(crate) use print_mpc_wire;
#[allow(unused)]
pub(crate) use print_multiprover_wire;
#[allow(unused)]
pub(crate) use print_wire;
#[allow(unused)]
pub(crate) use print_wire_debug;

// -----------
// | Helpers |
// -----------

/// Construct the `Scalar` representation of 2^m
pub fn scalar_2_to_m(m: u64) -> Scalar {
    assert!(m < SCALAR_MAX_BITS as u64, "result would overflow Scalar field");

    Scalar::from(2u8).pow(m)
}

/// Construct a proof of a given circuit
pub fn singleprover_prove<C: SingleProverCircuit>(
    witness: C::Witness,
    statement: C::Statement,
) -> Result<PlonkProof, ProverError> {
    C::prove(witness, statement)
}

/// Construct a proof of a given circuit and return a link hint with it
pub fn singleprover_prove_with_hint<C: SingleProverCircuit>(
    witness: C::Witness,
    statement: C::Statement,
) -> Result<(PlonkProof, ProofLinkingHint), ProverError> {
    C::prove_with_link_hint(witness, statement)
}

/// Verify a proof of a given circuit
pub fn verify_singleprover_proof<C: SingleProverCircuit>(
    statement: C::Statement,
    proof: &PlonkProof,
) -> Result<(), VerifierError> {
    C::verify(statement, proof)
}

/// Generate a proof of a circuit and verify it
pub fn singleprover_prove_and_verify<C: SingleProverCircuit>(
    witness: C::Witness,
    statement: C::Statement,
) -> Result<(), ProverError> {
    let proof = C::prove(witness, statement.clone())?;
    C::verify(statement, &proof).map_err(ProverError::Verification)
}

/// Construct a multiprover proof of a given circuit
pub fn multiprover_prove<C: MultiProverCircuit>(
    witness: C::Witness,
    statement: C::Statement,
    fabric: Fabric,
) -> Result<CollaborativePlonkProof, ProverError> {
    C::prove(witness, statement, fabric).map_err(ProverError::Plonk)
}

/// Construct a collaborative proof of a given circuit and return a shared link
/// hint with it
pub fn multiprover_prove_with_hint<C: MultiProverCircuit>(
    witness: C::Witness,
    statement: C::Statement,
    fabric: Fabric,
) -> Result<(CollaborativePlonkProof, MpcProofLinkingHint), ProverError> {
    C::prove_with_link_hint(witness, statement, fabric).map_err(ProverError::Plonk)
}

/// Generate a multiprover proof and verify it
pub async fn multiprover_prove_and_verify<C: MultiProverCircuit>(
    witness: C::Witness,
    statement: C::Statement,
    fabric: Fabric,
) -> Result<(), ProverError> {
    let proof = C::prove(witness, statement.clone(), fabric)
        .map_err(ProverError::Plonk)?
        .open_authenticated()
        .await
        .map_err(ProverError::Plonk)?;

    let statement = statement.open().await.map_err(ProverError::Mpc)?;
    C::verify(statement, &proof).map_err(ProverError::Verification)
}

// ----------------
// | Test Helpers |
// ----------------

/// Helpers used in tests throughout the crate and integration tests outside
/// the crate
#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {

    use alloy_primitives::Address;
    use ark_mpc::error::MpcError;
    use circuit_types::{AMOUNT_BITS, Amount};
    use constants::{AuthenticatedScalar, Scalar};
    use futures::{Future, FutureExt, future::join_all};
    use itertools::Itertools;
    use rand::{Rng, distributions::uniform::SampleRange, thread_rng};

    // -----------
    // | Helpers |
    // -----------

    /// Open a value and unwrap the result
    #[macro_export]
    macro_rules! open_unwrap {
        ($x:expr) => {
            $x.open_authenticated().await.unwrap()
        };
    }

    /// Open a vector of values and unwrap the result
    #[macro_export]
    macro_rules! open_unwrap_vec {
        ($x:expr) => {
            $crate::test_helpers::joint_open($x).await.unwrap()
        };
    }

    /// Create a random sequence of field elements
    pub fn random_scalars_vec(n: usize) -> Vec<Scalar> {
        let mut rng = thread_rng();
        (0..n).map(|_| Scalar::random(&mut rng)).collect_vec()
    }

    /// Create a random sequence of field elements as an array
    pub fn random_scalars_array<const N: usize>() -> [Scalar; N] {
        random_scalars_vec(N).try_into().unwrap()
    }

    /// Generate a random amount valid in a wallet
    ///
    /// Leave buffer for additions and subtractions
    pub fn random_amount() -> Amount {
        let mut rng = thread_rng();
        let amt = (0..max_amount()).sample_single(&mut rng);

        amt / 10
    }

    /// Get the maximum amount allowed
    pub fn max_amount() -> Amount {
        (1u128 << AMOUNT_BITS) - 1u128
    }

    /// Generate a random address
    pub fn random_address() -> Address {
        let mut rng = thread_rng();
        let mut address_bytes = [0u8; 20];
        rng.fill(&mut address_bytes);
        Address::from(address_bytes)
    }

    /// Open a batch of values and join into a single future
    #[allow(unused)]
    pub fn joint_open(
        values: Vec<AuthenticatedScalar>,
    ) -> impl Future<Output = Result<Vec<Scalar>, MpcError>> {
        let mut futures = Vec::new();
        for value in values {
            futures.push(value.open_authenticated());
        }

        join_all(futures).map(|res| res.into_iter().collect::<Result<Vec<_>, _>>())
    }
}
