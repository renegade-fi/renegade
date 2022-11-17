//! Groups circuits for MPC and zero knowledge execution
#![feature(generic_const_exprs)]
#![allow(incomplete_features)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

use std::ops::Neg;

use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use errors::{MpcError, ProverError, VerifierError};
use itertools::Itertools;
use mpc::SharedFabric;
use mpc_bulletproof::{
    r1cs::{Prover, R1CSProof, Verifier},
    r1cs_mpc::{MpcProver, SharedR1CSProof},
};
use mpc_ristretto::{
    authenticated_ristretto::AuthenticatedCompressedRistretto, beaver::SharedValueSource,
    network::MpcNetwork,
};
use num_bigint::{BigInt, BigUint, Sign};
use rand_core::{CryptoRng, RngCore};

pub mod constants;
pub mod errors;
pub mod mpc;
pub mod mpc_circuits;
pub mod mpc_gadgets;
pub mod types;
pub mod zk_circuits;
pub mod zk_gadgets;

pub(crate) const SCALAR_MAX_BITS: usize = 252;

/**
 * Helpers
 */

/// Represents 2^m as a scalar
pub fn scalar_2_to_m(m: usize) -> Scalar {
    assert!(
        m < SCALAR_MAX_BITS,
        "Cannot fill scalar with greater than {:?} bits, got {:?}",
        SCALAR_MAX_BITS,
        m,
    );
    if (128..SCALAR_MAX_BITS).contains(&m) {
        Scalar::from(1u128 << 127) * Scalar::from(1u128 << (m - 127))
    } else {
        Scalar::from(1u128 << m)
    }
}

/// Convert a scalar to a BigInt
pub fn scalar_to_bigint(a: &Scalar) -> BigInt {
    BigInt::from_signed_bytes_le(&a.to_bytes())
}

/// Convert a scalar to a BigUint
pub fn scalar_to_biguint(a: &Scalar) -> BigUint {
    BigUint::from_bytes_le(&a.to_bytes())
}

/// Convert a bigint to a scalar
pub fn bigint_to_scalar(a: &BigInt) -> Scalar {
    let (sign, mut bytes) = a.to_bytes_le();
    if bytes.len() < 32 {
        zero_pad_bytes(&mut bytes, 32)
    }

    let scalar = Scalar::from_bytes_mod_order(bytes[..32].try_into().unwrap());

    match sign {
        Sign::Minus => scalar.neg(),
        _ => scalar,
    }
}

/// Pad an array up to the desired length with zeros
fn zero_pad_bytes(unpadded_buf: &mut Vec<u8>, n: usize) {
    unpadded_buf.append(&mut vec![0u8; n - unpadded_buf.len()])
}

/// Convert a bigint to a vector of bits, encoded as scalars
pub fn bigint_to_scalar_bits<const D: usize>(a: &BigInt) -> Vec<Scalar> {
    let mut res = Vec::with_capacity(D);
    // Reverse the iterator; BigInt::bits expects big endian
    for i in 0..D {
        res.push(if a.bit(i as u64) {
            Scalar::one()
        } else {
            Scalar::zero()
        })
    }

    res
}

/**
 * Trait definitions
 */

/// Defines functionality to allocate a value within a single-prover constraint system
pub trait CommitProver {
    /// The type that results from committing to the base type
    type VarType;
    type CommitType;
    type ErrorType;

    /// Commit to the base type in the constraint system
    ///
    /// Returns a tuple holding both the var type (used for operations)
    /// within the constraint system, and the commit type; which is passed
    /// to the verifier to use as hidden values
    fn commit_prover<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType>;
}

/// Defines functionality to commit to a value in a verifier's constraint system
pub trait CommitVerifier {
    /// The type that results from committing to the implementation types
    type VarType;
    type ErrorType;

    /// Commit to a hidden value in the Verifier
    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType>;
}

/// Defines functionality to allocate a value within an MPC network
pub trait Allocate<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The output type that results from allocating the value in the network
    type SharedType;
    type ErrorType;

    /// Allocates the raw type in the network as a shared value
    fn allocate(
        &self,
        owning_party: u64,
        fabric: SharedFabric<N, S>,
    ) -> Result<Self::SharedType, Self::ErrorType>;
}

/// Defines functionality to allocate a base type as a shared committment in a multi-prover
/// constraint system
pub trait CommitSharedProver<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The type that results from committing to the base type
    type SharedVarType;
    type CommitType;
    type ErrorType;

    /// Commit to the base type in the constraint system
    fn commit<R: RngCore + CryptoRng>(
        &self,
        owning_party: u64,
        rng: &mut R,
        prover: &mut MpcProver<N, S>,
    ) -> Result<(Self::SharedVarType, Self::CommitType), Self::ErrorType>;
}

/// Defines functionality for a shared, allocated type to be opened to another type
///
/// The type this is implemented for is assumed to be a secret sharing of some MPC
/// network allocated value.
pub trait Open {
    /// The output type that results from opening this value
    type OpenOutput;
    /// The error type that results if opening fails
    type Error;
    /// Opens the shared type without authenticating
    fn open(&self) -> Result<Self::OpenOutput, Self::Error>;
    /// Opens the shared type and authenticates the result
    fn open_and_authenticate(&self) -> Result<Self::OpenOutput, Self::Error>;
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Open
    for AuthenticatedCompressedRistretto<N, S>
{
    type OpenOutput = CompressedRistretto;
    type Error = MpcError;

    fn open(&self) -> Result<Self::OpenOutput, Self::Error> {
        Ok(self
            .open()
            .map_err(|err| MpcError::OpeningError(err.to_string()))?
            .value())
    }

    fn open_and_authenticate(&self) -> Result<Self::OpenOutput, Self::Error> {
        Ok(self
            .open_and_authenticate()
            .map_err(|err| MpcError::OpeningError(err.to_string()))?
            .value())
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Open
    for Vec<AuthenticatedCompressedRistretto<N, S>>
{
    type OpenOutput = Vec<CompressedRistretto>;
    type Error = MpcError;

    fn open(&self) -> Result<Self::OpenOutput, Self::Error> {
        Ok(AuthenticatedCompressedRistretto::batch_open(&self)
            .map_err(|err| MpcError::OpeningError(err.to_string()))?
            .iter()
            .map(|comm| comm.value())
            .collect_vec())
    }

    fn open_and_authenticate(&self) -> Result<Self::OpenOutput, Self::Error> {
        Ok(
            AuthenticatedCompressedRistretto::batch_open_and_authenticate(&self)
                .map_err(|err| MpcError::OpeningError(err.to_string()))?
                .iter()
                .map(|comm| comm.value())
                .collect_vec(),
        )
    }
}

/// Defines the abstraction of a Circuit.
///
/// A circuit represents a provable unit, a complete NP statement that takes as input
/// a series of values, commits to them, and applies constraints
///
/// The input types are broken out into the witness type and the statement type.
/// The witness type represents the secret witness that the prover has access to but
/// that the verifier does not. The statement is the set of public inputs and any
/// other circuit meta-parameters that both prover and verifier have access to.
pub trait SingleProverCircuit {
    /// The witness type, given only to the prover, which generates a blinding commitment
    /// that can be given to the verifier
    type Witness;
    /// The statement type, given to both the prover and verifier, parameterizes the underlying
    /// NP statement being proven
    type Statement: Clone;
    /// The data type of the output committment from the prover.
    ///
    /// The prover commits to the witness and sends this commitment to the verifier, this type
    /// is the structure in which that commitment is sent
    type WitnessCommitment;

    /// The size of the bulletproof generators that must be allocated
    /// to fully compute a proof or verification of the statement
    ///
    /// This is a function of circuit depth, one generator is needed per
    /// multiplication gate (roughly)
    const BP_GENS_CAPACITY: usize;

    /// Generate a proof of the statement represented by the circuit
    ///
    /// Returns both the commitment to the inputs, as well as the proof itself
    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        prover: Prover,
    ) -> Result<(Self::WitnessCommitment, R1CSProof), ProverError>;

    /// Verify a proof of the statement represented by the circuit
    ///
    /// The verifier has access to the statement variables, but only hiding (and binding)
    /// commitments to the witness variables
    fn verify(
        witness_commitment: Self::WitnessCommitment,
        statement: Self::Statement,
        proof: R1CSProof,
        verifier: Verifier,
    ) -> Result<(), VerifierError>;
}

/// Defines the abstraction of a Circuit that is evaluated in a multiprover setting
///
/// A circuit represents a provable unit, a complete NP statement that takes as input
/// a series of values, commits to them, and applies constraints.
///
/// The input types are broken out into the witness type and the statement type.
/// The witness type represents the secret witness that the prover has access to but
/// that the verifier does not. The statement is the set of public inputs and any
/// other circuit meta-parameters that both prover and verifier have access to.
pub trait MultiProverCircuit<'a, N: 'a + MpcNetwork + Send, S: 'a + SharedValueSource<Scalar>> {
    /// The witness type, given only to the prover, which generates a blinding commitment
    /// that can be given to the verifier
    type Witness;
    /// The statement type, given to both the prover and verifier, parameterizes the underlying
    /// NP statement being proven
    type Statement: Clone;
    /// The data type of the output committment from the prover.
    ///
    /// The prover commits to the witness and sends this commitment to the verifier, this type
    /// is the structure in which that commitment is sent
    type WitnessCommitment: Open;

    /// The size of the bulletproof generators that must be allocated
    /// to fully compute a proof or verification of the statement
    ///
    /// This is a function of circuit depth, one generator is needed per
    /// multiplication gate (roughly)
    const BP_GENS_CAPACITY: usize;

    /// Generate a proof of the statement represented by the circuit
    ///
    /// Returns both the commitment to the inputs, as well as the proof itself
    #[allow(clippy::type_complexity)]
    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        prover: MpcProver<'a, '_, '_, N, S>,
        fabric: SharedFabric<N, S>,
    ) -> Result<(Self::WitnessCommitment, SharedR1CSProof<N, S>), ProverError>;

    /// Verify a proof of the statement represented by the circuit
    ///
    /// The verifier has access to the statement variables, but only hiding (and binding)
    /// commitments to the witness variables
    ///
    /// The verifier in this case provides the same interface as the single prover case.
    /// The proof and commitments to the witness should be "opened" by having the MPC
    /// parties reconstruct the underlying secret from their shares. Then the opened
    /// proof and commitments can be passed to the verifier.
    fn verify(
        witness_commitments: <Self::WitnessCommitment as Open>::OpenOutput,
        statement: Self::Statement,
        proof: R1CSProof,
        verifier: Verifier,
    ) -> Result<(), VerifierError>;
}

/**
 * Test helpers
 */

#[cfg(test)]
pub(crate) mod test_helpers {
    use ark_ff::{Fp256, MontBackend, MontConfig};
    use ark_sponge::poseidon::PoseidonConfig;
    use curve25519_dalek::scalar::Scalar;
    use merlin::Transcript;
    use mpc_bulletproof::{
        r1cs::{Prover, Verifier},
        PedersenGens,
    };
    use num_bigint::{BigInt, BigUint};

    use crate::{
        bigint_to_scalar, errors::VerifierError, mpc_gadgets::poseidon::PoseidonSpongeParameters,
        scalar_to_bigint, scalar_to_biguint, SingleProverCircuit,
    };

    const TRANSCRIPT_SEED: &str = "test";

    /// Defines a custom Arkworks field with the same modulus as the Dalek Ristretto group
    ///
    /// This is necessary for testing against Arkworks, otherwise the values will not be directly comparable
    #[derive(MontConfig)]
    #[modulus = "7237005577332262213973186563042994240857116359379907606001950938285454250989"]
    #[generator = "2"]
    pub(crate) struct TestFieldConfig;
    pub(crate) type TestField = Fp256<MontBackend<TestFieldConfig, 4>>;

    /**
     * Helpers
     */

    /// Converts a dalek scalar to an arkworks ff element
    pub(crate) fn scalar_to_prime_field(a: &Scalar) -> TestField {
        Fp256::from(scalar_to_biguint(a))
    }

    /// Converts a nested vector of Dalek scalars to arkworks field elements
    pub(crate) fn convert_scalars_nested_vec(a: &Vec<Vec<Scalar>>) -> Vec<Vec<TestField>> {
        let mut res = Vec::with_capacity(a.len());
        for row in a.iter() {
            let mut row_res = Vec::with_capacity(row.len());
            for val in row.iter() {
                row_res.push(scalar_to_prime_field(val))
            }

            res.push(row_res);
        }

        res
    }

    /// Converts a set of Poseidon parameters encoded as scalars to parameters encoded as field elements
    pub(crate) fn convert_params(
        native_params: &PoseidonSpongeParameters,
    ) -> PoseidonConfig<TestField> {
        PoseidonConfig::new(
            native_params.full_rounds,
            native_params.parital_rounds,
            native_params.alpha,
            convert_scalars_nested_vec(&native_params.mds_matrix),
            convert_scalars_nested_vec(&native_params.round_constants),
            native_params.rate,
            native_params.capacity,
        )
    }

    /// Convert an arkworks prime field element to a bigint
    pub(crate) fn felt_to_bigint(element: &TestField) -> BigInt {
        let felt_biguint = Into::<BigUint>::into(*element);
        felt_biguint.into()
    }

    /// Convert an arkworks prime field element to a scalar
    pub(crate) fn felt_to_scalar(element: &TestField) -> Scalar {
        let felt_bigint = felt_to_bigint(element);
        bigint_to_scalar(&felt_bigint)
    }

    /// Compares a Dalek Scalar to an Arkworks field element
    pub(crate) fn compare_scalar_to_felt(scalar: &Scalar, felt: &TestField) -> bool {
        scalar_to_bigint(scalar).eq(&felt_to_bigint(felt))
    }

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
    use curve25519_dalek::scalar::Scalar;
    use num_bigint::BigInt;
    use rand::{thread_rng, Rng, RngCore};

    use crate::{bigint_to_scalar, bigint_to_scalar_bits, scalar_2_to_m, scalar_to_bigint};

    #[test]
    fn test_scalar_2_to_m() {
        let rand_m: usize = thread_rng().gen_range(0..256);
        let res = scalar_2_to_m(rand_m);

        let expected = bigint_to_scalar(&(BigInt::from(1u64) << rand_m));
        assert_eq!(res, expected);
    }

    #[test]
    fn test_scalar_to_bigint() {
        let rand_val = thread_rng().next_u64();
        let res = scalar_to_bigint(&Scalar::from(rand_val));

        assert_eq!(res, BigInt::from(rand_val));
    }

    #[test]
    fn test_bigint_to_scalar() {
        let rand_val = thread_rng().next_u64();
        let res = bigint_to_scalar(&BigInt::from(rand_val));

        assert_eq!(res, Scalar::from(rand_val));
    }

    #[test]
    fn test_bigint_to_scalar_bits() {
        let mut rng = thread_rng();
        let random_scalar_bits = (0..256)
            .map(|_| rng.gen_bool(0.5 /* p */) as u64)
            .collect::<Vec<_>>();

        let random_bigint = random_scalar_bits
            .iter()
            .rev()
            .cloned()
            .map(BigInt::from)
            .fold(BigInt::from(0u64), |acc, val| acc * 2 + val);
        let scalar_bits = random_scalar_bits
            .into_iter()
            .map(Scalar::from)
            .collect::<Vec<_>>();

        let res = bigint_to_scalar_bits::<256 /* bits */>(&random_bigint);

        assert_eq!(res.len(), scalar_bits.len());
        assert_eq!(res, scalar_bits);
    }
}
