//! Groups circuits for MPC and zero knowledge execution
#![feature(generic_const_exprs)]
#![allow(incomplete_features)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(unsafe_code)]

use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use errors::{MpcError, ProverError, VerifierError};
use itertools::Itertools;
use merlin::Transcript;
use mpc::SharedFabric;
use mpc_bulletproof::{
    r1cs::{Prover, R1CSProof, RandomizableConstraintSystem, Variable, Verifier},
    r1cs_mpc::{MpcProver, MpcVariable, SharedR1CSProof},
    PedersenGens,
};
use mpc_ristretto::{
    authenticated_ristretto::AuthenticatedCompressedRistretto,
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource, network::MpcNetwork,
};
use serde::{Deserialize, Serialize};

use rand_core::{CryptoRng, OsRng, RngCore};

pub mod errors;
pub mod mpc;
pub mod mpc_circuits;
pub mod mpc_gadgets;
pub mod types;
pub mod zk_circuits;
pub mod zk_gadgets;

/// The maximum number of balances allowed in a wallet
pub const MAX_BALANCES: usize = 5;
/// The maximum number of fees a wallet may hold
pub const MAX_FEES: usize = 5;
/// The maximum number of orders allowed in a wallet
pub const MAX_ORDERS: usize = 5;
/// The highest possible set bit for a positive scalar
pub(crate) const POSITIVE_SCALAR_MAX_BITS: usize = 251;
/// The highest possible set bit in the Dalek scalar field
pub(crate) const SCALAR_MAX_BITS: usize = 253;
/// The seed for a fiat-shamir transcript
pub(crate) const TRANSCRIPT_SEED: &str = "merlin seed";

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
        log::info!("eval({}): {:?}", stringify!($x), scalar_to_biguint(&x_eval));
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
        use crypto::fields::scalar_to_biguint;
        use tracing::log;
        let x_eval = $cs.eval(&$x.into()).unwrap().open().unwrap().to_scalar();
        log::info!("eval({}): {:?}", stringify!($x), scalar_to_biguint(&x_eval));
    }};
}

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
) -> Result<(C::WitnessCommitment, R1CSProof), ProverError> {
    let mut transcript = Transcript::new(TRANSCRIPT_SEED.as_bytes());
    let pc_gens = PedersenGens::default();
    let prover = Prover::new(&pc_gens, &mut transcript);

    C::prove(witness, statement, prover)
}

/// Abstracts over the flow of collaboratively proving a generic circuit
pub fn multiprover_prove<'a, N, S, C>(
    witness: C::Witness,
    statement: C::Statement,
    fabric: SharedFabric<N, S>,
) -> Result<(C::WitnessCommitment, SharedR1CSProof<N, S>), ProverError>
where
    N: MpcNetwork + Send,
    S: SharedValueSource<Scalar>,
    C: MultiProverCircuit<'a, N, S>,
{
    let mut transcript = Transcript::new(TRANSCRIPT_SEED.as_bytes());
    let pc_gens = PedersenGens::default();
    let prover = MpcProver::new_with_fabric(fabric.0.clone(), &mut transcript, &pc_gens);

    // Prove the statement
    C::prove(witness, statement.clone(), prover, fabric)
}

/// Abstracts over the flow of verifying a proof for a single-prover proved circuit
pub fn verify_singleprover_proof<C: SingleProverCircuit>(
    statement: C::Statement,
    witness_commitment: C::WitnessCommitment,
    proof: R1CSProof,
) -> Result<(), VerifierError> {
    // Verify the statement with a fresh transcript
    let mut verifier_transcript = Transcript::new(TRANSCRIPT_SEED.as_bytes());
    let pc_gens = PedersenGens::default();
    let verifier = Verifier::new(&pc_gens, &mut verifier_transcript);

    C::verify(witness_commitment, statement, proof, verifier)
}

/// Abstracts over the flow of verifying a proof for a collaboratively proved circuit
pub fn verify_collaborative_proof<'a, N, S, C>(
    statement: C::Statement,
    witness_commitment: <C::WitnessCommitment as Open<N, S>>::OpenOutput,
    proof: R1CSProof,
) -> Result<(), VerifierError>
where
    C: MultiProverCircuit<'a, N, S>,
    N: MpcNetwork + Send,
    S: SharedValueSource<Scalar>,
{
    // Verify the statement with a fresh transcript
    let mut verifier_transcript = Transcript::new(TRANSCRIPT_SEED.as_bytes());
    let pc_gens = PedersenGens::default();
    let verifier = Verifier::new(&pc_gens, &mut verifier_transcript);

    C::verify(witness_commitment, statement, proof, verifier)
}

// ---------
// | Types |
// ---------

/// A linkable commitment is a commitment used in multiple proofs. We split the constraints
/// of the matching engine into roughly 3 pieces:
///     1. Input validity checks, done offline by managing relayers (`VALID COMMITMENTS`)
///     2. The matching engine execution, proved collaboratively over an MPC fabric (`VALID MATCH MPC`)
///     3. Output validity checks: i.e. note construction and encryption (`VALID MATCH ENCRYPTION`)
/// These components are split to remove as many constraints from the bottleneck (the collaborative proof)
/// as possible.
///
/// However, we need to ensure that -- for example -- the order used in the proof of `VALID COMMITMENTS`
/// is the same order as the order used in `VALID MATCH MPC`. This can be done by constructing the Pedersen
/// commitments to the orders using the same randomness across proofs. That way, the verified may use the
/// shared Pedersen commitment as an implicit constraint that witness values are equal across proofs.
///
/// The `LinkableCommitment` type allows this from the prover side by storing the randomness used in the
/// original commitment along with the value itself.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LinkableCommitment {
    /// The underlying value committed to
    pub val: Scalar,
    /// The randomness used to blind the commitment
    randomness: Scalar,
}

impl LinkableCommitment {
    /// Create a new linkable commitment from a given value
    pub fn new(val: Scalar) -> Self {
        // Choose a random blinder
        let mut rng = OsRng {};
        let randomness = Scalar::random(&mut rng);
        Self { val, randomness }
    }

    /// Get the Pedersen commitment to this value
    pub fn compute_commitment(&self) -> CompressedRistretto {
        let pedersen_generators = PedersenGens::default();
        pedersen_generators
            .commit(self.val, self.randomness)
            .compress()
    }
}

impl From<Scalar> for LinkableCommitment {
    fn from(val: Scalar) -> Self {
        LinkableCommitment::new(val)
    }
}

impl From<LinkableCommitment> for Scalar {
    fn from(comm: LinkableCommitment) -> Self {
        comm.val
    }
}

/// A linkable commitment that has been allocated inside of an MPC fabric
#[derive(Debug)]
pub struct AuthenticatedLinkableCommitment<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The underlying shared scalar
    val: AuthenticatedScalar<N, S>,
    /// The randomness used to blind the commitment
    randomness: Scalar,
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Clone
    for AuthenticatedLinkableCommitment<N, S>
{
    fn clone(&self) -> Self {
        Self {
            val: self.val.clone(),
            randomness: self.randomness,
        }
    }
}

/// Flattening operation for serialization to share over an MPC fabric

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> AuthenticatedLinkableCommitment<N, S> {
    /// Create a linkable commitment from a shared scalar by sampling a shared
    /// blinder
    pub fn new(val: AuthenticatedScalar<N, S>) -> Self {
        let mut rng = OsRng {};
        let randomness = Scalar::random(&mut rng);
        Self { val, randomness }
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> CommitSharedProver<N, S>
    for AuthenticatedLinkableCommitment<N, S>
{
    type SharedVarType = MpcVariable<N, S>;
    type CommitType = AuthenticatedCompressedRistretto<N, S>;
    type ErrorType = MpcError;

    fn commit<R: RngCore + CryptoRng>(
        &self,
        _owning_party: u64,
        _rng: &mut R,
        prover: &mut MpcProver<N, S>,
    ) -> Result<(Self::SharedVarType, Self::CommitType), Self::ErrorType> {
        let (comm, var) = prover
            .commit_preshared(&self.val, self.randomness)
            .map_err(|err| MpcError::SharingError(err.to_string()))?;

        Ok((var, comm))
    }
}

// ----------
// | Traits |
// ----------

/// Defines functionality to allocate a witness value within a single-prover constraint system
pub trait CommitWitness {
    /// The type that results from committing to the base type
    type VarType;
    /// The type that consists of Pedersen commitments to the base type
    type CommitType;
    /// The error thrown by the commit method
    type ErrorType;

    /// Commit to the base type in the constraint system
    ///
    /// Returns a tuple holding both the var type (used for operations)
    /// within the constraint system, and the commit type; which is passed
    /// to the verifier to use as hidden values
    fn commit_witness<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType>;
}

/// Defines functionality to allocate a public variable within a single-prover constraint system
pub trait CommitPublic {
    /// The type that results from committing to the base type
    type VarType;
    /// The error thrown by the commit method
    type ErrorType;

    /// Commit to the base type in the constraint system
    fn commit_public<CS: RandomizableConstraintSystem>(
        &self,
        cs: &mut CS,
    ) -> Result<Self::VarType, Self::ErrorType>;
}

/// Defines functionality to commit to a value in a verifier's constraint system
pub trait CommitVerifier {
    /// The type that results from committing to the implementation types
    type VarType;
    /// The type of error thrown when committing fails
    type ErrorType;

    /// Commit to a hidden value in the Verifier
    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType>;
}

/// Defines functionality to allocate a value within an MPC network
pub trait Allocate<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The output type that results from allocating the value in the network
    type SharedType;
    /// The type of error thrown when allocation fails
    type ErrorType;

    /// Allocates the raw type in the network as a shared value
    fn allocate(
        &self,
        owning_party: u64,
        fabric: SharedFabric<N, S>,
    ) -> Result<Self::SharedType, Self::ErrorType>;
}

/// Defines functionality to allocate a value as a public, shared value in an MPC network
pub trait SharePublic<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>: Sized {
    /// The type of error thrown when sharing fails
    type ErrorType;

    /// Share the value with the counterparty
    fn share_public(
        &self,
        owning_party: u64,
        fabric: SharedFabric<N, S>,
    ) -> Result<Self, Self::ErrorType>;
}

/// Defines functionality to allocate a base type as a shared commitment in a multi-prover
/// constraint system
pub trait CommitSharedProver<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The type that results from committing to the base type
    type SharedVarType;
    /// The type consisting of Pedersen commitments to the base type
    type CommitType;
    /// The type of error that is thrown when committing fails
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
pub trait Open<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The output type that results from opening this value
    type OpenOutput;
    /// The error type that results if opening fails
    type Error;
    /// Opens the shared type without authenticating
    fn open(self, fabric: SharedFabric<N, S>) -> Result<Self::OpenOutput, Self::Error>;
    /// Opens the shared type and authenticates the result
    fn open_and_authenticate(
        self,
        fabric: SharedFabric<N, S>,
    ) -> Result<Self::OpenOutput, Self::Error>;
}

#[allow(clippy::needless_borrow)]
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Open<N, S>
    for AuthenticatedCompressedRistretto<N, S>
{
    type OpenOutput = CompressedRistretto;
    type Error = MpcError;

    fn open(self, _: SharedFabric<N, S>) -> Result<Self::OpenOutput, Self::Error> {
        Ok((&self)
            .open()
            .map_err(|err| MpcError::OpeningError(err.to_string()))?
            .value())
    }

    fn open_and_authenticate(self, _: SharedFabric<N, S>) -> Result<Self::OpenOutput, Self::Error> {
        Ok((&self)
            .open_and_authenticate()
            .map_err(|err| MpcError::OpeningError(err.to_string()))?
            .value())
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Open<N, S>
    for Vec<AuthenticatedCompressedRistretto<N, S>>
{
    type OpenOutput = Vec<CompressedRistretto>;
    type Error = MpcError;

    fn open(self, _: SharedFabric<N, S>) -> Result<Self::OpenOutput, Self::Error> {
        Ok(AuthenticatedCompressedRistretto::batch_open(&self)
            .map_err(|err| MpcError::OpeningError(err.to_string()))?
            .iter()
            .map(|comm| comm.value())
            .collect_vec())
    }

    fn open_and_authenticate(self, _: SharedFabric<N, S>) -> Result<Self::OpenOutput, Self::Error> {
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
    /// The data type of the output commitment from the prover.
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
    /// The data type of the output commitment from the prover.
    ///
    /// The prover commits to the witness and sends this commitment to the verifier, this type
    /// is the structure in which that commitment is sent
    type WitnessCommitment: Open<N, S>;

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
        witness_commitments: <Self::WitnessCommitment as Open<N, S>>::OpenOutput,
        statement: Self::Statement,
        proof: R1CSProof,
        verifier: Verifier,
    ) -> Result<(), VerifierError>;
}

// -----------------------
// | Default Trait Impls |
// -----------------------

impl CommitWitness for Scalar {
    type VarType = Variable;
    type CommitType = CompressedRistretto;
    type ErrorType = (); // Does not error

    fn commit_witness<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (comm, var) = prover.commit(*self, Scalar::random(rng));
        Ok((var, comm))
    }
}

impl CommitPublic for Scalar {
    type VarType = Variable;
    type ErrorType = (); // Does not error

    fn commit_public<CS: RandomizableConstraintSystem>(
        &self,
        cs: &mut CS,
    ) -> Result<Self::VarType, Self::ErrorType> {
        Ok(cs.commit_public(*self))
    }
}

impl CommitWitness for LinkableCommitment {
    type VarType = Variable;
    type CommitType = CompressedRistretto;
    type ErrorType = ();

    fn commit_witness<R: RngCore + CryptoRng>(
        &self,
        _rng: &mut R, // rng is unused, use the randomness in `self`
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (comm, var) = prover.commit(self.val, self.randomness);
        Ok((var, comm))
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> SharePublic<N, S> for LinkableCommitment {
    type ErrorType = MpcError;

    fn share_public(
        &self,
        owning_party: u64,
        fabric: SharedFabric<N, S>,
    ) -> Result<Self, Self::ErrorType> {
        let shared_values = fabric
            .borrow_fabric()
            .batch_shared_plaintext_scalars(owning_party, &[self.val, self.randomness])
            .map_err(|err| MpcError::SharingError(err.to_string()))?;

        Ok(Self {
            val: shared_values[0],
            randomness: shared_values[1],
        })
    }
}

// ----------------
// | Test Helpers |
// ----------------

#[cfg(test)]
pub(crate) mod test_helpers {
    use crypto::fields::{prime_field_to_bigint, scalar_to_bigint, DalekRistrettoField};
    use curve25519_dalek::scalar::Scalar;
    use env_logger::{Builder, Env, Target};
    use merlin::Transcript;
    use mpc_bulletproof::{
        r1cs::{Prover, Verifier},
        PedersenGens,
    };

    use crate::{errors::VerifierError, SingleProverCircuit};

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

        builder.init();
    }

    // -----------
    // | Helpers |
    // -----------

    /// Compares a Dalek Scalar to an Arkworks field element
    pub(crate) fn compare_scalar_to_felt(scalar: &Scalar, felt: &DalekRistrettoField) -> bool {
        scalar_to_bigint(scalar).eq(&prime_field_to_bigint(felt))
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

/// Groups helpers that operate on native types; which correspond to circuitry
/// defined in this library
///
/// For example; when computing witnesses, wallet commitments, note commitments,
/// nullifiers, etc are all useful helpers
pub mod native_helpers {
    use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
    use crypto::{
        fields::{
            biguint_to_prime_field, prime_field_to_scalar, scalar_to_prime_field,
            DalekRistrettoField,
        },
        hash::default_poseidon_params,
    };
    use curve25519_dalek::scalar::Scalar;
    use itertools::Itertools;

    use crate::types::{keychain::PublicIdentificationKey, note::Note, wallet::Wallet};

    /// Compute the hash of the randomness of a given wallet
    pub fn compute_poseidon_hash(values: &[Scalar]) -> Scalar {
        let mut hasher = PoseidonSponge::new(&default_poseidon_params());
        hasher.absorb(&values.iter().map(scalar_to_prime_field).collect_vec());

        let out: DalekRistrettoField = hasher.squeeze_field_elements(1 /* num_elements */)[0];
        prime_field_to_scalar(&out)
    }

    /// Compute the commitment to a wallet
    pub fn compute_wallet_commitment<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
        const MAX_FEES: usize,
    >(
        wallet: &Wallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    ) -> DalekRistrettoField
    where
        [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
    {
        let mut hasher = PoseidonSponge::new(&default_poseidon_params());

        // Hash the balances into the state
        for balance in wallet.balances.iter() {
            hasher.absorb(&biguint_to_prime_field(&balance.mint));
            hasher.absorb(&balance.amount);
        }

        // Hash the orders into the state
        for order in wallet.orders.iter() {
            hasher.absorb(&vec![
                biguint_to_prime_field(&order.quote_mint),
                biguint_to_prime_field(&order.base_mint),
            ]);
            hasher.absorb(&vec![
                order.side as u64,
                order.price.to_owned().into(),
                order.amount,
            ]);
        }

        // Hash the fees into the state
        for fee in wallet.fees.iter() {
            hasher.absorb(&vec![
                biguint_to_prime_field(&fee.settle_key),
                biguint_to_prime_field(&fee.gas_addr),
            ]);

            hasher.absorb(&vec![fee.gas_token_amount, fee.percentage_fee.into()]);
        }

        // Hash the keys into the state
        let mut key_scalars = Vec::<Scalar>::from(wallet.keys.pk_root.clone());
        key_scalars.push(wallet.keys.pk_match.into());
        key_scalars.push(wallet.keys.pk_settle.into());
        key_scalars.push(wallet.keys.pk_view.into());

        hasher.absorb(&key_scalars.iter().map(scalar_to_prime_field).collect_vec());

        // Hash the randomness into the state
        hasher.absorb(&scalar_to_prime_field(&wallet.randomness));

        hasher.squeeze_field_elements(1 /* num_elements */)[0]
    }

    /// Compute the commitment to a note
    pub fn compute_note_commitment(
        note: &Note,
        pk_settle_receiver: PublicIdentificationKey,
    ) -> DalekRistrettoField {
        // Absorb the elements of the note in order into the sponge
        let mut hasher = PoseidonSponge::new(&default_poseidon_params());
        hasher.absorb(&biguint_to_prime_field(&note.mint1));
        hasher.absorb(&vec![note.volume1, note.direction1 as u64]);
        hasher.absorb(&biguint_to_prime_field(&note.mint2));
        hasher.absorb(&vec![note.volume2, note.direction2 as u64]);
        hasher.absorb(&biguint_to_prime_field(&note.fee_mint));
        hasher.absorb(&vec![
            note.fee_volume,
            note.fee_direction as u64,
            note.type_ as u64,
        ]);
        hasher.absorb(&biguint_to_prime_field(&note.randomness));
        hasher.absorb(&scalar_to_prime_field(&pk_settle_receiver.into()));
        hasher.squeeze_field_elements(1 /* num_elements */)[0]
    }

    /// Given a wallet and its commitment, compute the wallet spend nullifier
    pub fn compute_wallet_spend_nullifier<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
        const MAX_FEES: usize,
    >(
        wallet: &Wallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        commitment: DalekRistrettoField,
    ) -> DalekRistrettoField
    where
        [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
    {
        let mut hasher = PoseidonSponge::new(&default_poseidon_params());
        hasher.absorb(&vec![commitment, scalar_to_prime_field(&wallet.randomness)]);
        hasher.squeeze_field_elements(1 /* num_elements */)[0]
    }

    /// Given a wallet and its commitment, compute the wallet match nullifier
    pub fn compute_wallet_match_nullifier<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
        const MAX_FEES: usize,
    >(
        wallet: &Wallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        commitment: DalekRistrettoField,
    ) -> DalekRistrettoField
    where
        [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
    {
        let mut hasher = PoseidonSponge::new(&default_poseidon_params());
        hasher.absorb(&vec![
            commitment,
            scalar_to_prime_field(&(wallet.randomness + Scalar::one())),
        ]);
        hasher.squeeze_field_elements(1 /* num_elements */)[0]
    }

    /// Given a note and its commitment, compute the note redeem nullifier
    pub fn compute_note_redeem_nullifier(
        note_commitment: DalekRistrettoField,
        pk_settle_receiver: PublicIdentificationKey,
    ) -> DalekRistrettoField {
        let mut hasher = PoseidonSponge::new(&default_poseidon_params());
        hasher.absorb(&vec![
            note_commitment,
            scalar_to_prime_field(&pk_settle_receiver.into()),
        ]);
        hasher.squeeze_field_elements(1 /* num_elements */)[0]
    }
}

#[cfg(test)]
mod circuits_test {
    use crypto::fields::bigint_to_scalar;
    use num_bigint::BigInt;
    use rand::{thread_rng, Rng};

    use crate::scalar_2_to_m;

    #[test]
    fn test_scalar_2_to_m() {
        let rand_m: usize = thread_rng().gen_range(0..256);
        let res = scalar_2_to_m(rand_m);

        let expected = bigint_to_scalar(&(BigInt::from(1u64) << rand_m));
        assert_eq!(res, expected);
    }
}
