//! Defines traits which groups types of types and translations between them
//!
//! We strongly type inputs to our ZK(MPC) circuits to gain circuit readability
//! and inherit safety properties from the type checker and linters (i.e. unused
//! witness elements)
//!
//! We group types of types by traits which associate with other types. For example, types
//! allocated in an MPC circuit implement different traits than ZK circuit types do, due to
//! their different underlying primitives
//!
//! At a high level the types are:
//!     - Base types: application level types that have semantically meaningful values
//!     - Single-prover variable types: base types allocated in a single-prover constraint system
//!     - Single-prover commitment types: commitments to base types in a single-prover system
//!     - MPC types: base types that have been allocated in an MPC fabric
//!     - Multi-prover variable types: base types allocated in a multi-prover constraint system
//!     - Multi-prover commitment types: commitments to base types in a multi-prover system

use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use itertools::Itertools;
use mpc_bulletproof::{
    r1cs::{Prover, R1CSProof, RandomizableConstraintSystem, Variable, Verifier},
    r1cs_mpc::{MpcProver, SharedR1CSProof},
};
use mpc_ristretto::{
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource, network::MpcNetwork,
};
use rand_core::{CryptoRng, RngCore};

use crate::{
    errors::{MpcError, ProverError, VerifierError},
    mpc::SharedFabric,
    LinkableCommitment,
};

// ---------------
// | Type Traits |
// ---------------

/// Implementing types are base (application level) types that define serialization to/from `Scalars`
///
/// Commitment, variable, MPC, etc types are implemented automatically from serialization and deserialization
pub trait BaseType: Clone {
    /// Convert the base type to its serialized scalar representation in the circuit
    fn to_scalars(self) -> Vec<Scalar>;
    /// Convert from a serialized scalar representation to the base type
    fn from_scalars<I: Iterator<Item = Scalar>>(i: &mut I) -> Self;
}

// --- Singleprover Circuit Traits --- //

/// The base type that may be allocated in a single-prover circuit
pub trait CircuitBaseType: BaseType {
    /// The variable type for this base type
    type VarType: CircuitVarType;
    /// The commitment type for this base type
    type CommitmentType: CircuitCommitmentType;
}

/// Implementing types are variable types that may appear in constraints in
/// a constraint system
pub trait CircuitVarType {
    /// Convert from an iterable of variables representing the serialized type
    fn from_vars<I: Iterator<Item = Variable>>(i: &mut I) -> Self;
}

/// Implementing types are commitments to base types that have an analogous variable
/// type allocated with them
pub trait CircuitCommitmentType: Clone {
    /// The variable type that this type is a commitment to
    type VarType: CircuitVarType;
    /// Convert from an iterable of compressed ristretto points, each representing
    /// a commitment to an underlying variable
    fn from_commitments<I: Iterator<Item = CompressedRistretto>>(i: &mut I) -> Self;
    /// Convert to a vector of compressed ristretto points
    fn to_commitments(self) -> Vec<CompressedRistretto>;
}

// --- MPC Circuit Traits --- //

/// A base type for allocating into an MPC network
pub trait MpcBaseType<N: MpcNetwork + Send + Clone, S: SharedValueSource<Scalar> + Clone>:
    BaseType
{
    /// The type that results from allocating the base type into an MPC network
    type AllocatedType: MpcType<N, S>;
}

/// An implementing type is the representation of a `BaseType` in an MPC circuit
/// *outside* of a multiprover constraint system
pub trait MpcType<N: MpcNetwork + Send + Clone, S: SharedValueSource<Scalar> + Clone>:
    Clone
{
    /// The native type when the value is opened out of a circuit
    type NativeType: BaseType;
    /// Convert from an iterable of authenticated scalars: scalars that have been
    /// allocated in an MPC fabric
    fn from_authenticated_scalars<I: Iterator<Item = AuthenticatedScalar<N, S>>>(i: &mut I)
        -> Self;
    /// Convert to a vector of authenticated scalars
    fn to_authenticated_scalars(self) -> Vec<AuthenticatedScalar<N, S>>;
}

// --- Multiprover Circuit Traits --- //

/// A base type for allocating within a multiprover constraint system
pub trait MultiproverCircuitBaseType<
    N: MpcNetwork + Send + Clone,
    S: SharedValueSource<Scalar> + Clone,
>: BaseType
{
    /// The multiprover constraint system variable type that results when committing
    /// to the base type in a multiprover constraint system
    type MultiproverVarType;
    /// The shared commitment type that results when committing to the base type in a multiprover
    /// constraint system
    type MultiproverCommType;
}

/// A multiprover circuit variable type
pub trait MultiproverCircuitVariableType<
    N: MpcNetwork + Send + Clone,
    S: SharedValueSource<Scalar> + Clone,
>
{
    /// The base type that generates this variable type when allocated in a multiprover constraint system
    type BaseType: MultiproverCircuitBaseType<N, S>;
}

/// A multiprover circuit commitment type
pub trait MultiproverCircuitCommitmentType<
    N: MpcNetwork + Send + Clone,
    S: SharedValueSource<Scalar> + Clone,
>
{
    /// The multi-prover variable type that this type is a commitment to
    type VariableType: MultiproverCircuitVariableType<N, S>;
}

// -----------------------------
// | Type Traits Default Impls |
// -----------------------------

impl BaseType for Scalar {
    fn to_scalars(self) -> Vec<Scalar> {
        vec![self]
    }

    fn from_scalars<I: Iterator<Item = Scalar>>(i: &mut I) -> Self {
        i.next().unwrap()
    }
}

impl CircuitBaseType for Scalar {
    type VarType = Variable;
    type CommitmentType = CompressedRistretto;
}

impl CircuitVarType for Variable {
    fn from_vars<I: Iterator<Item = Variable>>(i: &mut I) -> Self {
        i.next().unwrap()
    }
}

impl CircuitCommitmentType for CompressedRistretto {
    type VarType = Variable;

    fn from_commitments<I: Iterator<Item = CompressedRistretto>>(i: &mut I) -> Self {
        i.next().unwrap()
    }

    fn to_commitments(self) -> Vec<CompressedRistretto> {
        vec![self]
    }
}

impl<N: MpcNetwork + Send + Clone, S: SharedValueSource<Scalar> + Clone> MpcBaseType<N, S>
    for Scalar
{
    type AllocatedType = AuthenticatedScalar<N, S>;
}

impl<N: MpcNetwork + Send + Clone, S: SharedValueSource<Scalar> + Clone> MpcType<N, S>
    for AuthenticatedScalar<N, S>
{
    type NativeType = Scalar;

    fn from_authenticated_scalars<I: Iterator<Item = AuthenticatedScalar<N, S>>>(
        i: &mut I,
    ) -> Self {
        i.next().unwrap()
    }

    fn to_authenticated_scalars(self) -> Vec<AuthenticatedScalar<N, S>> {
        vec![self]
    }
}

// ------------------
// | Circuit Traits |
// ------------------

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

// -------------------------------
// | Circuit Trait Default Impls |
// -------------------------------

impl<T: CircuitBaseType> CommitWitness for T {
    type VarType = <Self as CircuitBaseType>::VarType;
    type CommitType = <Self as CircuitBaseType>::CommitmentType;
    type ErrorType = (); // Single prover does not error

    fn commit_witness<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let scalars: Vec<Scalar> = self.clone().to_scalars();
        let (comms, vars): (Vec<CompressedRistretto>, Vec<Variable>) = scalars
            .into_iter()
            .map(|s| prover.commit(s, Scalar::random(rng)))
            .unzip();

        Ok((
            Self::VarType::from_vars(&mut vars.into_iter()),
            Self::CommitType::from_commitments(&mut comms.into_iter()),
        ))
    }
}

impl<T: CircuitBaseType> CommitPublic for T {
    type VarType = <Self as CircuitBaseType>::VarType;
    type ErrorType = (); // Does not error in single-prover context

    fn commit_public<CS: RandomizableConstraintSystem>(
        &self,
        cs: &mut CS,
    ) -> Result<Self::VarType, Self::ErrorType> {
        let self_scalars = self.clone().to_scalars();
        let vars = self_scalars
            .into_iter()
            .map(|s| cs.commit_public(s))
            .collect_vec();

        Ok(Self::VarType::from_vars(&mut vars.into_iter()))
    }
}

impl<T: CircuitCommitmentType> CommitVerifier for T {
    type VarType = T::VarType;
    type ErrorType = (); // Does not error

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let comms = self.clone().to_commitments();
        let vars = comms.into_iter().map(|c| verifier.commit(c)).collect_vec();

        Ok(Self::VarType::from_vars(&mut vars.into_iter()))
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
            .batch_share_plaintext_scalars(owning_party, &[self.val, self.randomness])
            .map_err(|err| MpcError::SharingError(err.to_string()))?;

        Ok(Self {
            val: shared_values[0],
            randomness: shared_values[1],
        })
    }
}

impl<N: MpcNetwork + Send + Clone, S: SharedValueSource<Scalar> + Clone, T: MpcBaseType<N, S>>
    Allocate<N, S> for T
{
    type SharedType = T::AllocatedType;
    type ErrorType = MpcError;

    fn allocate(
        &self,
        owning_party: u64,
        fabric: SharedFabric<N, S>,
    ) -> Result<Self::SharedType, Self::ErrorType> {
        // Convert to scalars and share
        let self_scalars = self.clone().to_scalars();
        let shared_scalars = fabric
            .borrow_fabric()
            .batch_allocate_private_scalars(owning_party, &self_scalars)
            .map_err(|err| MpcError::SharingError(err.to_string()))?;

        Ok(Self::SharedType::from_authenticated_scalars(
            &mut shared_scalars.into_iter(),
        ))
    }
}

impl<N: MpcNetwork + Send + Clone, S: SharedValueSource<Scalar> + Clone, T: MpcType<N, S>>
    Open<N, S> for T
{
    type OpenOutput = T::NativeType;
    type Error = MpcError;

    fn open(self, _: SharedFabric<N, S>) -> Result<Self::OpenOutput, Self::Error> {
        let self_authenticated_scalars = self.to_authenticated_scalars();
        let opened_scalars = AuthenticatedScalar::batch_open(&self_authenticated_scalars)
            .map_err(|err| MpcError::OpeningError(err.to_string()))?
            .into_iter()
            .map(|auth_scalar| auth_scalar.to_scalar())
            .collect_vec();

        Ok(T::NativeType::from_scalars(&mut opened_scalars.into_iter()))
    }

    fn open_and_authenticate(self, _: SharedFabric<N, S>) -> Result<Self::OpenOutput, Self::Error> {
        let self_authenticated_scalars = self.to_authenticated_scalars();
        let opened_scalars =
            AuthenticatedScalar::batch_open_and_authenticate(&self_authenticated_scalars)
                .map_err(|err| MpcError::OpeningError(err.to_string()))?
                .into_iter()
                .map(|auth_scalar| auth_scalar.to_scalar())
                .collect_vec();

        Ok(T::NativeType::from_scalars(&mut opened_scalars.into_iter()))
    }
}
