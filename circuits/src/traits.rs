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
    r1cs_mpc::{MpcProver, MpcVariable, SharedR1CSProof},
};
use mpc_ristretto::{
    authenticated_ristretto::AuthenticatedCompressedRistretto,
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

    /// Commit to the base type as a witness variable
    fn commit_witness<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> (Self::VarType, Self::CommitmentType) {
        let scalars: Vec<Scalar> = self.clone().to_scalars();
        let randomness = self.commitment_randomness(rng);
        let (comms, vars): (Vec<CompressedRistretto>, Vec<Variable>) = scalars
            .into_iter()
            .zip(randomness.into_iter())
            .map(|(s, r)| prover.commit(s, r))
            .unzip();

        (
            Self::VarType::from_vars(&mut vars.into_iter()),
            Self::CommitmentType::from_commitments(&mut comms.into_iter()),
        )
    }

    /// Commit to the base type as a public variable
    fn commit_public<CS: RandomizableConstraintSystem>(&self, cs: &mut CS) -> Self::VarType {
        let scalars: Vec<Scalar> = self.clone().to_scalars();
        let vars = scalars
            .into_iter()
            .map(|s| cs.commit_public(s))
            .collect_vec();

        Self::VarType::from_vars(&mut vars.into_iter())
    }

    /// Get the randomness used to commit to this value
    ///
    /// We make this method generically defined so that linkable types may store and
    /// re-use their commitment randomness between proofs
    fn commitment_randomness<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Vec<Scalar>;
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

    /// Commit to a hidden value in the Verifier
    fn commit_verifier(&self, verifier: &mut Verifier) -> Self::VarType {
        let vars = self
            .clone()
            .to_commitments()
            .into_iter()
            .map(|c| verifier.commit(c))
            .collect_vec();

        Self::VarType::from_vars(&mut vars.into_iter())
    }
}

// --- MPC Circuit Traits --- //

/// A base type for allocating into an MPC network
pub trait MpcBaseType<N: MpcNetwork + Send + Clone, S: SharedValueSource<Scalar> + Clone>:
    BaseType
{
    /// The type that results from allocating the base type into an MPC network
    type AllocatedType: MpcType<N, S>;

    /// Allocates the base type in the network as a shared value
    fn allocate(
        &self,
        owning_party: u64,
        fabric: SharedFabric<N, S>,
    ) -> Result<Self::AllocatedType, MpcError> {
        let self_scalars = self.clone().to_scalars();
        let values = fabric
            .borrow_fabric()
            .batch_allocate_private_scalars(owning_party, &self_scalars)
            .map_err(|err| MpcError::SetupError(err.to_string()))?;

        Ok(Self::AllocatedType::from_authenticated_scalars(
            &mut values.into_iter(),
        ))
    }

    /// Share the plaintext value with the counterparty
    fn share_public(
        &self,
        owning_party: u64,
        fabric: SharedFabric<N, S>,
    ) -> Result<Self, MpcError> {
        let self_scalars = self.clone().to_scalars();
        let res_scalars = fabric
            .borrow_fabric()
            .batch_share_plaintext_scalars(owning_party, &self_scalars)
            .map_err(|err| MpcError::SharingError(err.to_string()))?;

        Ok(Self::from_scalars(&mut res_scalars.into_iter()))
    }
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

    /// Opens the shared type without authenticating
    fn open(self, _: SharedFabric<N, S>) -> Result<Self::NativeType, MpcError> {
        let self_scalars = self.to_authenticated_scalars();
        let opened_scalars = AuthenticatedScalar::batch_open(&self_scalars)
            .map_err(|err| MpcError::OpeningError(err.to_string()))?
            .into_iter()
            .map(|x| x.to_scalar())
            .collect_vec();

        Ok(Self::NativeType::from_scalars(
            &mut opened_scalars.into_iter(),
        ))
    }

    /// Opens the shared type and authenticates the result
    fn open_and_authenticate(self, _: SharedFabric<N, S>) -> Result<Self::NativeType, MpcError> {
        let self_scalars = self.to_authenticated_scalars();
        let opened_scalars = AuthenticatedScalar::batch_open_and_authenticate(&self_scalars)
            .map_err(|err| MpcError::OpeningError(err.to_string()))?
            .into_iter()
            .map(|x| x.to_scalar())
            .collect_vec();

        Ok(Self::NativeType::from_scalars(
            &mut opened_scalars.into_iter(),
        ))
    }
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
    type MultiproverVarType: MultiproverCircuitVariableType<N, S>;
    /// The shared commitment type that results when committing to the base type in a multiprover
    /// constraint system
    type MultiproverCommType: MultiproverCircuitCommitmentType<N, S>;

    /// Commit to the value in a multiprover constraint system
    fn commit_shared<R: RngCore + CryptoRng>(
        &self,
        owning_party: u64,
        rng: &mut R,
        prover: &mut MpcProver<N, S>,
    ) -> Result<(Self::MultiproverVarType, Self::MultiproverCommType), MpcError> {
        let self_scalars = self.clone().to_scalars();
        let randomness = (0..self_scalars.len())
            .map(|_| Scalar::random(rng))
            .collect_vec();

        let (comms, vars) = prover
            .batch_commit(owning_party, &self_scalars, &randomness)
            .map_err(|err| MpcError::SharingError(err.to_string()))?;

        Ok((
            Self::MultiproverVarType::from_mpc_vars(&mut vars.into_iter()),
            Self::MultiproverCommType::from_mpc_commitments(&mut comms.into_iter()),
        ))
    }
}

/// A multiprover circuit variable type
pub trait MultiproverCircuitVariableType<
    N: MpcNetwork + Send + Clone,
    S: SharedValueSource<Scalar> + Clone,
>
{
    /// Deserialization from an iterator over MPC allocated variables
    fn from_mpc_vars<I: Iterator<Item = MpcVariable<N, S>>>(i: &mut I) -> Self;
}

/// A multiprover circuit commitment type
pub trait MultiproverCircuitCommitmentType<
    N: MpcNetwork + Send + Clone,
    S: SharedValueSource<Scalar> + Clone,
>: Clone
{
    /// The base commitment type that this commitment opens to
    type BaseCommitType: CircuitCommitmentType;
    /// Deserialization form an iterator over MPC allocated commitments
    fn from_mpc_commitments<I: Iterator<Item = AuthenticatedCompressedRistretto<N, S>>>(
        i: &mut I,
    ) -> Self;
    /// Serialization to a vector of MPC allocated commitments
    fn to_mpc_commitments(self) -> Vec<AuthenticatedCompressedRistretto<N, S>>;

    /// Opens the shared type without authenticating
    fn open(self, _: SharedFabric<N, S>) -> Result<Self::BaseCommitType, MpcError> {
        let self_comms = self.to_mpc_commitments();
        let opened_commitments = AuthenticatedCompressedRistretto::batch_open(&self_comms)
            .map_err(|err| MpcError::OpeningError(err.to_string()))?
            .into_iter()
            .map(|x| x.value())
            .collect_vec();

        Ok(Self::BaseCommitType::from_commitments(
            &mut opened_commitments.into_iter(),
        ))
    }

    /// Opens the shared type and authenticates the result
    fn open_and_authenticate(
        self,
        _: SharedFabric<N, S>,
    ) -> Result<Self::BaseCommitType, MpcError> {
        let self_comms = self.to_mpc_commitments();
        let opened_commitments =
            AuthenticatedCompressedRistretto::batch_open_and_authenticate(&self_comms)
                .map_err(|err| MpcError::OpeningError(err.to_string()))?
                .into_iter()
                .map(|x| x.value())
                .collect_vec();

        Ok(Self::BaseCommitType::from_commitments(
            &mut opened_commitments.into_iter(),
        ))
    }
}

// --- Proof Linkable Types --- //

/// Implementing types have an analogous linkable type that may be shared between proofs
pub trait LinkableBaseType: BaseType {
    /// The linkable type that re-uses commitment randomness between commitments
    type Linkable: LinkableType;
}

/// Implementing types are proof-linkable analogs of a base type, which hold onto their commitment
/// randomness and re-use it between proofs
pub trait LinkableType: Clone {
    /// The base type this type is a linkable commitment for
    type BaseType: LinkableBaseType;
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

    fn commitment_randomness<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Vec<Scalar> {
        vec![Scalar::random(rng)]
    }
}

impl BaseType for LinkableCommitment {
    fn to_scalars(self) -> Vec<Scalar> {
        vec![self.val]
    }

    fn from_scalars<I: Iterator<Item = Scalar>>(i: &mut I) -> Self {
        // Choose a random commitment
        i.next().unwrap().into()
    }
}

impl CircuitBaseType for LinkableCommitment {
    type VarType = Variable;
    type CommitmentType = CompressedRistretto;

    fn commitment_randomness<R: RngCore + CryptoRng>(&self, _rng: &mut R) -> Vec<Scalar> {
        vec![self.randomness]
    }
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

impl<N: MpcNetwork + Send + Clone, S: SharedValueSource<Scalar> + Clone>
    MultiproverCircuitBaseType<N, S> for Scalar
{
    type MultiproverVarType = MpcVariable<N, S>;
    type MultiproverCommType = AuthenticatedCompressedRistretto<N, S>;
}

impl<N: MpcNetwork + Send + Clone, S: SharedValueSource<Scalar> + Clone>
    MultiproverCircuitBaseType<N, S> for LinkableCommitment
{
    type MultiproverVarType = MpcVariable<N, S>;
    type MultiproverCommType = AuthenticatedCompressedRistretto<N, S>;

    fn commit_shared<R: RngCore + CryptoRng>(
        &self,
        owning_party: u64,
        _rng: &mut R,
        prover: &mut MpcProver<N, S>,
    ) -> Result<(Self::MultiproverVarType, Self::MultiproverCommType), MpcError> {
        let (comm, var) = prover
            .commit(owning_party, self.val, self.randomness)
            .map_err(|err| MpcError::SharingError(err.to_string()))?;
        Ok((var, comm))
    }
}

impl<N: MpcNetwork + Send + Clone, S: SharedValueSource<Scalar> + Clone>
    MultiproverCircuitVariableType<N, S> for MpcVariable<N, S>
{
    fn from_mpc_vars<I: Iterator<Item = MpcVariable<N, S>>>(i: &mut I) -> Self {
        i.next().unwrap()
    }
}

impl<N: MpcNetwork + Send + Clone, S: SharedValueSource<Scalar> + Clone>
    MultiproverCircuitCommitmentType<N, S> for AuthenticatedCompressedRistretto<N, S>
{
    type BaseCommitType = CompressedRistretto;
    fn from_mpc_commitments<I: Iterator<Item = AuthenticatedCompressedRistretto<N, S>>>(
        i: &mut I,
    ) -> Self {
        i.next().unwrap()
    }

    fn to_mpc_commitments(self) -> Vec<AuthenticatedCompressedRistretto<N, S>> {
        vec![self]
    }
}

impl LinkableBaseType for Scalar {
    type Linkable = LinkableCommitment;
}

impl LinkableType for LinkableCommitment {
    type BaseType = Scalar;
}

// ------------------
// | Circuit Traits |
// ------------------

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
    type Witness: CircuitBaseType;
    /// The statement type, given to both the prover and verifier, parameterizes the underlying
    /// NP statement being proven
    type Statement: CircuitBaseType;
    /// The data type of the output commitment from the prover.
    ///
    /// The prover commits to the witness and sends this commitment to the verifier, this type
    /// is the structure in which that commitment is sent
    type WitnessCommitment: CircuitCommitmentType;

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
pub trait MultiProverCircuit<
    'a,
    N: 'a + MpcNetwork + Send + Clone,
    S: 'a + SharedValueSource<Scalar> + Clone,
>
{
    /// The witness type, given only to the prover, which generates a blinding commitment
    /// that can be given to the verifier
    type Witness: MultiproverCircuitBaseType<N, S>;
    /// The statement type, given to both the prover and verifier, parameterizes the underlying
    /// NP statement being proven
    type Statement: Clone + MultiproverCircuitBaseType<N, S>;
    /// The data type of the output commitment from the prover.
    ///
    /// The prover commits to the witness and sends this commitment to the verifier, this type
    /// is the structure in which that commitment is sent
    type WitnessCommitment: MultiproverCircuitCommitmentType<N, S>;

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
        witness_commitments: <Self::WitnessCommitment as MultiproverCircuitCommitmentType<N, S>>::BaseCommitType,
        statement: Self::Statement,
        proof: R1CSProof,
        verifier: Verifier,
    ) -> Result<(), VerifierError>;
}
