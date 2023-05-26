//! Defines traits which group derived types and translations between them
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

use crypto::fields::{biguint_to_scalar, scalar_to_biguint};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use itertools::Itertools;
use mpc_bulletproof::{
    r1cs::{
        LinearCombination, Prover, R1CSProof, RandomizableConstraintSystem, Variable, Verifier,
    },
    r1cs_mpc::{MpcLinearCombination, MpcProver, MpcVariable, SharedR1CSProof},
};
use mpc_ristretto::{
    authenticated_ristretto::AuthenticatedCompressedRistretto,
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource,
    mpc_scalar::scalar_to_u64, network::MpcNetwork,
};
use num_bigint::BigUint;
use rand_core::{CryptoRng, RngCore};

use crate::{
    errors::{MpcError, ProverError, VerifierError},
    mpc::SharedFabric,
    LinkableCommitment,
};

/// The error message emitted when too few scalars are given
const ERR_TOO_FEW_SCALARS: &str = "from_scalars: Invalid number of scalars";
/// The error message emitted when too few variables are given
const ERR_TOO_FEW_VARS: &str = "from_vars: Invalid number of variables";
/// The error message emitted when too few commitments are given
const ERR_TOO_FEW_COMMITMENTS: &str = "from_commitments: Invalid number of commitments";

// ---------------
// | Type Traits |
// ---------------

/// Implementing types are base (application level) types that define serialization to/from `Scalars`
///
/// Commitment, variable, MPC, etc types are implemented automatically from serialization and deserialization
pub trait BaseType: Clone + Default {
    /// Convert the base type to its serialized scalar representation in the circuit
    fn to_scalars(self) -> Vec<Scalar>;
    /// Convert from a serialized scalar representation to the base type
    fn from_scalars<I: Iterator<Item = Scalar>>(i: &mut I) -> Self;
}

// --- Singleprover Circuit Traits --- //

/// A marker trait used to generalize over the atomic `Variable`
/// and `LinearCombination` types
pub trait LinearCombinationLike:
    Into<LinearCombination> + Clone + CircuitVarType<Self> + From<Variable>
{
}
impl LinearCombinationLike for Variable {}
impl LinearCombinationLike for LinearCombination {}

/// The base type that may be allocated in a single-prover circuit
pub trait CircuitBaseType: BaseType {
    /// The variable type for this base type
    type VarType<L: LinearCombinationLike>: CircuitVarType<L>;
    /// The commitment type for this base type
    type CommitmentType: CircuitCommitmentType;

    /// Commit to the base type as a witness variable
    fn commit_witness<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> (Self::VarType<Variable>, Self::CommitmentType) {
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
    fn commit_public<CS: RandomizableConstraintSystem>(
        &self,
        cs: &mut CS,
    ) -> Self::VarType<Variable> {
        let scalars: Vec<Scalar> = self.clone().to_scalars();
        let mut vars = scalars.into_iter().map(|s| cs.commit_public(s));

        Self::VarType::from_vars(&mut vars)
    }

    /// Get the randomness used to commit to this value
    ///
    /// We make this method generically defined so that linkable types may store and
    /// re-use their commitment randomness between proofs
    fn commitment_randomness<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Vec<Scalar>;
}

/// Implementing types are variable types that may appear in constraints in
/// a constraint system
pub trait CircuitVarType<L: LinearCombinationLike>: Clone {
    /// Convert to an iterable of serialized variables for the type
    fn to_vars(self) -> Vec<L>;
    /// Convert from an iterable of variables representing the serialized type
    fn from_vars<I: Iterator<Item = L>>(i: &mut I) -> Self;
}

/// Implementing types are commitments to base types that have an analogous variable
/// type allocated with them
pub trait CircuitCommitmentType: Clone {
    /// The variable type that this type is a commitment to
    type VarType: CircuitVarType<Variable>;
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

/// A marker trait used to generalize over the atomic `Variable`
/// and `LinearCombination` types
pub trait MpcLinearCombinationLike<
    N: MpcNetwork + Send + Clone,
    S: SharedValueSource<Scalar> + Clone,
>:
    MultiproverCircuitVariableType<N, S, Self> + Sized + Into<MpcLinearCombination<N, S>> + Clone
{
}
impl<N: MpcNetwork + Send + Clone, S: SharedValueSource<Scalar> + Clone>
    MpcLinearCombinationLike<N, S> for MpcVariable<N, S>
{
}
impl<N: MpcNetwork + Send + Clone, S: SharedValueSource<Scalar> + Clone>
    MpcLinearCombinationLike<N, S> for MpcLinearCombination<N, S>
{
}

/// A base type for allocating within a multiprover constraint system
pub trait MultiproverCircuitBaseType<
    N: MpcNetwork + Send + Clone,
    S: SharedValueSource<Scalar> + Clone,
>: BaseType + CircuitBaseType
{
    /// The multiprover constraint system variable type that results when committing
    /// to the base type in a multiprover constraint system
    type MultiproverVarType<L: MpcLinearCombinationLike<N, S>>: MultiproverCircuitVariableType<
        N,
        S,
        L,
    >;
    /// The shared commitment type that results when committing to the base type in a multiprover
    /// constraint system
    type MultiproverCommType: MultiproverCircuitCommitmentType<N, S>;

    /// Commit to the value in a multiprover constraint system
    #[allow(clippy::type_complexity)]
    fn commit_shared<R: RngCore + CryptoRng>(
        &self,
        owning_party: u64,
        rng: &mut R,
        prover: &mut MpcProver<N, S>,
    ) -> Result<
        (
            Self::MultiproverVarType<MpcVariable<N, S>>,
            Self::MultiproverCommType,
        ),
        MpcError,
    > {
        let self_scalars = self.clone().to_scalars();
        let randomness = self.commitment_randomness(rng);

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
    L: MpcLinearCombinationLike<N, S>,
>
{
    /// Deserialization from an iterator over MPC allocated variables
    fn from_mpc_vars<I: Iterator<Item = L>>(i: &mut I) -> Self;
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

// --- Secret Share Types --- //

/// Implementing types may be secret shared via the `SecretShareType` trait below
pub trait SecretShareBaseType: BaseType {
    /// The secret share type for this base type
    type ShareType: SecretShareType;
}

/// Implementing types represent secret shares of a base type
pub trait SecretShareType: Sized + BaseType {
    /// The base type that this secret share is a representation of
    type Base: BaseType;
    /// Apply an additive blinder to each element of the secret shares
    fn blind(self, blinder: Scalar) -> Self {
        let mut res_scalars = self.to_scalars().into_iter().map(|s| s + blinder);
        Self::from_scalars(&mut res_scalars)
    }

    /// Remove an additive blind from each element of the secret shares
    fn unblind(self, blinder: Scalar) -> Self {
        let mut res_scalars = self.to_scalars().into_iter().map(|s| s - blinder);
        Self::from_scalars(&mut res_scalars)
    }

    /// Add two sets of shares to recover the base type
    ///
    /// We do not require that shares implement `Add` because we wish to default implement
    /// traits on generics types (e.g. `[T]` where `T: SecretShareType`). Requiring an additional
    /// trait bound on `T` would prevent this.
    fn add_shares(self, rhs: Self) -> Self::Base {
        let mut res_scalars = self
            .to_scalars()
            .into_iter()
            .zip(rhs.to_scalars().into_iter())
            .map(|(s1, s2)| s1 + s2);

        Self::Base::from_scalars(&mut res_scalars)
    }
}

/// Implementing types represent a secret share allocated in a constraint system
pub trait SecretShareVarType<L: LinearCombinationLike>: Sized + CircuitVarType<L> {
    /// The base type that this secret share is a representation of
    type Base: CircuitVarType<LinearCombination>;
    /// The type that results from blinding or unblinding the share
    type BlindType: CircuitVarType<LinearCombination>;

    /// Apply an additive blinder to each element of the secret shares
    fn blind<L1: LinearCombinationLike>(self, blinder: L1) -> Self::BlindType {
        let mut res_lcs = self
            .to_vars()
            .into_iter()
            .map(|v| v.into() + blinder.clone().into());

        Self::BlindType::from_vars(&mut res_lcs)
    }

    /// Remove an additive blind from each element of the secret shares
    fn unblind<L1: LinearCombinationLike>(self, blinder: L1) -> Self::BlindType {
        let mut res_lcs = self
            .to_vars()
            .into_iter()
            .map(|v| v.into() - blinder.clone().into());

        Self::BlindType::from_vars(&mut res_lcs)
    }

    /// Add two sets of shares to recover the base type
    ///
    /// We do not require that shares implement `Add` because we wish to default implement
    /// traits on generics types (e.g. `[T]` where `T: SecretShareType`). Requiring an additional
    /// trait bound on `T` would prevent this.
    fn add_shares<L1, R>(self, rhs: R) -> Self::Base
    where
        L1: LinearCombinationLike,
        R: SecretShareVarType<L1>,
    {
        let mut res_lcs = self
            .to_vars()
            .into_iter()
            .zip(rhs.to_vars().into_iter())
            .map(|(v1, v2)| v1.into() + v2.into());

        Self::Base::from_vars(&mut res_lcs)
    }
}

// -----------------------------
// | Type Traits Default Impls |
// -----------------------------

// --- Base Types --- //

impl BaseType for Scalar {
    fn to_scalars(self) -> Vec<Scalar> {
        vec![self]
    }

    fn from_scalars<I: Iterator<Item = Scalar>>(i: &mut I) -> Self {
        i.next().unwrap()
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

impl BaseType for u64 {
    fn to_scalars(self) -> Vec<Scalar> {
        vec![Scalar::from(self)]
    }

    fn from_scalars<I: Iterator<Item = Scalar>>(i: &mut I) -> Self {
        scalar_to_u64(&i.next().unwrap())
    }
}

impl BaseType for BigUint {
    fn to_scalars(self) -> Vec<Scalar> {
        vec![biguint_to_scalar(&self)]
    }

    fn from_scalars<I: Iterator<Item = Scalar>>(i: &mut I) -> Self {
        scalar_to_biguint(&i.next().unwrap())
    }
}

impl<const N: usize, T: BaseType> BaseType for [T; N] {
    fn to_scalars(self) -> Vec<Scalar> {
        self.into_iter().flat_map(|x| x.to_scalars()).collect()
    }

    fn from_scalars<I: Iterator<Item = Scalar>>(i: &mut I) -> Self {
        (0..N)
            .map(|_| T::from_scalars(i))
            .collect_vec()
            .try_into()
            .map_err(|_| ERR_TOO_FEW_SCALARS)
            .unwrap()
    }
}

impl<T: BaseType> BaseType for Vec<T> {
    fn to_scalars(self) -> Vec<Scalar> {
        self.into_iter().flat_map(|x| x.to_scalars()).collect()
    }

    fn from_scalars<I: Iterator<Item = Scalar>>(i: &mut I) -> Self {
        let mut peekable = i.peekable();
        let mut res = Vec::new();
        while peekable.peek().is_some() {
            res.push(T::from_scalars(&mut peekable));
        }

        res
    }
}

// --- Singleprover Circuit Trait Impls --- //

impl CircuitBaseType for Scalar {
    type VarType<L: LinearCombinationLike> = L;
    type CommitmentType = CompressedRistretto;

    fn commitment_randomness<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Vec<Scalar> {
        vec![Scalar::random(rng)]
    }
}

impl CircuitBaseType for LinkableCommitment {
    type VarType<L: LinearCombinationLike> = L;
    type CommitmentType = CompressedRistretto;

    fn commitment_randomness<R: RngCore + CryptoRng>(&self, _rng: &mut R) -> Vec<Scalar> {
        vec![self.randomness]
    }
}

impl CircuitBaseType for u64 {
    type VarType<L: LinearCombinationLike> = L;
    type CommitmentType = CompressedRistretto;

    fn commitment_randomness<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Vec<Scalar> {
        vec![Scalar::random(rng)]
    }
}

impl CircuitBaseType for BigUint {
    type VarType<L: LinearCombinationLike> = L;
    type CommitmentType = CompressedRistretto;

    fn commitment_randomness<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Vec<Scalar> {
        vec![Scalar::random(rng)]
    }
}

impl<const N: usize, T: CircuitBaseType> CircuitBaseType for [T; N] {
    type VarType<L: LinearCombinationLike> = [T::VarType<L>; N];
    type CommitmentType = [T::CommitmentType; N];

    fn commitment_randomness<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Vec<Scalar> {
        self.iter()
            .flat_map(|x| x.commitment_randomness(rng))
            .collect()
    }
}

impl<T: CircuitBaseType> CircuitBaseType for Vec<T> {
    type VarType<L: LinearCombinationLike> = Vec<T::VarType<L>>;
    type CommitmentType = Vec<T::CommitmentType>;

    fn commitment_randomness<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Vec<Scalar> {
        self.iter()
            .flat_map(|x| x.commitment_randomness(rng))
            .collect()
    }
}

impl CircuitVarType<Variable> for Variable {
    fn to_vars(self) -> Vec<Variable> {
        vec![self]
    }

    fn from_vars<I: Iterator<Item = Variable>>(i: &mut I) -> Self {
        i.next().unwrap()
    }
}

impl CircuitVarType<LinearCombination> for LinearCombination {
    fn to_vars(self) -> Vec<LinearCombination> {
        vec![self]
    }

    fn from_vars<I: Iterator<Item = LinearCombination>>(i: &mut I) -> Self {
        i.next().unwrap()
    }
}

impl<const N: usize, L: LinearCombinationLike, T: CircuitVarType<L>> CircuitVarType<L> for [T; N] {
    fn to_vars(self) -> Vec<L> {
        self.into_iter().flat_map(|x| x.to_vars()).collect()
    }

    fn from_vars<I: Iterator<Item = L>>(i: &mut I) -> Self {
        (0..N)
            .map(|_| T::from_vars(i))
            .collect_vec()
            .try_into()
            .map_err(|_| ERR_TOO_FEW_VARS)
            .unwrap()
    }
}

impl<L: LinearCombinationLike, T: CircuitVarType<L>> CircuitVarType<L> for Vec<T> {
    fn to_vars(self) -> Vec<L> {
        self.into_iter().flat_map(|x| x.to_vars()).collect()
    }

    fn from_vars<I: Iterator<Item = L>>(i: &mut I) -> Self {
        let mut peekable = i.peekable();
        let mut res = Vec::new();
        while peekable.peek().is_some() {
            res.push(T::from_vars(&mut peekable));
        }

        res
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

impl<const N: usize, T: CircuitCommitmentType> CircuitCommitmentType for [T; N] {
    type VarType = [T::VarType; N];

    fn from_commitments<I: Iterator<Item = CompressedRistretto>>(i: &mut I) -> Self {
        (0..N)
            .map(|_| T::from_commitments(i))
            .collect_vec()
            .try_into()
            .map_err(|_| ERR_TOO_FEW_COMMITMENTS)
            .unwrap()
    }

    fn to_commitments(self) -> Vec<CompressedRistretto> {
        self.into_iter()
            .flat_map(|x| x.to_commitments())
            .collect_vec()
    }
}

impl<T: CircuitCommitmentType> CircuitCommitmentType for Vec<T> {
    type VarType = Vec<T::VarType>;

    fn from_commitments<I: Iterator<Item = CompressedRistretto>>(i: &mut I) -> Self {
        let mut peekable = i.peekable();
        let mut res = Vec::new();
        while peekable.peek().is_some() {
            res.push(T::from_commitments(&mut peekable));
        }

        res
    }

    fn to_commitments(self) -> Vec<CompressedRistretto> {
        self.into_iter()
            .flat_map(|x| x.to_commitments())
            .collect_vec()
    }
}

// --- MPC Circuit Trait Impls --- //

impl<N: MpcNetwork + Send + Clone, S: SharedValueSource<Scalar> + Clone> MpcBaseType<N, S>
    for Scalar
{
    type AllocatedType = AuthenticatedScalar<N, S>;
}

impl<N: MpcNetwork + Send + Clone, S: SharedValueSource<Scalar> + Clone> MpcBaseType<N, S> for u64 {
    type AllocatedType = AuthenticatedScalar<N, S>;
}

impl<N: MpcNetwork + Send + Clone, S: SharedValueSource<Scalar> + Clone> MpcBaseType<N, S>
    for BigUint
{
    type AllocatedType = AuthenticatedScalar<N, S>;
}

impl<
        const L: usize,
        N: MpcNetwork + Send + Clone,
        S: SharedValueSource<Scalar> + Clone,
        T: MpcBaseType<N, S>,
    > MpcBaseType<N, S> for [T; L]
{
    type AllocatedType = [T::AllocatedType; L];
}

impl<N: MpcNetwork + Send + Clone, S: SharedValueSource<Scalar> + Clone, T: MpcBaseType<N, S>>
    MpcBaseType<N, S> for Vec<T>
{
    type AllocatedType = Vec<T::AllocatedType>;
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

impl<
        const L: usize,
        N: MpcNetwork + Send + Clone,
        S: SharedValueSource<Scalar> + Clone,
        T: MpcType<N, S>,
    > MpcType<N, S> for [T; L]
{
    type NativeType = [T::NativeType; L];

    fn from_authenticated_scalars<I: Iterator<Item = AuthenticatedScalar<N, S>>>(
        i: &mut I,
    ) -> Self {
        (0..L)
            .map(|_| T::from_authenticated_scalars(i))
            .collect_vec()
            .try_into()
            .map_err(|_| "from_authenticated_scalars: Invalid number of authenticated scalars")
            .unwrap()
    }

    fn to_authenticated_scalars(self) -> Vec<AuthenticatedScalar<N, S>> {
        self.into_iter()
            .flat_map(|x| x.to_authenticated_scalars())
            .collect_vec()
    }
}

impl<N: MpcNetwork + Send + Clone, S: SharedValueSource<Scalar> + Clone, T: MpcType<N, S>>
    MpcType<N, S> for Vec<T>
{
    type NativeType = Vec<T::NativeType>;

    fn from_authenticated_scalars<I: Iterator<Item = AuthenticatedScalar<N, S>>>(
        i: &mut I,
    ) -> Self {
        let mut peekable = i.peekable();
        let mut res = Vec::new();
        while peekable.peek().is_some() {
            res.push(T::from_authenticated_scalars(&mut peekable));
        }

        res
    }

    fn to_authenticated_scalars(self) -> Vec<AuthenticatedScalar<N, S>> {
        self.into_iter()
            .flat_map(|x| x.to_authenticated_scalars())
            .collect_vec()
    }
}

// --- Multiprover Circuit Trait Impls --- //

impl<N: MpcNetwork + Send + Clone, S: SharedValueSource<Scalar> + Clone>
    MultiproverCircuitBaseType<N, S> for Scalar
{
    type MultiproverVarType<L: MpcLinearCombinationLike<N, S>> = L;
    type MultiproverCommType = AuthenticatedCompressedRistretto<N, S>;
}

impl<N: MpcNetwork + Send + Clone, S: SharedValueSource<Scalar> + Clone>
    MultiproverCircuitBaseType<N, S> for u64
{
    type MultiproverVarType<L: MpcLinearCombinationLike<N, S>> = L;
    type MultiproverCommType = AuthenticatedCompressedRistretto<N, S>;
}

impl<N: MpcNetwork + Send + Clone, S: SharedValueSource<Scalar> + Clone>
    MultiproverCircuitBaseType<N, S> for BigUint
{
    type MultiproverVarType<L: MpcLinearCombinationLike<N, S>> = L;
    type MultiproverCommType = AuthenticatedCompressedRistretto<N, S>;
}

impl<N: MpcNetwork + Send + Clone, S: SharedValueSource<Scalar> + Clone>
    MultiproverCircuitBaseType<N, S> for LinkableCommitment
{
    type MultiproverVarType<L: MpcLinearCombinationLike<N, S>> = L;
    type MultiproverCommType = AuthenticatedCompressedRistretto<N, S>;

    /// Linkable commitments store their randomness to be re-used across proofs,
    /// so they must override this method to use custom randomness
    fn commit_shared<R: RngCore + CryptoRng>(
        &self,
        owning_party: u64,
        _rng: &mut R,
        prover: &mut MpcProver<N, S>,
    ) -> Result<
        (
            Self::MultiproverVarType<MpcVariable<N, S>>,
            Self::MultiproverCommType,
        ),
        MpcError,
    > {
        let (comm, var) = prover
            .commit(owning_party, self.val, self.randomness)
            .map_err(|err| MpcError::SharingError(err.to_string()))?;
        Ok((var, comm))
    }
}

impl<
        const L: usize,
        N: MpcNetwork + Send + Clone,
        S: SharedValueSource<Scalar> + Clone,
        T: MultiproverCircuitBaseType<N, S>,
    > MultiproverCircuitBaseType<N, S> for [T; L]
{
    type MultiproverVarType<M: MpcLinearCombinationLike<N, S>> = [T::MultiproverVarType<M>; L];
    type MultiproverCommType = [T::MultiproverCommType; L];
}

impl<
        N: MpcNetwork + Send + Clone,
        S: SharedValueSource<Scalar> + Clone,
        T: MultiproverCircuitBaseType<N, S>,
    > MultiproverCircuitBaseType<N, S> for Vec<T>
{
    type MultiproverVarType<M: MpcLinearCombinationLike<N, S>> = Vec<T::MultiproverVarType<M>>;
    type MultiproverCommType = Vec<T::MultiproverCommType>;
}

impl<N: MpcNetwork + Send + Clone, S: SharedValueSource<Scalar> + Clone>
    MultiproverCircuitVariableType<N, S, MpcVariable<N, S>> for MpcVariable<N, S>
{
    fn from_mpc_vars<I: Iterator<Item = MpcVariable<N, S>>>(i: &mut I) -> Self {
        i.next().unwrap()
    }
}

impl<N: MpcNetwork + Send + Clone, S: SharedValueSource<Scalar> + Clone>
    MultiproverCircuitVariableType<N, S, MpcLinearCombination<N, S>>
    for MpcLinearCombination<N, S>
{
    fn from_mpc_vars<I: Iterator<Item = MpcLinearCombination<N, S>>>(i: &mut I) -> Self {
        i.next().unwrap()
    }
}

impl<
        const U: usize,
        N: MpcNetwork + Send + Clone,
        S: SharedValueSource<Scalar> + Clone,
        L: MpcLinearCombinationLike<N, S>,
        T: MultiproverCircuitVariableType<N, S, L>,
    > MultiproverCircuitVariableType<N, S, L> for [T; U]
{
    fn from_mpc_vars<I: Iterator<Item = L>>(i: &mut I) -> Self {
        (0..U)
            .map(|_| T::from_mpc_vars(i))
            .collect_vec()
            .try_into()
            .map_err(|_| "from_mpc_vars: Invalid number of variables")
            .unwrap()
    }
}

impl<
        N: MpcNetwork + Send + Clone,
        S: SharedValueSource<Scalar> + Clone,
        L: MpcLinearCombinationLike<N, S>,
        T: MultiproverCircuitVariableType<N, S, L>,
    > MultiproverCircuitVariableType<N, S, L> for Vec<T>
{
    fn from_mpc_vars<I: Iterator<Item = L>>(i: &mut I) -> Self {
        let mut peekable = i.peekable();
        let mut res = Vec::new();
        while peekable.peek().is_some() {
            res.push(T::from_mpc_vars(&mut peekable));
        }

        res
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

impl<
        const U: usize,
        N: MpcNetwork + Send + Clone,
        S: SharedValueSource<Scalar> + Clone,
        T: MultiproverCircuitCommitmentType<N, S>,
    > MultiproverCircuitCommitmentType<N, S> for [T; U]
{
    type BaseCommitType = [T::BaseCommitType; U];
    fn from_mpc_commitments<I: Iterator<Item = AuthenticatedCompressedRistretto<N, S>>>(
        i: &mut I,
    ) -> Self {
        (0..U)
            .map(|_| T::from_mpc_commitments(i))
            .collect_vec()
            .try_into()
            .map_err(|_| "from_mpc_commitments: Invalid number of commitments")
            .unwrap()
    }

    fn to_mpc_commitments(self) -> Vec<AuthenticatedCompressedRistretto<N, S>> {
        self.into_iter()
            .flat_map(|x| x.to_mpc_commitments())
            .collect()
    }
}

impl<
        N: MpcNetwork + Send + Clone,
        S: SharedValueSource<Scalar> + Clone,
        T: MultiproverCircuitCommitmentType<N, S>,
    > MultiproverCircuitCommitmentType<N, S> for Vec<T>
{
    type BaseCommitType = Vec<T::BaseCommitType>;
    fn from_mpc_commitments<I: Iterator<Item = AuthenticatedCompressedRistretto<N, S>>>(
        i: &mut I,
    ) -> Self {
        let mut peekable = i.peekable();
        let mut res = Vec::new();
        while peekable.peek().is_some() {
            res.push(T::from_mpc_commitments(&mut peekable));
        }

        res
    }

    fn to_mpc_commitments(self) -> Vec<AuthenticatedCompressedRistretto<N, S>> {
        self.into_iter()
            .flat_map(|x| x.to_mpc_commitments())
            .collect()
    }
}

// --- Linkable Type Trait Impls --- //

impl LinkableBaseType for Scalar {
    type Linkable = LinkableCommitment;
}

impl LinkableBaseType for u64 {
    type Linkable = LinkableCommitment;
}

impl LinkableBaseType for BigUint {
    type Linkable = LinkableCommitment;
}

impl<const N: usize, T: LinkableBaseType> LinkableBaseType for [T; N] {
    type Linkable = [T::Linkable; N];
}

impl<T: LinkableBaseType> LinkableBaseType for Vec<T> {
    type Linkable = Vec<T::Linkable>;
}

impl LinkableType for LinkableCommitment {
    type BaseType = Scalar;
}

impl<const N: usize, T: LinkableType> LinkableType for [T; N] {
    type BaseType = [T::BaseType; N];
}

impl<T: LinkableType> LinkableType for Vec<T> {
    type BaseType = Vec<T::BaseType>;
}

// --- Secret Share Impls --- //

impl SecretShareBaseType for Scalar {
    type ShareType = Scalar;
}

impl SecretShareBaseType for u64 {
    type ShareType = Scalar;
}

impl SecretShareBaseType for BigUint {
    type ShareType = Scalar;
}

impl<const N: usize, T: SecretShareBaseType> SecretShareBaseType for [T; N] {
    type ShareType = [T::ShareType; N];
}

impl<T: SecretShareBaseType> SecretShareBaseType for Vec<T> {
    type ShareType = Vec<T::ShareType>;
}

impl SecretShareType for Scalar {
    type Base = Scalar;
}

impl<const N: usize, T: SecretShareType> SecretShareType for [T; N] {
    type Base = [T::Base; N];
}

impl<T: SecretShareType> SecretShareType for Vec<T> {
    type Base = Vec<T::Base>;
}

impl SecretShareVarType<Variable> for Variable {
    type Base = LinearCombination;
    type BlindType = LinearCombination;
}

impl SecretShareVarType<LinearCombination> for LinearCombination {
    type Base = LinearCombination;
    type BlindType = LinearCombination;
}

impl<const N: usize, L: LinearCombinationLike, T: SecretShareVarType<L>> SecretShareVarType<L>
    for [T; N]
{
    type Base = [T::Base; N];
    type BlindType = [T::BlindType; N];
}

impl<L: LinearCombinationLike, T: SecretShareVarType<L>> SecretShareVarType<L> for Vec<T> {
    type Base = Vec<T::Base>;
    type BlindType = Vec<T::BlindType>;
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
    ) -> Result<
        (
            <Self::Witness as CircuitBaseType>::CommitmentType,
            R1CSProof,
        ),
        ProverError,
    >;

    /// Verify a proof of the statement represented by the circuit
    ///
    /// The verifier has access to the statement variables, but only hiding (and binding)
    /// commitments to the witness variables
    fn verify(
        witness_commitment: <Self::Witness as WitnessCommitment>::CommitmentType,
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
    ) -> Result<
        (
            <Self::WitnessCommitment as MultiproverCircuitBaseType<'a, N, S>>::CommitmentType,
            SharedR1CSProof<N, S>,
        ),
        ProverError,
    >;

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
        witness_commitments:
            <<Self::Witness as MultiproverCircuitBaseType<'a, N, S>>::MultiproverCommType 
                as MultiproverCircuitCommitmentType<N, S,>>::BaseCommitType,
        statement: Self::Statement,
        proof: R1CSProof,
        verifier: Verifier,
    ) -> Result<(), VerifierError>;
}
