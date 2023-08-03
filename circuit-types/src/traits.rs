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
//!     - Linkable types: Types that may be commitment linked across proofs
//!     - Secret share types: Additive sharings of a base type

use async_trait::async_trait;
use futures::future::join_all;
use itertools::Itertools;
use mpc_bulletproof::{
    r1cs::{
        LinearCombination, Prover, R1CSProof, RandomizableConstraintSystem, Variable, Verifier,
    },
    r1cs_mpc::{
        MpcLinearCombination, MpcProver, MpcRandomizableConstraintSystem, MpcVariable,
        PartiallySharedR1CSProof, R1CSError,
    },
    BulletproofGens,
};
use mpc_stark::{
    algebra::{
        authenticated_scalar::AuthenticatedScalarResult,
        authenticated_stark_point::AuthenticatedStarkPointOpenResult, scalar::Scalar,
        stark_curve::StarkPoint,
    },
    network::PartyId,
    MpcFabric,
};
use num_bigint::BigUint;
use rand::{thread_rng, CryptoRng, RngCore};
use renegade_crypto::fields::{biguint_to_scalar, scalar_to_biguint, scalar_to_u64};

use crate::{
    errors::{MpcError, ProverError, VerifierError},
    AuthenticatedLinkableCommitment, LinkableCommitment,
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
#[async_trait]
pub trait BaseType: Clone {
    /// Convert the base type to its serialized scalar representation in the circuit
    fn to_scalars(&self) -> Vec<Scalar>;
    /// Convert the base type to its serialized scalar representation including commitment
    /// linking information
    ///
    /// The default implementation does nothing beyond what `to_scalars` does, but commitment
    /// linked types should override this method
    fn to_scalars_with_linking(&self) -> Vec<Scalar> {
        self.to_scalars()
    }
    /// Convert from a serialized scalar representation to the base type
    fn from_scalars<I: Iterator<Item = Scalar>>(i: &mut I) -> Self;

    /// Share the plaintext value with the counterparty over an MPC fabric
    ///
    /// This method is added to the `BaseType` trait for maximum flexibility, so that
    /// types may be shared without requiring them to implement the full `MpcBaseType`
    /// trait
    async fn share_public(&self, owning_party: PartyId, fabric: MpcFabric) -> Self {
        let self_scalars = self.clone().to_scalars_with_linking();
        let res_scalars = fabric
            .batch_share_plaintext(self_scalars, owning_party)
            .await;

        Self::from_scalars(&mut res_scalars.into_iter())
    }
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
    type CommitmentType: CircuitCommitmentType<VarType = Self::VarType<Variable>>;

    /// Commit to the base type as a witness variable
    fn commit_witness<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> (Self::VarType<Variable>, Self::CommitmentType) {
        let scalars: Vec<Scalar> = self.clone().to_scalars();
        let randomness = self.commitment_randomness(rng);
        let (comms, vars): (Vec<StarkPoint>, Vec<Variable>) = scalars
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
    /// The type created by converting all base types to `LinearCombination`
    type LinearCombinationType: CircuitVarType<LinearCombination>;
    /// Convert to a collection of serialized variables for the type
    fn to_vars(&self) -> Vec<L>;
    /// Convert from an iterable of variables representing the serialized type
    fn from_vars<I: Iterator<Item = L>>(i: &mut I) -> Self;
    /// Convert the base type to a `LinearCombination` type
    fn to_lc(&self) -> Self::LinearCombinationType {
        let mut vars = self
            .to_vars()
            .into_iter()
            .map(|v| Into::<LinearCombination>::into(v));
        Self::LinearCombinationType::from_vars(&mut vars)
    }
}

/// Implementing types are commitments to base types that have an analogous variable
/// type allocated with them
pub trait CircuitCommitmentType: Clone {
    /// The variable type that this type is a commitment to
    type VarType: CircuitVarType<Variable>;
    /// Convert from an iterable of compressed ristretto points, each representing
    /// a commitment to an underlying variable
    fn from_commitments<I: Iterator<Item = StarkPoint>>(i: &mut I) -> Self;
    /// Convert to a vector of compressed ristretto points
    fn to_commitments(&self) -> Vec<StarkPoint>;

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
pub trait MpcBaseType: BaseType {
    /// The type that results from allocating the base type into an MPC network
    type AllocatedType: MpcType;

    /// Allocates the base type in the network as a shared value
    fn allocate(
        &self,
        sender: PartyId,
        fabric: MpcFabric,
    ) -> Result<Self::AllocatedType, MpcError> {
        let self_scalars = self.clone().to_scalars_with_linking();
        let values = fabric.batch_share_scalar(self_scalars, sender);

        Ok(Self::AllocatedType::from_authenticated_scalars(
            &mut values.into_iter(),
        ))
    }
}

/// An implementing type is the representation of a `BaseType` in an MPC circuit
/// *outside* of a multiprover constraint system
#[async_trait]
pub trait MpcType: Clone {
    /// The native type when the value is opened out of a circuit
    type NativeType: BaseType;
    /// Get a reference to the underlying MPC fabric
    fn fabric(&self) -> &MpcFabric;
    /// Convert from an iterable of authenticated scalars: scalars that have been
    /// allocated in an MPC fabric
    fn from_authenticated_scalars<I: Iterator<Item = AuthenticatedScalarResult>>(i: &mut I)
        -> Self;
    /// Convert to a vector of authenticated scalars
    fn to_authenticated_scalars(&self) -> Vec<AuthenticatedScalarResult>;
    /// Convert to a vector of authenticated scalars with proof linking information included
    ///
    /// By default this method does nothing beyond what `to_authenticated_scalars` does, but
    /// commitment linked types should override this method to include commitment randomness
    fn to_authenticated_scalars_with_linking(&self) -> Vec<AuthenticatedScalarResult> {
        self.to_authenticated_scalars()
    }

    /// Opens the shared type without authenticating
    async fn open(self) -> Result<Self::NativeType, MpcError> {
        let self_scalars = self.to_authenticated_scalars_with_linking();
        let opened_scalars = join_all(AuthenticatedScalarResult::open_batch(&self_scalars)).await;

        Ok(Self::NativeType::from_scalars(
            &mut opened_scalars.into_iter(),
        ))
    }

    /// Opens the shared type and authenticates the result
    async fn open_and_authenticate(self) -> Result<Self::NativeType, MpcError> {
        let self_scalars = self.to_authenticated_scalars_with_linking();
        let opened_scalars = join_all(AuthenticatedScalarResult::open_authenticated_batch(
            &self_scalars,
        ))
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| MpcError::OpeningError(err.to_string()))?;

        Ok(Self::NativeType::from_scalars(
            &mut opened_scalars.into_iter(),
        ))
    }
}

// --- Multiprover Circuit Traits --- //

/// A marker trait used to generalize over the atomic `MpcVariable`
/// and `MpcLinearCombination` types
pub trait MpcLinearCombinationLike:
    MultiproverCircuitVariableType<Self> + Sized + Into<MpcLinearCombination> + Clone
{
}
impl MpcLinearCombinationLike for MpcVariable {}
impl MpcLinearCombinationLike for MpcLinearCombination {}

/// A base type for allocating within a multiprover constraint system
pub trait MultiproverCircuitBaseType: MpcType {
    /// The base type of the multiprover circuit type
    type BaseType: CircuitBaseType;
    /// The multiprover constraint system variable type that results when committing
    /// to the base type in a multiprover constraint system
    type MultiproverVarType<L: MpcLinearCombinationLike>: MultiproverCircuitVariableType<L>;
    /// The shared commitment type that results when committing to the base type in a multiprover
    /// constraint system
    type MultiproverCommType: MultiproverCircuitCommitmentType;

    /// Commit to the value in a multiprover constraint system
    #[allow(clippy::type_complexity)]
    fn commit_shared<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut MpcProver,
    ) -> Result<
        (
            Self::MultiproverVarType<MpcVariable>,
            Self::MultiproverCommType,
        ),
        MpcError,
    > {
        let self_scalars = self.clone().to_authenticated_scalars();
        let randomness = self.commitment_randomness(rng);

        let (comms, vars) = prover
            .batch_commit_preshared(&self_scalars, &randomness)
            .map_err(|err| MpcError::SharingError(err.to_string()))?;

        Ok((
            Self::MultiproverVarType::from_mpc_vars(&mut vars.into_iter()),
            Self::MultiproverCommType::from_mpc_commitments(&mut comms.into_iter()),
        ))
    }

    /// Get the randomness needed to commit to a given value
    fn commitment_randomness<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Vec<AuthenticatedScalarResult>;
}

/// A multiprover circuit variable type
pub trait MultiproverCircuitVariableType<L: MpcLinearCombinationLike>: Clone {
    /// Serialization to a vector of MPC allocated variables
    fn to_mpc_vars(&self) -> Vec<L>;
    /// Deserialization from an iterator over MPC allocated variables
    fn from_mpc_vars<I: Iterator<Item = L>>(i: &mut I) -> Self;
}

/// A multiprover circuit commitment type
#[async_trait]
pub trait MultiproverCircuitCommitmentType: Clone + Sync {
    /// The base commitment type that this commitment opens to
    type BaseCommitType: CircuitCommitmentType;
    /// Deserialization form an iterator over MPC allocated commitments
    ///
    /// The transcript opens each commitment as it is generated so that the transcript may
    /// be evaluated in plaintext (outside of the MPC circuit). For this reason, the primitive
    /// type of a multiprover commitment type is the result of this opening, which may resolve to
    /// an error if either party cheats
    fn from_mpc_commitments<I: Iterator<Item = AuthenticatedStarkPointOpenResult>>(
        i: &mut I,
    ) -> Self;
    /// Serialization to a vector of MPC allocated commitments
    fn to_mpc_commitments(&self) -> Vec<AuthenticatedStarkPointOpenResult>;

    /// Opens the shared type and authenticates the result
    async fn open_and_authenticate(self) -> Result<Self::BaseCommitType, MpcError> {
        let opened_commitments = join_all(self.to_mpc_commitments())
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| MpcError::OpeningError(err.to_string()))?;

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
    /// Convert from the base type to the linkable type
    fn to_linkable(&self) -> Self::Linkable;
}

/// Implementing types are proof-linkable analogs of a base type, which hold onto their commitment
/// randomness and re-use it between proofs
pub trait LinkableType: Clone + BaseType {
    /// The base type this type is a linkable commitment for
    type BaseType: LinkableBaseType;
    /// Convert to the base type, removing the proof-linkable information
    fn to_base_type(&self) -> Self::BaseType {
        let self_scalars = self.to_scalars();
        Self::BaseType::from_scalars(&mut self_scalars.into_iter())
    }
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
    fn to_scalars(&self) -> Vec<Scalar> {
        vec![*self]
    }

    fn from_scalars<I: Iterator<Item = Scalar>>(i: &mut I) -> Self {
        i.next().unwrap()
    }
}

impl BaseType for LinkableCommitment {
    fn to_scalars(&self) -> Vec<Scalar> {
        vec![self.val]
    }

    fn to_scalars_with_linking(&self) -> Vec<Scalar> {
        vec![self.val, self.randomness]
    }

    fn from_scalars<I: Iterator<Item = Scalar>>(i: &mut I) -> Self {
        // Choose a random commitment
        Self {
            val: i.next().unwrap(),
            randomness: i.next().unwrap(),
        }
    }
}

impl BaseType for u64 {
    fn to_scalars(&self) -> Vec<Scalar> {
        vec![Scalar::from(*self)]
    }

    fn from_scalars<I: Iterator<Item = Scalar>>(i: &mut I) -> Self {
        scalar_to_u64(&i.next().unwrap())
    }
}

impl BaseType for BigUint {
    fn to_scalars(&self) -> Vec<Scalar> {
        vec![biguint_to_scalar(self)]
    }

    fn from_scalars<I: Iterator<Item = Scalar>>(i: &mut I) -> Self {
        scalar_to_biguint(&i.next().unwrap())
    }
}

impl BaseType for () {
    fn to_scalars(&self) -> Vec<Scalar> {
        vec![]
    }

    fn from_scalars<I: Iterator<Item = Scalar>>(_: &mut I) -> Self {}
}

impl<const N: usize, T: BaseType> BaseType for [T; N] {
    fn to_scalars(&self) -> Vec<Scalar> {
        self.iter().flat_map(|x| x.to_scalars()).collect()
    }

    fn to_scalars_with_linking(&self) -> Vec<Scalar> {
        self.iter()
            .flat_map(|x| x.to_scalars_with_linking())
            .collect()
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

// --- Singleprover Circuit Trait Impls --- //

impl CircuitBaseType for Scalar {
    type VarType<L: LinearCombinationLike> = L;
    type CommitmentType = StarkPoint;

    fn commitment_randomness<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Vec<Scalar> {
        vec![Scalar::random(rng)]
    }
}

impl CircuitBaseType for LinkableCommitment {
    type VarType<L: LinearCombinationLike> = L;
    type CommitmentType = StarkPoint;

    fn commitment_randomness<R: RngCore + CryptoRng>(&self, _rng: &mut R) -> Vec<Scalar> {
        vec![self.randomness]
    }
}

impl CircuitBaseType for u64 {
    type VarType<L: LinearCombinationLike> = L;
    type CommitmentType = StarkPoint;

    fn commitment_randomness<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Vec<Scalar> {
        vec![Scalar::random(rng)]
    }
}

impl CircuitBaseType for BigUint {
    type VarType<L: LinearCombinationLike> = L;
    type CommitmentType = StarkPoint;

    fn commitment_randomness<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Vec<Scalar> {
        vec![Scalar::random(rng)]
    }
}

impl CircuitBaseType for () {
    type VarType<L: LinearCombinationLike> = ();
    type CommitmentType = ();

    fn commitment_randomness<R: RngCore + CryptoRng>(&self, _rng: &mut R) -> Vec<Scalar> {
        vec![]
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

impl CircuitVarType<Variable> for Variable {
    type LinearCombinationType = LinearCombination;

    fn to_vars(&self) -> Vec<Variable> {
        vec![*self]
    }

    fn from_vars<I: Iterator<Item = Variable>>(i: &mut I) -> Self {
        i.next().unwrap()
    }
}

impl CircuitVarType<LinearCombination> for LinearCombination {
    type LinearCombinationType = LinearCombination;

    fn to_vars(&self) -> Vec<LinearCombination> {
        vec![self.clone()]
    }

    fn from_vars<I: Iterator<Item = LinearCombination>>(i: &mut I) -> Self {
        i.next().unwrap()
    }
}

impl<L: LinearCombinationLike> CircuitVarType<L> for () {
    type LinearCombinationType = ();

    fn from_vars<I: Iterator<Item = L>>(_: &mut I) -> Self {}

    fn to_vars(&self) -> Vec<L> {
        vec![]
    }
}

impl<const N: usize, L: LinearCombinationLike, T: CircuitVarType<L>> CircuitVarType<L> for [T; N] {
    type LinearCombinationType = [T::LinearCombinationType; N];

    fn to_vars(&self) -> Vec<L> {
        self.iter().flat_map(|x| x.to_vars()).collect()
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

impl CircuitCommitmentType for StarkPoint {
    type VarType = Variable;

    fn from_commitments<I: Iterator<Item = StarkPoint>>(i: &mut I) -> Self {
        i.next().unwrap()
    }

    fn to_commitments(&self) -> Vec<StarkPoint> {
        vec![*self]
    }
}

impl CircuitCommitmentType for () {
    type VarType = ();
    fn from_commitments<I: Iterator<Item = StarkPoint>>(_: &mut I) -> Self {}

    fn to_commitments(&self) -> Vec<StarkPoint> {
        vec![]
    }
}

impl<const N: usize, T: CircuitCommitmentType> CircuitCommitmentType for [T; N] {
    type VarType = [T::VarType; N];

    fn from_commitments<I: Iterator<Item = StarkPoint>>(i: &mut I) -> Self {
        (0..N)
            .map(|_| T::from_commitments(i))
            .collect_vec()
            .try_into()
            .map_err(|_| ERR_TOO_FEW_COMMITMENTS)
            .unwrap()
    }

    fn to_commitments(&self) -> Vec<StarkPoint> {
        self.iter().flat_map(|x| x.to_commitments()).collect_vec()
    }
}

// --- MPC Circuit Trait Impls --- //

impl MpcBaseType for Scalar {
    type AllocatedType = AuthenticatedScalarResult;
}

impl MpcBaseType for u64 {
    type AllocatedType = AuthenticatedScalarResult;
}

impl MpcBaseType for BigUint {
    type AllocatedType = AuthenticatedScalarResult;
}

impl MpcBaseType for LinkableCommitment {
    type AllocatedType = AuthenticatedLinkableCommitment;
}

impl MpcBaseType for () {
    type AllocatedType = ();
}

impl<const L: usize, T: MpcBaseType> MpcBaseType for [T; L] {
    type AllocatedType = [T::AllocatedType; L];
}

impl MpcType for AuthenticatedScalarResult {
    type NativeType = Scalar;

    fn fabric(&self) -> &MpcFabric {
        self.fabric()
    }

    fn from_authenticated_scalars<I: Iterator<Item = AuthenticatedScalarResult>>(
        i: &mut I,
    ) -> Self {
        i.next().unwrap()
    }

    fn to_authenticated_scalars(&self) -> Vec<AuthenticatedScalarResult> {
        vec![self.clone()]
    }
}

impl MpcType for AuthenticatedLinkableCommitment {
    type NativeType = LinkableCommitment;

    fn fabric(&self) -> &MpcFabric {
        self.val.fabric()
    }

    fn from_authenticated_scalars<I: Iterator<Item = AuthenticatedScalarResult>>(
        i: &mut I,
    ) -> Self {
        let val = i.next().unwrap();
        let randomness = i.next().unwrap();
        AuthenticatedLinkableCommitment { val, randomness }
    }

    fn to_authenticated_scalars(&self) -> Vec<AuthenticatedScalarResult> {
        vec![self.val.clone()]
    }

    fn to_authenticated_scalars_with_linking(&self) -> Vec<AuthenticatedScalarResult> {
        vec![self.val.clone(), self.randomness.clone()]
    }
}

impl MpcType for () {
    type NativeType = ();

    fn fabric(&self) -> &MpcFabric {
        unimplemented!()
    }

    fn from_authenticated_scalars<I: Iterator<Item = AuthenticatedScalarResult>>(
        _: &mut I,
    ) -> Self {
    }

    fn to_authenticated_scalars(&self) -> Vec<AuthenticatedScalarResult> {
        vec![]
    }
}

impl<const L: usize, T: MpcType> MpcType for [T; L] {
    type NativeType = [T::NativeType; L];

    fn fabric(&self) -> &MpcFabric {
        self[0].fabric()
    }

    fn from_authenticated_scalars<I: Iterator<Item = AuthenticatedScalarResult>>(
        i: &mut I,
    ) -> Self {
        (0..L)
            .map(|_| T::from_authenticated_scalars(i))
            .collect_vec()
            .try_into()
            .map_err(|_| "from_authenticated_scalars: Invalid number of authenticated scalars")
            .unwrap()
    }

    fn to_authenticated_scalars(&self) -> Vec<AuthenticatedScalarResult> {
        self.iter()
            .flat_map(|x| x.to_authenticated_scalars())
            .collect_vec()
    }

    fn to_authenticated_scalars_with_linking(&self) -> Vec<AuthenticatedScalarResult> {
        self.iter()
            .flat_map(|x| x.to_authenticated_scalars_with_linking())
            .collect_vec()
    }
}

// --- Multiprover Circuit Trait Impls --- //

impl MultiproverCircuitBaseType for AuthenticatedScalarResult {
    type BaseType = Scalar;
    type MultiproverVarType<L: MpcLinearCombinationLike> = L;
    type MultiproverCommType = AuthenticatedStarkPointOpenResult;

    fn commitment_randomness<R: RngCore + CryptoRng>(
        &self,
        _rng: &mut R,
    ) -> Vec<AuthenticatedScalarResult> {
        self.fabric().random_shared_scalars_authenticated(1 /* n */)
    }
}

impl MultiproverCircuitBaseType for AuthenticatedLinkableCommitment {
    type BaseType = LinkableCommitment;
    type MultiproverVarType<L: MpcLinearCombinationLike> = L;
    type MultiproverCommType = AuthenticatedStarkPointOpenResult;

    fn commitment_randomness<R: RngCore + CryptoRng>(
        &self,
        _rng: &mut R,
    ) -> Vec<AuthenticatedScalarResult> {
        vec![self.randomness.clone()]
    }
}

impl MultiproverCircuitBaseType for () {
    type BaseType = ();
    type MultiproverVarType<L: MpcLinearCombinationLike> = ();
    type MultiproverCommType = ();

    fn commitment_randomness<R: RngCore + CryptoRng>(
        &self,
        _rng: &mut R,
    ) -> Vec<AuthenticatedScalarResult> {
        vec![]
    }
}

impl<const L: usize, T: MultiproverCircuitBaseType> MultiproverCircuitBaseType for [T; L] {
    type BaseType = [T::BaseType; L];
    type MultiproverVarType<M: MpcLinearCombinationLike> = [T::MultiproverVarType<M>; L];
    type MultiproverCommType = [T::MultiproverCommType; L];

    fn commitment_randomness<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Vec<AuthenticatedScalarResult> {
        self.iter()
            .flat_map(|x| x.commitment_randomness(rng))
            .collect_vec()
    }
}

impl MultiproverCircuitVariableType<MpcVariable> for MpcVariable {
    fn to_mpc_vars(&self) -> Vec<MpcVariable> {
        vec![self.clone()]
    }

    fn from_mpc_vars<I: Iterator<Item = MpcVariable>>(i: &mut I) -> Self {
        i.next().unwrap()
    }
}

impl MultiproverCircuitVariableType<MpcLinearCombination> for MpcLinearCombination {
    fn to_mpc_vars(&self) -> Vec<MpcLinearCombination> {
        vec![self.clone()]
    }

    fn from_mpc_vars<I: Iterator<Item = MpcLinearCombination>>(i: &mut I) -> Self {
        i.next().unwrap()
    }
}

impl<L: MpcLinearCombinationLike> MultiproverCircuitVariableType<L> for () {
    fn to_mpc_vars(&self) -> Vec<L> {
        vec![]
    }

    fn from_mpc_vars<I: Iterator<Item = L>>(_: &mut I) -> Self {}
}

impl<const U: usize, L: MpcLinearCombinationLike, T: MultiproverCircuitVariableType<L>>
    MultiproverCircuitVariableType<L> for [T; U]
{
    fn to_mpc_vars(&self) -> Vec<L> {
        self.iter().flat_map(|x| x.to_mpc_vars()).collect()
    }

    fn from_mpc_vars<I: Iterator<Item = L>>(i: &mut I) -> Self {
        (0..U)
            .map(|_| T::from_mpc_vars(i))
            .collect_vec()
            .try_into()
            .map_err(|_| ERR_TOO_FEW_VARS)
            .unwrap()
    }
}

impl MultiproverCircuitCommitmentType for AuthenticatedStarkPointOpenResult {
    type BaseCommitType = StarkPoint;
    fn from_mpc_commitments<I: Iterator<Item = AuthenticatedStarkPointOpenResult>>(
        i: &mut I,
    ) -> Self {
        i.next().unwrap()
    }

    fn to_mpc_commitments(&self) -> Vec<AuthenticatedStarkPointOpenResult> {
        vec![self.clone()]
    }
}

impl MultiproverCircuitCommitmentType for () {
    type BaseCommitType = ();
    fn from_mpc_commitments<I: Iterator<Item = AuthenticatedStarkPointOpenResult>>(
        _: &mut I,
    ) -> Self {
    }

    fn to_mpc_commitments(&self) -> Vec<AuthenticatedStarkPointOpenResult> {
        vec![]
    }
}

impl<const U: usize, T: MultiproverCircuitCommitmentType> MultiproverCircuitCommitmentType
    for [T; U]
{
    type BaseCommitType = [T::BaseCommitType; U];
    fn from_mpc_commitments<I: Iterator<Item = AuthenticatedStarkPointOpenResult>>(
        i: &mut I,
    ) -> Self {
        (0..U)
            .map(|_| T::from_mpc_commitments(i))
            .collect_vec()
            .try_into()
            .map_err(|_| "from_mpc_commitments: Invalid number of commitments")
            .unwrap()
    }

    fn to_mpc_commitments(&self) -> Vec<AuthenticatedStarkPointOpenResult> {
        self.iter().flat_map(|x| x.to_mpc_commitments()).collect()
    }
}

// --- Linkable Type Trait Impls --- //

impl LinkableBaseType for Scalar {
    type Linkable = LinkableCommitment;

    fn to_linkable(&self) -> Self::Linkable {
        LinkableCommitment::from(*self)
    }
}

impl LinkableBaseType for u64 {
    type Linkable = LinkableCommitment;

    fn to_linkable(&self) -> Self::Linkable {
        LinkableCommitment::from(Scalar::from(*self))
    }
}

impl LinkableBaseType for BigUint {
    type Linkable = LinkableCommitment;

    fn to_linkable(&self) -> Self::Linkable {
        LinkableCommitment::from(biguint_to_scalar(self))
    }
}

impl<const N: usize, T: LinkableBaseType> LinkableBaseType for [T; N] {
    type Linkable = [T::Linkable; N];

    fn to_linkable(&self) -> Self::Linkable {
        self.iter()
            .map(|x| x.to_linkable())
            .collect_vec()
            .try_into()
            .map_err(|_| ERR_TOO_FEW_SCALARS)
            .unwrap()
    }
}

impl LinkableType for LinkableCommitment {
    type BaseType = Scalar;
}

impl<const N: usize, T: LinkableType> LinkableType for [T; N] {
    type BaseType = [T::BaseType; N];
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

impl SecretShareType for Scalar {
    type Base = Scalar;
}

impl<const N: usize, T: SecretShareType> SecretShareType for [T; N] {
    type Base = [T::Base; N];
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

    /// Apply the constraints of the circuit to a given constraint system
    fn apply_constraints<CS: RandomizableConstraintSystem>(
        witness_var: <Self::Witness as CircuitBaseType>::VarType<Variable>,
        statement_var: <Self::Statement as CircuitBaseType>::VarType<Variable>,
        cs: &mut CS,
    ) -> Result<(), R1CSError>;

    /// Generate a proof of the statement represented by the circuit
    ///
    /// Returns both the commitment to the inputs, as well as the proof itself
    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        mut prover: Prover,
    ) -> Result<
        (
            <Self::Witness as CircuitBaseType>::CommitmentType,
            R1CSProof,
        ),
        ProverError,
    > {
        // Commit to the witness and statement
        let mut rng = thread_rng();
        let (witness_var, witness_comm) = witness.commit_witness(&mut rng, &mut prover);
        let statement_var = statement.commit_public(&mut prover);

        // Apply the constraints
        Self::apply_constraints(witness_var, statement_var, &mut prover)
            .map_err(ProverError::R1CS)?;

        // Generate the proof
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        let proof = prover.prove(&bp_gens).map_err(ProverError::R1CS)?;

        Ok((witness_comm, proof))
    }

    /// Verify a proof of the statement represented by the circuit
    ///
    /// The verifier has access to the statement variables, but only hiding (and binding)
    /// commitments to the witness variables
    fn verify(
        witness_commitment: <Self::Witness as CircuitBaseType>::CommitmentType,
        statement: Self::Statement,
        proof: R1CSProof,
        mut verifier: Verifier,
    ) -> Result<(), VerifierError> {
        // Commit to the witness and statement
        let witness_var = witness_commitment.commit_verifier(&mut verifier);
        let statement_var = statement.commit_public(&mut verifier);

        // Apply the constraints
        Self::apply_constraints(witness_var, statement_var, &mut verifier)
            .map_err(VerifierError::R1CS)?;

        // Verify the proof
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        verifier
            .verify(&proof, &bp_gens)
            .map_err(VerifierError::R1CS)
    }
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
pub trait MultiProverCircuit<'a> {
    /// The witness type, given only to the prover, which generates a blinding commitment
    /// that can be given to the verifier
    type Witness: MultiproverCircuitBaseType;
    /// The statement type, given to both the prover and verifier, parameterizes the underlying
    /// NP statement being proven
    type Statement: Clone + MultiproverCircuitBaseType + MpcType;

    /// The size of the bulletproof generators that must be allocated
    /// to fully compute a proof or verification of the statement
    ///
    /// This is a function of circuit depth, one generator is needed per
    /// multiplication gate (roughly)
    const BP_GENS_CAPACITY: usize;

    /// Apply the constraints of the circuit to a multiprover constraint system
    fn apply_constraints_multiprover<CS: MpcRandomizableConstraintSystem<'a>>(
        witness: <Self::Witness as MultiproverCircuitBaseType>::MultiproverVarType<MpcVariable>,
        statement: <Self::Statement as MultiproverCircuitBaseType>::MultiproverVarType<MpcVariable>,
        fabric: MpcFabric,
        cs: &mut CS,
    ) -> Result<(), ProverError>;

    /// Apply the constraints of the circuit to a singleprover constraint system
    #[allow(clippy::type_complexity)]
    fn apply_constraints_singleprover<CS: RandomizableConstraintSystem>(
        witness:
            <<<Self::Witness as MultiproverCircuitBaseType>::MultiproverCommType
                as MultiproverCircuitCommitmentType>::BaseCommitType
                as CircuitCommitmentType>::VarType,
        statement:
            <<Self::Statement as MultiproverCircuitBaseType>::BaseType
                as CircuitBaseType>::VarType<Variable>,
        cs: &mut CS,
    ) -> Result<(), R1CSError>;

    /// Generate a proof of the statement represented by the circuit
    ///
    /// Returns both the commitment to the inputs, as well as the proof itself
    #[allow(clippy::type_complexity)]
    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        fabric: MpcFabric,
        mut prover: MpcProver<'a, '_, '_>,
    ) -> Result<
        (
            <Self::Witness as MultiproverCircuitBaseType>::MultiproverCommType,
            PartiallySharedR1CSProof,
        ),
        ProverError,
    > {
        // Commit to the witness and statement
        let mut rng = thread_rng();
        let (witness_var, witness_comm) = witness
            .commit_shared(&mut rng, &mut prover)
            .map_err(ProverError::Mpc)?;
        let (statement_var, _) = statement
            .commit_shared(&mut rng, &mut prover)
            .map_err(ProverError::Mpc)?;

        // Apply the constraints
        Self::apply_constraints_multiprover(witness_var, statement_var, fabric, &mut prover)?;

        // Generate the proof
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        let proof = prover.prove(&bp_gens).map_err(ProverError::Collaborative)?;

        Ok((witness_comm, proof))
    }

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
            <<Self::Witness as MultiproverCircuitBaseType>::MultiproverCommType
                as MultiproverCircuitCommitmentType>::BaseCommitType,
        statement: <Self::Statement as MultiproverCircuitBaseType>::BaseType,
        proof: R1CSProof,
        mut verifier: Verifier,
    ) -> Result<(), VerifierError>
where {
        // Commit to the witness and statement
        let witness_var = witness_commitments.commit_verifier(&mut verifier);
        let statement_var = statement.commit_public(&mut verifier);

        // Apply the circuit constraints
        Self::apply_constraints_singleprover(witness_var, statement_var, &mut verifier)
            .map_err(VerifierError::R1CS)?;

        // Verify the proof
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        verifier
            .verify(&proof, &bp_gens)
            .map_err(VerifierError::R1CS)
    }
}
