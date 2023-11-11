//! Defines traits which group derived types and translations between them
//!
//! We strongly type inputs to our ZK(MPC) circuits to gain circuit readability
//! and inherit safety properties from the type checker and linters (i.e. unused
//! witness elements)
//!
//! We group types of types by traits which associate with other types. For
//! example, types allocated in an MPC circuit implement different traits than
//! ZK circuit types do, due to their different underlying primitives
//!
//! At a high level the types are:
//!     - Base types: application level types that have semantically meaningful
//!       values
//!     - Single-prover variable types: base types allocated in a single-prover
//!       constraint system
//!     - MPC types: base types that have been allocated in an MPC fabric
//!     - Secret share types: Additive sharings of a base type

use ark_mpc::{algebra::AuthenticatedScalarResult, network::PartyId};
use async_trait::async_trait;
use constants::{AuthenticatedScalar, Scalar, ScalarField, SystemCurve, SystemCurveGroup};
use futures::future::join_all;
use itertools::Itertools;
use mpc_plonk::{
    errors::PlonkError,
    multiprover::proof_system::{
        CollaborativeProof, MpcCircuit, MpcPlonkCircuit as GenericMpcPlonkCircuit,
        MultiproverPlonkKzgSnark,
    },
    proof_system::{
        structs::{Proof, ProvingKey, VerifyingKey},
        PlonkKzgSnark, UniversalSNARK,
    },
    transcript::SolidityTranscript,
};
use mpc_relation::{
    constraint_system::Circuit, ConstraintSystem, PlonkCircuit as GenericPlonkCircuit, Variable,
};
use num_bigint::BigUint;
use rand::thread_rng;
use renegade_crypto::fields::{biguint_to_scalar, scalar_to_biguint, scalar_to_u64};

use crate::{
    errors::{MpcError, ProverError, VerifierError},
    Fabric, MpcPlonkCircuit, PlonkCircuit,
};

/// The error message emitted when too few scalars are given
const ERR_TOO_FEW_SCALARS: &str = "from_scalars: Invalid number of scalars";
/// The error message emitted when too few variables are given
const ERR_TOO_FEW_VARS: &str = "from_vars: Invalid number of variables";

// ---------------
// | Type Traits |
// ---------------

/// Implementing types are base (application level) types that define
/// serialization to/from `Scalars`
///
/// Variable, MPC, etc types are implemented automatically from serialization
/// and deserialization
#[async_trait]
pub trait BaseType: Clone {
    /// Convert the base type to its serialized scalar representation in the
    /// circuit
    fn to_scalars(&self) -> Vec<Scalar>;
    /// Convert from a serialized scalar representation to the base type
    fn from_scalars<I: Iterator<Item = Scalar>>(i: &mut I) -> Self;

    /// Share the plaintext value with the counterparty over an MPC fabric
    ///
    /// This method is added to the `BaseType` trait for maximum flexibility, so
    /// that types may be shared without requiring them to implement the
    /// full `MpcBaseType` trait
    async fn share_public(&self, owning_party: PartyId, fabric: Fabric) -> Self {
        let self_scalars = self.to_scalars();
        let res_scalars = fabric
            .batch_share_plaintext(self_scalars, owning_party)
            .await;

        Self::from_scalars(&mut res_scalars.into_iter())
    }
}

// --- Singleprover Circuit Traits --- //

/// The base type that may be allocated in a single-prover circuit
pub trait CircuitBaseType: BaseType {
    /// The variable type for this base type
    type VarType: CircuitVarType;

    /// Allocate the base type in the proof system and return the variable type
    /// associate with the base type
    fn create_witness(&self, circuit: &mut PlonkCircuit) -> Self::VarType {
        let scalars: Vec<Scalar> = self.clone().to_scalars();
        let mut vars = scalars
            .into_iter()
            .map(|s| circuit.create_variable(s.inner()).unwrap());

        Self::VarType::from_vars(&mut vars)
    }

    /// Allocate the base type as a public variable in a constraint system
    fn create_public_var(&self, circuit: &mut PlonkCircuit) -> Self::VarType {
        let scalars: Vec<Scalar> = self.clone().to_scalars();
        let mut vars = scalars
            .into_iter()
            .map(|s| circuit.create_public_variable(s.inner()).unwrap());

        Self::VarType::from_vars(&mut vars)
    }
}

/// Implementing types are variable types that may appear in constraints in
/// a constraint system
pub trait CircuitVarType: Clone {
    /// The base type that this variable type is a representation of
    type BaseType: CircuitBaseType;

    /// Convert to a collection of serialized variables for the type
    fn to_vars(&self) -> Vec<Variable>;
    /// Convert from an iterable of variables representing the serialized type
    fn from_vars<I: Iterator<Item = Variable>>(i: &mut I) -> Self;
    /// Evaluate the variable type in the constraint system to retrieve the base
    /// type
    fn eval(&self, circuit: &PlonkCircuit) -> Self::BaseType {
        let vars = self.to_vars();
        let mut scalars = vars
            .into_iter()
            .map(|v| circuit.witness(v).unwrap())
            .map(Scalar::new);

        Self::BaseType::from_scalars(&mut scalars)
    }
    /// Evaluate the variable type in a multiprover constraint system to
    /// retrieve the base type
    fn eval_multiprover<T: MultiproverCircuitBaseType>(&self, circuit: &MpcPlonkCircuit) -> T {
        let vars = self.to_vars();
        let mut scalars = vars.into_iter().map(|v| circuit.witness(v).unwrap());

        T::from_authenticated_scalars(&mut scalars)
    }
}

// --- MPC Circuit Traits --- //

/// A base type for allocating into an MPC network
pub trait MpcBaseType: BaseType {
    /// The type that results from allocating the base type into an MPC network
    type AllocatedType: MpcType;

    /// Allocates the base type in the network as a shared value
    fn allocate(&self, sender: PartyId, fabric: &Fabric) -> Self::AllocatedType {
        let self_scalars = self.to_scalars();
        let values = fabric.batch_share_scalar(self_scalars, sender);

        Self::AllocatedType::from_authenticated_scalars(&mut values.into_iter())
    }
}

/// An implementing type is the representation of a `BaseType` in an MPC circuit
/// *outside* of a multiprover constraint system
#[async_trait]
pub trait MpcType: Clone {
    /// The native type when the value is opened out of a circuit
    type NativeType: BaseType;
    /// Get a reference to the underlying MPC fabric
    fn fabric(&self) -> &Fabric;
    /// Convert from an iterable of authenticated scalars: scalars that have
    /// been allocated in an MPC fabric
    fn from_authenticated_scalars<I: Iterator<Item = AuthenticatedScalar>>(i: &mut I) -> Self;
    /// Convert to a vector of authenticated scalars
    fn to_authenticated_scalars(&self) -> Vec<AuthenticatedScalar>;

    /// Opens the shared type without authenticating
    async fn open(self) -> Result<Self::NativeType, MpcError> {
        let self_scalars = self.to_authenticated_scalars();
        let opened_scalars = join_all(AuthenticatedScalarResult::open_batch(&self_scalars)).await;

        Ok(Self::NativeType::from_scalars(
            &mut opened_scalars.into_iter(),
        ))
    }

    /// Opens the shared type and authenticates the result
    async fn open_and_authenticate(self) -> Result<Self::NativeType, MpcError> {
        let self_scalars = self.to_authenticated_scalars();
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

/// A base type for allocating within a multiprover constraint system
pub trait MultiproverCircuitBaseType: MpcType {
    /// The base type of the multiprover circuit type
    type BaseType: CircuitBaseType;
    /// The constraint system variable type that results when
    /// allocating the base type in a multiprover constraint system
    type VarType: CircuitVarType;

    /// Commit to the value in a multiprover constraint system
    #[allow(clippy::type_complexity)]
    fn create_shared_witness(
        &self,
        circuit: &mut MpcPlonkCircuit,
    ) -> Result<Self::VarType, MpcError> {
        let self_scalars = self.clone().to_authenticated_scalars();
        let mut vars = self_scalars
            .into_iter()
            .map(|s| circuit.create_variable(s).unwrap());

        Ok(Self::VarType::from_vars(&mut vars))
    }
}

// --- Secret Share Types --- //

/// Implementing types may be secret shared via the `SecretShareType` trait
/// below
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
    /// We do not require that shares implement `Add` because we wish to default
    /// implement traits on generics types (e.g. `[T]` where `T:
    /// SecretShareType`). Requiring an additional trait bound on `T` would
    /// prevent this.
    fn add_shares(&self, rhs: &Self) -> Self::Base {
        let mut res_scalars = self
            .to_scalars()
            .into_iter()
            .zip(rhs.to_scalars())
            .map(|(s1, s2)| s1 + s2);

        Self::Base::from_scalars(&mut res_scalars)
    }
}

/// Implementing types represent a secret share allocated in a constraint system
pub trait SecretShareVarType: Sized + CircuitVarType {
    /// The base type that this secret share is a representation of
    type Base: CircuitVarType;

    /// Apply an additive blinder to each element of the secret shares
    fn blind(self, blinder: Variable, circuit: &mut PlonkCircuit) -> Self {
        let mut res_vars = self
            .to_vars()
            .into_iter()
            .map(|v| circuit.add(v, blinder).unwrap());

        Self::from_vars(&mut res_vars)
    }

    /// Remove an additive blind from each element of the secret shares
    fn unblind(self, blinder: Variable, circuit: &mut PlonkCircuit) -> Self {
        let mut res_vars = self
            .to_vars()
            .into_iter()
            .map(|v| circuit.sub(v, blinder).unwrap());

        Self::from_vars(&mut res_vars)
    }

    /// Add two sets of shares to recover the base type
    ///
    /// We do not require that shares implement `Add` because we wish to default
    /// implement traits on generics types (e.g. `[T]` where `T:
    /// SecretShareType`). Requiring an additional trait bound on `T` would
    /// prevent this.
    fn add_shares<R>(&self, rhs: &R, circuit: &mut PlonkCircuit) -> Self::Base
    where
        R: SecretShareVarType,
    {
        let mut res_vars = self
            .to_vars()
            .into_iter()
            .zip(rhs.to_vars())
            .map(|(v1, v2)| circuit.add(v1, v2).unwrap());

        Self::Base::from_vars(&mut res_vars)
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
    type VarType = Variable;
}

impl CircuitBaseType for u64 {
    type VarType = Variable;
}

impl CircuitBaseType for BigUint {
    type VarType = Variable;
}

impl CircuitBaseType for () {
    type VarType = ();
}

impl<const N: usize, T: CircuitBaseType> CircuitBaseType for [T; N] {
    type VarType = [T::VarType; N];
}

impl CircuitVarType for Variable {
    type BaseType = Scalar;

    fn to_vars(&self) -> Vec<Variable> {
        vec![*self]
    }

    fn from_vars<I: Iterator<Item = Variable>>(i: &mut I) -> Self {
        i.next().unwrap()
    }
}

impl CircuitVarType for () {
    type BaseType = ();

    fn from_vars<I: Iterator<Item = Variable>>(_: &mut I) -> Self {}

    fn to_vars(&self) -> Vec<Variable> {
        vec![]
    }
}

impl<const N: usize, T: CircuitVarType> CircuitVarType for [T; N] {
    type BaseType = [T::BaseType; N];

    fn to_vars(&self) -> Vec<Variable> {
        self.iter().flat_map(|x| x.to_vars()).collect()
    }

    fn from_vars<I: Iterator<Item = Variable>>(i: &mut I) -> Self {
        (0..N)
            .map(|_| T::from_vars(i))
            .collect_vec()
            .try_into()
            .map_err(|_| ERR_TOO_FEW_VARS)
            .unwrap()
    }
}

// --- MPC Circuit Trait Impls --- //

impl MpcBaseType for Scalar {
    type AllocatedType = AuthenticatedScalar;
}

impl MpcBaseType for u64 {
    type AllocatedType = AuthenticatedScalar;
}

impl MpcBaseType for BigUint {
    type AllocatedType = AuthenticatedScalar;
}

impl MpcBaseType for () {
    type AllocatedType = ();
}

impl<const L: usize, T: MpcBaseType> MpcBaseType for [T; L] {
    type AllocatedType = [T::AllocatedType; L];
}

impl MpcType for AuthenticatedScalar {
    type NativeType = Scalar;

    fn fabric(&self) -> &Fabric {
        self.fabric()
    }

    fn from_authenticated_scalars<I: Iterator<Item = AuthenticatedScalar>>(i: &mut I) -> Self {
        i.next().unwrap()
    }

    fn to_authenticated_scalars(&self) -> Vec<AuthenticatedScalar> {
        vec![self.clone()]
    }
}

impl MpcType for () {
    type NativeType = ();

    fn fabric(&self) -> &Fabric {
        unimplemented!()
    }

    fn from_authenticated_scalars<I: Iterator<Item = AuthenticatedScalar>>(_: &mut I) -> Self {}

    fn to_authenticated_scalars(&self) -> Vec<AuthenticatedScalar> {
        vec![]
    }
}

impl<const L: usize, T: MpcType> MpcType for [T; L] {
    type NativeType = [T::NativeType; L];

    fn fabric(&self) -> &Fabric {
        self[0].fabric()
    }

    fn from_authenticated_scalars<I: Iterator<Item = AuthenticatedScalar>>(i: &mut I) -> Self {
        (0..L)
            .map(|_| T::from_authenticated_scalars(i))
            .collect_vec()
            .try_into()
            .map_err(|_| "from_authenticated_scalars: Invalid number of authenticated scalars")
            .unwrap()
    }

    fn to_authenticated_scalars(&self) -> Vec<AuthenticatedScalar> {
        self.iter()
            .flat_map(|x| x.to_authenticated_scalars())
            .collect_vec()
    }
}

// --- Multiprover Circuit Trait Impls --- //

impl MultiproverCircuitBaseType for AuthenticatedScalar {
    type BaseType = Scalar;
    type VarType = Variable;
}

impl MultiproverCircuitBaseType for () {
    type BaseType = ();
    type VarType = ();
}

impl<const L: usize, T: MultiproverCircuitBaseType> MultiproverCircuitBaseType for [T; L] {
    type BaseType = [T::BaseType; L];
    type VarType = [T::VarType; L];
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

impl SecretShareVarType for Variable {
    type Base = Variable;
}

impl<const N: usize, T: SecretShareVarType> SecretShareVarType for [T; N] {
    type Base = [T::Base; N];
}

// ------------------
// | Circuit Traits |
// ------------------

/// Defines the abstraction of a Circuit
///
/// A circuit represents a provable unit, a complete NP statement that takes as
/// input a series of values, commits to them, and applies constraints
///
/// The input types are broken out into the witness type and the statement type.
/// The witness type represents the secret witness that the prover has access to
/// but that the verifier does not. The statement is the set of public inputs
/// and any other circuit meta-parameters that both prover and verifier have
/// access to
pub trait SingleProverCircuit {
    /// The witness type, given only to the prover, which generates a blinding
    /// commitment that can be given to the verifier
    type Witness: CircuitBaseType;
    /// The statement type, given to both the prover and verifier, parameterizes
    /// the underlying NP statement being proven
    type Statement: CircuitBaseType;

    /// Apply the constraints of the circuit to a given constraint system
    fn apply_constraints(
        witness_var: <Self::Witness as CircuitBaseType>::VarType,
        statement_var: <Self::Statement as CircuitBaseType>::VarType,
        cs: &mut PlonkCircuit,
    ) -> Result<(), PlonkError>;

    /// Generate a proof of the statement represented by the circuit
    ///
    /// Returns both the commitment to the inputs, as well as the proof itself
    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        pk: &ProvingKey<SystemCurve>,
        mut circuit: PlonkCircuit,
    ) -> Result<Proof<SystemCurve>, ProverError> {
        // Allocate the witness and statement in the constraint system
        let witness_var = witness.create_witness(&mut circuit);
        let statement_var = statement.create_public_var(&mut circuit);

        // Apply the constraints
        Self::apply_constraints(witness_var, statement_var, &mut circuit)
            .map_err(ProverError::Plonk)?;

        // Generate the proof
        let mut rng = thread_rng();
        PlonkKzgSnark::prove::<_, _, SolidityTranscript>(
            &mut rng, &circuit, pk, None, // extra_init_msg
        )
        .map_err(ProverError::Plonk)
    }

    /// Verify a proof of the statement represented by the circuit
    ///
    /// The verifier has access to the statement variables, but not the witness
    fn verify(
        statement: Self::Statement,
        proof: Proof<SystemCurve>,
        vk: &VerifyingKey<SystemCurve>,
    ) -> Result<(), VerifierError> {
        // Allocate the statement in the constraint system
        let statement_vals = statement
            .to_scalars()
            .iter()
            .map(Scalar::inner)
            .collect_vec();

        // Verify the proof
        PlonkKzgSnark::verify::<SolidityTranscript>(
            vk,
            &statement_vals,
            &proof,
            None, // extra_init_msg
        )
        .map_err(VerifierError::Plonk)
    }
}

/// Defines the abstraction of a Circuit that is evaluated in a multiprover
/// setting
///
/// A circuit represents a provable unit, a complete NP statement that takes as
/// input a series of values, commits to them, and applies constraints
///
/// The input types are broken out into the witness type and the statement type.
/// The witness type represents the secret witness that the prover has access to
/// but that the verifier does not. The statement is the set of public inputs
/// and any other circuit meta-parameters that both prover and verifier have
/// access to
pub trait MultiProverCircuit {
    /// The witness type, given only to the prover, which generates a blinding
    /// commitment that can be given to the verifier
    type Witness: MultiproverCircuitBaseType;
    /// The statement type, given to both the prover and verifier, parameterizes
    /// the underlying NP statement being proven
    type Statement: Clone + MultiproverCircuitBaseType + MpcType;

    /// The single-prover circuit analog that this multiprover circuit is
    /// derived from, used for verification
    type BaseCircuit: SingleProverCircuit<
        Witness = <Self::Witness as MultiproverCircuitBaseType>::BaseType,
        Statement = <Self::Statement as MultiproverCircuitBaseType>::BaseType,
    >;

    /// Apply the constraints of the circuit to a multiprover constraint system
    fn apply_constraints_multiprover(
        witness: <Self::Witness as MultiproverCircuitBaseType>::VarType,
        statement: <Self::Statement as MultiproverCircuitBaseType>::VarType,
        fabric: &Fabric,
        circuit: &mut MpcPlonkCircuit,
    ) -> Result<(), ProverError>;

    /// Generate a proof of the statement represented by the circuit
    ///
    /// Returns both the commitment to the inputs, as well as the proof itself
    #[allow(clippy::type_complexity)]
    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        pk: &ProvingKey<SystemCurve>,
        fabric: Fabric,
        circuit: &mut MpcPlonkCircuit,
    ) -> Result<CollaborativeProof<SystemCurve>, ProverError> {
        // Allocate the witness and statement in the constraint system
        let witness_var = witness
            .create_shared_witness(circuit)
            .map_err(ProverError::Mpc)?;
        let statement_var = statement
            .create_shared_witness(circuit)
            .map_err(ProverError::Mpc)?;

        // Apply the constraints
        Self::apply_constraints_multiprover(witness_var, statement_var, &fabric, circuit)?;

        // Generate the proof
        MultiproverPlonkKzgSnark::prove(circuit, pk, fabric).map_err(ProverError::Plonk)
    }

    /// Verify a proof of the statement represented by the circuit
    ///
    /// The verifier has access to the statement variables, but only hiding (and
    /// binding) commitments to the witness variables
    ///
    /// The verifier in this case provides the same interface as the single
    /// prover case. The proof and commitments to the witness should be
    /// "opened" by having the MPC parties reconstruct the underlying secret
    /// from their shares. Then the opened proof and commitments can be
    /// passed to the verifier.
    fn verify(
        statement: <Self::Statement as MultiproverCircuitBaseType>::BaseType,
        proof: Proof<SystemCurve>,
        vk: &VerifyingKey<SystemCurve>,
    ) -> Result<(), VerifierError> {
        Self::BaseCircuit::verify(statement, proof, vk)
    }
}
