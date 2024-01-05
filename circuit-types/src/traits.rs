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
use constants::{AuthenticatedScalar, Scalar, ScalarField, SystemCurve};
use futures::future::join_all;
use itertools::Itertools;
use mpc_plonk::{
    errors::PlonkError,
    multiprover::proof_system::{CollaborativeProof, MultiproverPlonkKzgSnark},
    proof_system::{
        structs::{Proof, ProvingKey, VerifyingKey},
        PlonkKzgSnark, UniversalSNARK,
    },
    transcript::SolidityTranscript,
};
use mpc_relation::{traits::Circuit, BoolVar, Variable};
use num_bigint::BigUint;
use rand::thread_rng;
use renegade_crypto::fields::{biguint_to_scalar, scalar_to_biguint, scalar_to_u64};
use std::sync::Arc;

use crate::{
    errors::{MpcError, ProverError, VerifierError},
    AuthenticatedBool, Fabric, MpcPlonkCircuit, PlonkCircuit,
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
    async fn share_public(&self, owning_party: PartyId, fabric: &Fabric) -> Self {
        let self_scalars = self.to_scalars();
        let res_scalars = fabric.batch_share_plaintext(self_scalars, owning_party).await;

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
        let vars =
            scalars.into_iter().map(|s| circuit.create_variable(s.inner()).unwrap()).collect_vec();

        Self::VarType::from_vars(&mut vars.into_iter(), circuit)
    }

    /// Allocate the base type as a public variable in a constraint system
    fn create_public_var(&self, circuit: &mut PlonkCircuit) -> Self::VarType {
        let scalars: Vec<Scalar> = self.clone().to_scalars();
        let vars = scalars
            .into_iter()
            .map(|s| circuit.create_public_variable(s.inner()).unwrap())
            .collect_vec();

        Self::VarType::from_vars(&mut vars.into_iter(), circuit)
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
    fn from_vars<I: Iterator<Item = Variable>, C: Circuit<ScalarField>>(
        i: &mut I,
        cs: &mut C,
    ) -> Self;
    /// Evaluate the variable type in the constraint system to retrieve the base
    /// type
    fn eval(&self, circuit: &PlonkCircuit) -> Self::BaseType {
        let vars = self.to_vars();
        let mut scalars = vars.into_iter().map(|v| circuit.witness(v).unwrap()).map(Scalar::new);

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
pub trait MpcType: Clone + Send + Sync {
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
    async fn open(&self) -> Result<Self::NativeType, MpcError> {
        let self_scalars = self.to_authenticated_scalars();
        let opened_scalars = join_all(AuthenticatedScalarResult::open_batch(&self_scalars)).await;

        Ok(Self::NativeType::from_scalars(&mut opened_scalars.into_iter()))
    }

    /// Opens the shared type and authenticates the result
    async fn open_and_authenticate(&self) -> Result<Self::NativeType, MpcError> {
        let self_scalars = self.to_authenticated_scalars();
        let opened_scalars =
            join_all(AuthenticatedScalarResult::open_authenticated_batch(&self_scalars))
                .await
                .into_iter()
                .collect::<Result<Vec<_>, _>>()
                .map_err(|err| MpcError::OpeningError(err.to_string()))?;

        Ok(Self::NativeType::from_scalars(&mut opened_scalars.into_iter()))
    }
}

// --- Multiprover Circuit Traits --- //

/// A base type for allocating within a multiprover constraint system
pub trait MultiproverCircuitBaseType: MpcType<NativeType = Self::BaseType> {
    /// The base type of the multiprover circuit type
    type BaseType: CircuitBaseType;
    /// The constraint system variable type that results when
    /// allocating the base type in a multiprover constraint system
    type VarType: CircuitVarType;

    /// Allocate the value in a multiprover constraint system as a witness
    /// element
    fn create_shared_witness(&self, circuit: &mut MpcPlonkCircuit) -> Self::VarType {
        let self_scalars = self.clone().to_authenticated_scalars();
        let vars =
            self_scalars.into_iter().map(|s| circuit.create_variable(s).unwrap()).collect_vec();

        Self::VarType::from_vars(&mut vars.into_iter(), circuit)
    }

    /// Allocate the value in a multiprover constraint system as a public
    /// element
    fn create_shared_public_var(&self, circuit: &mut MpcPlonkCircuit) -> Self::VarType {
        let self_scalars = self.clone().to_authenticated_scalars();
        let vars = self_scalars
            .into_iter()
            .map(|s| circuit.create_public_variable(s).unwrap())
            .collect_vec();

        Self::VarType::from_vars(&mut vars.into_iter(), circuit)
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
    fn blind(&self, blinder: Scalar) -> Self {
        let mut res_scalars = self.to_scalars().into_iter().map(|s| s + blinder);
        Self::from_scalars(&mut res_scalars)
    }

    /// Remove an additive blind from each element of the secret shares
    fn unblind(&self, blinder: Scalar) -> Self {
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
        let mut res_scalars =
            self.to_scalars().into_iter().zip(rhs.to_scalars()).map(|(s1, s2)| s1 + s2);

        Self::Base::from_scalars(&mut res_scalars)
    }
}

/// Implementing types represent a secret share allocated in a constraint system
pub trait SecretShareVarType: Sized + CircuitVarType {
    /// The base type that this secret share is a representation of
    type Base: CircuitVarType;

    /// Apply an additive blinder to each element of the secret shares
    fn blind(self, blinder: Variable, circuit: &mut PlonkCircuit) -> Self {
        let res_vars =
            self.to_vars().into_iter().map(|v| circuit.add(v, blinder).unwrap()).collect_vec();

        Self::from_vars(&mut res_vars.into_iter(), circuit)
    }

    /// Remove an additive blind from each element of the secret shares
    fn unblind(&self, blinder: Variable, circuit: &mut PlonkCircuit) -> Self {
        let res_vars =
            self.to_vars().into_iter().map(|v| circuit.sub(v, blinder).unwrap()).collect_vec();

        Self::from_vars(&mut res_vars.into_iter(), circuit)
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
        let res_vars = self
            .to_vars()
            .into_iter()
            .zip(rhs.to_vars())
            .map(|(v1, v2)| circuit.add(v1, v2).unwrap())
            .collect_vec();

        Self::Base::from_vars(&mut res_vars.into_iter(), circuit)
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

impl BaseType for bool {
    fn to_scalars(&self) -> Vec<Scalar> {
        vec![Scalar::from(*self as u8)]
    }

    fn from_scalars<I: Iterator<Item = Scalar>>(i: &mut I) -> Self {
        let val = i.next().unwrap();
        let is_bool = (val * (Scalar::one() - val)) == Scalar::zero();
        assert!(is_bool, "from_scalars: Invalid boolean scalar value");

        val == Scalar::one()
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

impl CircuitBaseType for bool {
    type VarType = BoolVar;

    fn create_public_var(&self, circuit: &mut PlonkCircuit) -> Self::VarType {
        circuit.create_public_boolean_variable(*self).unwrap()
    }

    fn create_witness(&self, circuit: &mut PlonkCircuit) -> Self::VarType {
        circuit.create_boolean_variable(*self).unwrap()
    }
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

    fn from_vars<I: Iterator<Item = Variable>, C: Circuit<ScalarField>>(
        i: &mut I,
        _cs: &mut C,
    ) -> Self {
        i.next().unwrap()
    }
}

impl CircuitVarType for BoolVar {
    type BaseType = bool;

    fn to_vars(&self) -> Vec<Variable> {
        vec![(*self).into()]
    }

    fn from_vars<I: Iterator<Item = Variable>, C: Circuit<ScalarField>>(
        i: &mut I,
        cs: &mut C,
    ) -> Self {
        let var = i.next().unwrap();
        cs.enforce_bool(var).unwrap();

        BoolVar::new_unchecked(var)
    }
}

impl CircuitVarType for () {
    type BaseType = ();

    fn from_vars<I: Iterator<Item = Variable>, C: Circuit<ScalarField>>(
        _: &mut I,
        _cs: &mut C,
    ) -> Self {
    }

    fn to_vars(&self) -> Vec<Variable> {
        vec![]
    }
}

impl<const N: usize, T: CircuitVarType> CircuitVarType for [T; N] {
    type BaseType = [T::BaseType; N];

    fn to_vars(&self) -> Vec<Variable> {
        self.iter().flat_map(|x| x.to_vars()).collect()
    }

    fn from_vars<I: Iterator<Item = Variable>, C: Circuit<ScalarField>>(
        i: &mut I,
        cs: &mut C,
    ) -> Self {
        (0..N)
            .map(|_| T::from_vars(i, cs))
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

impl MpcBaseType for bool {
    type AllocatedType = AuthenticatedBool;
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

impl MpcType for AuthenticatedBool {
    type NativeType = bool;

    fn fabric(&self) -> &Fabric {
        self.0.fabric()
    }

    fn from_authenticated_scalars<I: Iterator<Item = AuthenticatedScalar>>(i: &mut I) -> Self {
        AuthenticatedBool(i.next().unwrap())
    }

    fn to_authenticated_scalars(&self) -> Vec<AuthenticatedScalar> {
        vec![self.0.clone()]
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
        self.iter().flat_map(|x| x.to_authenticated_scalars()).collect_vec()
    }
}

// --- Multiprover Circuit Trait Impls --- //

impl MultiproverCircuitBaseType for AuthenticatedScalar {
    type BaseType = Scalar;
    type VarType = Variable;
}

impl MultiproverCircuitBaseType for AuthenticatedBool {
    type BaseType = bool;
    type VarType = BoolVar;
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

/// A helper to get the proving and verifying keys for a circuit in tests
#[cfg(feature = "test-helpers")]
pub fn setup_preprocessed_keys<C: SingleProverCircuit>(
) -> (ProvingKey<SystemCurve>, VerifyingKey<SystemCurve>) {
    use crate::test_helpers::TESTING_SRS;
    use std::iter;

    // Create a dummy circuit of correct topology to generate the keys
    // We use zero'd scalars here to give valid boolean types as well as scalar
    // types
    let mut scalars = iter::repeat(Scalar::zero());
    let witness = C::Witness::from_scalars(&mut scalars);
    let statement = C::Statement::from_scalars(&mut scalars);

    let mut cs = PlonkCircuit::new_turbo_plonk();
    let witness_var = witness.create_witness(&mut cs);
    let statement_var = statement.create_public_var(&mut cs);

    // Apply the constraints
    C::apply_constraints(witness_var, statement_var, &mut cs).unwrap();
    cs.finalize_for_arithmetization().unwrap();

    // Generate the keys
    PlonkKzgSnark::<SystemCurve>::preprocess(&TESTING_SRS, &cs).unwrap()
}

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
pub trait SingleProverCircuit: Sized {
    /// The witness type, given only to the prover, which generates a blinding
    /// commitment that can be given to the verifier
    type Witness: CircuitBaseType;
    /// The statement type, given to both the prover and verifier, parameterizes
    /// the underlying NP statement being proven
    type Statement: CircuitBaseType;

    /// The name of the circuit
    fn name() -> String;

    /// Returns a reference to the proving key for the circuit
    #[cfg(not(feature = "test-helpers"))]
    fn proving_key() -> Arc<ProvingKey<SystemCurve>> {
        unimplemented!("proving_key: Not yet implemented for non-test circuits")
    }

    /// Returns a reference to the proving key for the circuit
    ///
    /// Default implementation of the `proving_key` method for tests
    #[cfg(feature = "test-helpers")]
    fn proving_key() -> Arc<ProvingKey<SystemCurve>> {
        let (pk, _) = setup_preprocessed_keys::<Self>();
        Arc::new(pk)
    }

    /// Returns a reference to the verifying key for the circuit
    #[cfg(not(feature = "test-helpers"))]
    fn verifying_key() -> Arc<VerifyingKey<SystemCurve>> {
        unimplemented!("verifying_key: Not yet implemented for non-test circuits")
    }

    /// Returns a reference to the verifying key for the circuit
    ///
    /// Default implementation of the `verifying_key` method for tests
    #[cfg(feature = "test-helpers")]
    fn verifying_key() -> Arc<VerifyingKey<SystemCurve>> {
        let (_, vk) = setup_preprocessed_keys::<Self>();
        Arc::new(vk)
    }

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
    ) -> Result<Proof<SystemCurve>, ProverError> {
        // Allocate the witness and statement in the constraint system
        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let witness_var = witness.create_witness(&mut circuit);
        let statement_var = statement.create_public_var(&mut circuit);

        // Apply the constraints
        Self::apply_constraints(witness_var, statement_var, &mut circuit)
            .map_err(ProverError::Plonk)?;
        circuit.finalize_for_arithmetization().map_err(ProverError::Circuit)?;

        // Generate the proof
        let mut rng = thread_rng();
        let pk = Self::proving_key();
        PlonkKzgSnark::prove::<_, _, SolidityTranscript>(
            &mut rng, &circuit, &pk, None, // extra_init_msg
        )
        .map_err(ProverError::Plonk)
    }

    /// Verify a proof of the statement represented by the circuit
    ///
    /// The verifier has access to the statement variables, but not the witness
    fn verify(statement: Self::Statement, proof: &Proof<SystemCurve>) -> Result<(), VerifierError> {
        // Allocate the statement in the constraint system
        let statement_vals = statement.to_scalars().iter().map(Scalar::inner).collect_vec();

        // Verify the proof
        let vk = Self::verifying_key();
        PlonkKzgSnark::verify::<SolidityTranscript>(
            &vk,
            &statement_vals,
            proof,
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

    /// The name of the circuit
    fn name() -> String {
        Self::BaseCircuit::name()
    }

    /// Returns a reference to the proving key for the circuit
    fn proving_key() -> Arc<ProvingKey<SystemCurve>> {
        Self::BaseCircuit::proving_key()
    }

    /// Returns a reference to the verifying key for the circuit
    fn verifying_key() -> Arc<VerifyingKey<SystemCurve>> {
        Self::BaseCircuit::verifying_key()
    }

    /// Apply the constraints of the circuit to a multiprover constraint system
    fn apply_constraints_multiprover(
        witness: <Self::Witness as MultiproverCircuitBaseType>::VarType,
        statement: <Self::Statement as MultiproverCircuitBaseType>::VarType,
        fabric: &Fabric,
        circuit: &mut MpcPlonkCircuit,
    ) -> Result<(), PlonkError>;

    /// Generate a proof of the statement represented by the circuit
    ///
    /// Returns both the commitment to the inputs, as well as the proof itself
    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        fabric: Fabric,
    ) -> Result<CollaborativeProof<SystemCurve>, PlonkError> {
        // Allocate the witness and statement in the constraint system
        let mut circuit = MpcPlonkCircuit::new(fabric.clone());
        let witness_var = witness.create_shared_witness(&mut circuit);
        let statement_var = statement.create_shared_public_var(&mut circuit);

        // Apply the constraints
        Self::apply_constraints_multiprover(witness_var, statement_var, &fabric, &mut circuit)?;
        circuit.finalize_for_arithmetization().map_err(PlonkError::CircuitError)?;

        // Generate the proof
        let pk = Self::proving_key();
        MultiproverPlonkKzgSnark::prove(&circuit, &pk, fabric)
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
        proof: &Proof<SystemCurve>,
    ) -> Result<(), VerifierError> {
        Self::BaseCircuit::verify(statement, proof)
    }
}
