//! Gadgets for rotating state elements

use circuit_types::{
    PlonkCircuit,
    merkle::MerkleOpeningVar,
    state_wrapper::{PartialCommitmentVar, StateWrapperVar},
    traits::{CircuitBaseType, SecretShareBaseType},
};
use mpc_relation::{Variable, errors::CircuitError, traits::Circuit};

use crate::zk_gadgets::{
    comparators::EqGadget,
    merkle::PoseidonMerkleHashGadget,
    v2::state_primitives::{CommitmentGadget, NullifierGadget, RecoveryIdGadget},
};

/// The arguments to a state element rotation gadget
pub struct StateElementRotationArgs<V, const MERKLE_HEIGHT: usize>
where
    V: CircuitBaseType + SecretShareBaseType,
    V::ShareType: CircuitBaseType,
{
    // --- Old Version --- //
    /// The old version of the state element
    pub old_version: StateWrapperVar<V>,
    /// The old private share of the state element
    pub old_private_share: <V::ShareType as CircuitBaseType>::VarType,
    /// The opening of the old version to the Merkle root
    pub old_opening: MerkleOpeningVar<MERKLE_HEIGHT>,
    /// The Merkle root to which the old version opens
    pub merkle_root: Variable,
    /// The nullifier of the old version
    pub nullifier: Variable,

    // --- New Version --- //
    /// The new version of the state element
    pub new_version: StateWrapperVar<V>,
    /// The new private share of the state element
    pub new_private_share: <V::ShareType as CircuitBaseType>::VarType,
    /// The commitment to the new version of the state element
    pub new_commitment: Variable,
    /// The new recovery identifier of the state element
    pub recovery_id: Variable,
}

/// The arguments to a state element rotation gadget with partial commitment
pub struct StateElementRotationArgsWithPartialCommitment<V, const MERKLE_HEIGHT: usize>
where
    V: CircuitBaseType + SecretShareBaseType,
    V::ShareType: CircuitBaseType,
{
    // --- Old Version --- //
    /// The old version of the state element
    pub old_version: StateWrapperVar<V>,
    /// The old private share of the state element
    pub old_private_share: <V::ShareType as CircuitBaseType>::VarType,
    /// The opening of the old version to the Merkle root
    pub old_opening: MerkleOpeningVar<MERKLE_HEIGHT>,
    /// The Merkle root to which the old version opens
    pub merkle_root: Variable,
    /// The nullifier of the old version
    pub nullifier: Variable,

    // --- New Version --- //
    /// The new version of the state element
    pub new_version: StateWrapperVar<V>,
    /// The new private share of the state element
    pub new_private_share: <V::ShareType as CircuitBaseType>::VarType,
    /// The partial commitment to the new version of the state element
    pub new_partial_commitment: PartialCommitmentVar,
    /// The new recovery identifier of the state element
    pub recovery_id: Variable,
}

/// A gadget for rotating a version of a state element
pub struct StateElementRotationGadget<const MERKLE_HEIGHT: usize>;
impl<const MERKLE_HEIGHT: usize> StateElementRotationGadget<MERKLE_HEIGHT> {
    /// Rotate a version of the state element to the next version
    ///
    /// This involves:
    /// 1. Compute a commitment to the old version and verify a Merkle opening
    ///    for it
    /// 2. Compute a nullifier for the old version
    /// 3. Compute the recovery identifier for the new version
    /// 4. Compute a commitment to the new version of the state element
    pub fn rotate_version<V>(
        args: &mut StateElementRotationArgs<V, MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError>
    where
        V: CircuitBaseType + SecretShareBaseType,
        V::ShareType: CircuitBaseType,
    {
        // Compute the recovery identifier for the new version and constrain it to the
        // given value
        let new_recovery_id = RecoveryIdGadget::compute_recovery_id(&mut args.new_version, cs)?;
        cs.enforce_equal(new_recovery_id, args.recovery_id)?;

        let (old_commitment, new_commitment) =
            CommitmentGadget::compute_commitments_with_shared_prefix::<V>(
                &args.old_private_share,
                &args.old_version,
                &args.new_private_share,
                &args.new_version,
                cs,
            )?;
        cs.enforce_equal(new_commitment, args.new_commitment)?;

        // Verify a Merkle opening for the old version
        PoseidonMerkleHashGadget::compute_and_constrain_root_prehashed(
            old_commitment,
            &args.old_opening,
            args.merkle_root,
            cs,
        )?;

        // Compute a nullifier for the old version
        let old_nullifier = NullifierGadget::compute_nullifier(&args.old_version, cs)?;
        cs.enforce_equal(old_nullifier, args.nullifier)?;

        Ok(())
    }

    /// Rotate a version of the state element to the next version with a partial
    /// commitment for the new version of the state element
    ///
    /// This involves:
    /// 1. Compute a commitment to the old version and verify a Merkle opening
    ///    for it
    /// 2. Compute a nullifier for the old version
    /// 3. Compute the recovery identifier for the new version
    /// 4. Compute a partial commitment to the new version of the state element
    pub fn rotate_version_with_partial_commitment<V>(
        num_shares: usize,
        args: &mut StateElementRotationArgsWithPartialCommitment<V, MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError>
    where
        V: CircuitBaseType + SecretShareBaseType,
        V::ShareType: CircuitBaseType,
    {
        // Compute the recovery identifier for the new version and constrain it to the
        // given value
        let new_recovery_id = RecoveryIdGadget::compute_recovery_id(&mut args.new_version, cs)?;
        cs.enforce_equal(new_recovery_id, args.recovery_id)?;

        let (old_commitment, new_partial_commitment) =
            CommitmentGadget::compute_partial_commitments_with_shared_prefix::<V>(
                num_shares,
                &args.old_private_share,
                &args.old_version,
                &args.new_private_share,
                &args.new_version,
                cs,
            )?;
        EqGadget::constrain_eq(&new_partial_commitment, &args.new_partial_commitment, cs)?;

        // Verify a Merkle opening for the old version
        PoseidonMerkleHashGadget::compute_and_constrain_root_prehashed(
            old_commitment,
            &args.old_opening,
            args.merkle_root,
            cs,
        )?;

        // Compute a nullifier for the old version
        let old_nullifier = NullifierGadget::compute_nullifier(&args.old_version, cs)?;
        cs.enforce_equal(old_nullifier, args.nullifier)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use circuit_macros::circuit_type;
    use circuit_types::fixed_point::FixedPoint;
    use circuit_types::merkle::MerkleOpening;
    use circuit_types::state_wrapper::{PartialCommitment, StateWrapper};
    use circuit_types::{PlonkCircuit, traits::*};
    use constants::{Scalar, ScalarField};
    use eyre::Result;
    use mpc_relation::{Variable, traits::Circuit};
    use rand::{Rng, thread_rng};
    use std::ops::Add;

    use crate::test_helpers::{create_merkle_opening, create_random_state_wrapper};

    use super::*;

    // -----------
    // | Helpers |
    // -----------

    // --- Test Struct --- //

    /// The height of the Merkle tree to test on
    const MERKLE_HEIGHT: usize = 10;

    /// A test state element
    #[derive(Clone)]
    #[circuit_type(singleprover_circuit, secret_share)]
    struct TestStateElement {
        /// A scalar value
        pub scalar: Scalar,
        /// An array of scalars
        pub array: [Scalar; 2],
        /// Nested type
        pub nested: TestNestedStateElement,
    }

    /// A test nested state element
    #[derive(Clone)]
    #[circuit_type(singleprover_circuit, secret_share)]
    struct TestNestedStateElement {
        /// A fixed point value
        fp: FixedPoint,
        /// A scalar value
        scalar: Scalar,
    }

    /// A native version of the state element rotation args
    #[derive(Clone)]
    struct NativeStateElementRotationArgs<V, const MERKLE_HEIGHT: usize>
    where
        V: CircuitBaseType + SecretShareBaseType,
        V::ShareType: CircuitBaseType,
    {
        /// The old version of the state element
        old_version: StateWrapper<V>,
        /// The old private share of the state element
        old_private_share: V::ShareType,
        /// The opening of the old version to the Merkle root
        old_opening: MerkleOpening<MERKLE_HEIGHT>,
        /// The Merkle root to which the old version opens
        merkle_root: Scalar,
        /// The nullifier of the old version
        nullifier: Scalar,
        /// The new version of the state element
        new_version: StateWrapper<V>,
        /// The new private share of the state element
        new_private_share: V::ShareType,
        /// The commitment to the new version of the state element
        new_commitment: Scalar,
        /// The new recovery identifier of the state element
        recovery_id: Scalar,
    }

    /// A native version of the state element rotation args with partial
    /// commitment
    #[derive(Clone)]
    struct NativeStateElementRotationArgsWithPartialCommitment<V, const MERKLE_HEIGHT: usize>
    where
        V: CircuitBaseType + SecretShareBaseType,
        V::ShareType: CircuitBaseType,
    {
        /// The old version of the state element
        old_version: StateWrapper<V>,
        /// The old private share of the state element
        old_private_share: V::ShareType,
        /// The opening of the old version to the Merkle root
        old_opening: MerkleOpening<MERKLE_HEIGHT>,
        /// The Merkle root to which the old version opens
        merkle_root: Scalar,
        /// The nullifier of the old version
        nullifier: Scalar,
        /// The new version of the state element
        new_version: StateWrapper<V>,
        /// The new private share of the state element
        new_private_share: V::ShareType,
        /// The partial commitment to the new version of the state element
        new_partial_commitment: PartialCommitment,
        /// The new recovery identifier of the state element
        recovery_id: Scalar,
    }

    // --- Test Helpers --- //

    /// Allocate a random scalar in the constraint system and return its pointer
    fn allocate_random_scalar(cs: &mut PlonkCircuit) -> Variable {
        let mut rng = thread_rng();
        let value = Scalar::random(&mut rng);
        value.create_witness(cs)
    }

    /// Create a rotation bundle and allocate it in a constraint system
    fn create_and_allocate_rotation_bundle()
    -> (PlonkCircuit, StateElementRotationArgs<TestStateElement, MERKLE_HEIGHT>) {
        let bundle = create_rotation_bundle();
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let args = StateElementRotationArgs {
            old_version: bundle.old_version.create_witness(&mut cs),
            old_private_share: bundle.old_private_share.create_witness(&mut cs),
            old_opening: bundle.old_opening.create_witness(&mut cs),
            merkle_root: bundle.merkle_root.create_witness(&mut cs),
            nullifier: bundle.nullifier.create_witness(&mut cs),
            new_version: bundle.new_version.create_witness(&mut cs),
            new_private_share: bundle.new_private_share.create_witness(&mut cs),
            new_commitment: bundle.new_commitment.create_witness(&mut cs),
            recovery_id: bundle.recovery_id.create_witness(&mut cs),
        };

        (cs, args)
    }

    /// Create a rotation bundle with partial commitment and allocate it in a
    /// constraint system
    fn create_and_allocate_rotation_bundle_with_partial_commitment(
        num_shares: usize,
    ) -> (
        PlonkCircuit,
        StateElementRotationArgsWithPartialCommitment<TestStateElement, MERKLE_HEIGHT>,
    ) {
        let bundle = create_rotation_bundle_with_partial_commitment(num_shares);
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let args = StateElementRotationArgsWithPartialCommitment {
            old_version: bundle.old_version.create_witness(&mut cs),
            old_private_share: bundle.old_private_share.create_witness(&mut cs),
            old_opening: bundle.old_opening.create_witness(&mut cs),
            merkle_root: bundle.merkle_root.create_witness(&mut cs),
            nullifier: bundle.nullifier.create_witness(&mut cs),
            new_version: bundle.new_version.create_witness(&mut cs),
            new_private_share: bundle.new_private_share.create_witness(&mut cs),
            new_partial_commitment: bundle.new_partial_commitment.create_witness(&mut cs),
            recovery_id: bundle.recovery_id.create_witness(&mut cs),
        };

        (cs, args)
    }

    /// Generate a valid rotation bundle
    fn create_rotation_bundle() -> NativeStateElementRotationArgs<TestStateElement, MERKLE_HEIGHT> {
        let old_elt = create_random_state_element();
        let new_elt = create_random_state_element();
        let old_version = create_random_state_wrapper(old_elt.clone());
        let mut new_version = create_random_state_wrapper(new_elt.clone());
        let new_version_copy = new_version.clone();

        // Compute commitments to the old and new shares
        let new_recovery_id = new_version.compute_recovery_id();
        let old_share_commitment = old_version.compute_commitment();
        let new_share_commitment = new_version.compute_commitment();

        // Create an opening for the old version
        let (root, old_opening) = create_merkle_opening(old_share_commitment);

        // Compute the nullifier for the old version
        let old_nullifier = old_version.compute_nullifier();
        NativeStateElementRotationArgs {
            old_version: old_version.clone(),
            old_private_share: old_version.private_shares(),
            old_opening,
            merkle_root: root,
            nullifier: old_nullifier,
            new_version: new_version_copy,
            new_private_share: new_version.private_shares(),
            new_commitment: new_share_commitment,
            recovery_id: new_recovery_id,
        }
    }

    /// Generate a valid rotation bundle with partial commitment
    fn create_rotation_bundle_with_partial_commitment(
        num_shares: usize,
    ) -> NativeStateElementRotationArgsWithPartialCommitment<TestStateElement, MERKLE_HEIGHT> {
        let old_elt = create_random_state_element();
        let new_elt = create_random_state_element();
        let old_version = create_random_state_wrapper(old_elt.clone());
        let mut new_version = create_random_state_wrapper(new_elt.clone());
        let new_version_copy = new_version.clone();

        // Compute commitments to the old and new shares
        let new_recovery_id = new_version.compute_recovery_id();
        let old_share_commitment = old_version.compute_commitment();
        let new_partial_commitment = new_version.compute_partial_commitment(num_shares);

        // Create an opening for the old version
        let (root, old_opening) = create_merkle_opening(old_share_commitment);

        // Compute the nullifier for the old version
        let old_nullifier = old_version.compute_nullifier();
        NativeStateElementRotationArgsWithPartialCommitment {
            old_version: old_version.clone(),
            old_private_share: old_version.private_shares(),
            old_opening,
            merkle_root: root,
            nullifier: old_nullifier,
            new_version: new_version_copy,
            new_private_share: new_version.private_shares(),
            new_partial_commitment,
            recovery_id: new_recovery_id,
        }
    }

    /// Create a random state element
    fn create_random_state_element() -> TestStateElement {
        let mut rng = thread_rng();
        TestStateElement {
            scalar: Scalar::random(&mut rng),
            array: [Scalar::random(&mut rng), Scalar::random(&mut rng)],
            nested: create_random_nested_state_element(),
        }
    }

    /// Create a random nested state element
    fn create_random_nested_state_element() -> TestNestedStateElement {
        let mut rng = thread_rng();
        TestNestedStateElement {
            fp: FixedPoint::from_f64_round_down(rng.r#gen()),
            scalar: Scalar::random(&mut rng),
        }
    }

    // ---------
    // | Tests |
    // ---------

    /// Test a valid rotation bundle
    #[test]
    #[allow(non_snake_case)]
    fn test_rotation_bundle__valid() -> Result<()> {
        let (mut cs, mut args) = create_and_allocate_rotation_bundle();
        StateElementRotationGadget::rotate_version(&mut args, &mut cs)?;

        cs.check_circuit_satisfiability(&[])?;
        Ok(())
    }

    /// Test a valid rotation bundle with partial commitment
    #[test]
    #[allow(non_snake_case)]
    fn test_rotation_bundle_with_partial_commitment__valid() -> Result<()> {
        let mut rng = thread_rng();
        let num_shares = rng.gen_range(1..=TestStateElement::NUM_SCALARS);
        let (mut cs, mut args) =
            create_and_allocate_rotation_bundle_with_partial_commitment(num_shares);
        StateElementRotationGadget::rotate_version_with_partial_commitment(
            num_shares, &mut args, &mut cs,
        )?;

        cs.check_circuit_satisfiability(&[])?;
        Ok(())
    }

    /// Test an invalid root
    #[test]
    #[allow(non_snake_case)]
    fn test_rotation__invalid_merkle_proof() -> Result<()> {
        let (mut cs, mut args) = create_and_allocate_rotation_bundle();

        args.merkle_root = allocate_random_scalar(&mut cs);
        StateElementRotationGadget::rotate_version(&mut args, &mut cs)?;

        assert!(cs.check_circuit_satisfiability(&[]).is_err());
        Ok(())
    }

    /// Test a modified public share in the old version
    #[test]
    #[allow(non_snake_case)]
    fn test_rotation__modified_old_public_share() -> Result<()> {
        let mut rng = thread_rng();
        let (mut cs, mut args) = create_and_allocate_rotation_bundle();

        // Modify a random share
        let mut shares = args.old_version.public_share.to_vars();
        let random_index = rng.r#gen_range(0..shares.len());
        shares[random_index] = allocate_random_scalar(&mut cs);
        args.old_version.public_share =
            TestStateElementShareVar::from_vars(&mut shares.into_iter(), &mut cs);

        // Apply the constraints and check that they are not satisfied
        StateElementRotationGadget::rotate_version(&mut args, &mut cs)?;
        assert!(cs.check_circuit_satisfiability(&[]).is_err());
        Ok(())
    }

    /// Test a modified private share in the old version
    #[test]
    #[allow(non_snake_case)]
    fn test_rotation__modified_old_private_share() -> Result<()> {
        let mut rng = thread_rng();
        let (mut cs, mut args) = create_and_allocate_rotation_bundle();

        // Modify a random share
        let mut shares = args.old_private_share.to_vars();
        let random_index = rng.r#gen_range(0..shares.len());
        shares[random_index] = allocate_random_scalar(&mut cs);
        args.old_private_share =
            TestStateElementShareVar::from_vars(&mut shares.into_iter(), &mut cs);

        // Apply the constraints and check that they are not satisfied
        StateElementRotationGadget::rotate_version(&mut args, &mut cs)?;
        assert!(cs.check_circuit_satisfiability(&[]).is_err());
        Ok(())
    }

    /// Test a modified public share in the new version
    #[test]
    #[allow(non_snake_case)]
    fn test_rotation__modified_new_public_share() -> Result<()> {
        let mut rng = thread_rng();
        let (mut cs, mut args) = create_and_allocate_rotation_bundle();

        // Modify a random share
        let mut shares = args.new_version.public_share.to_vars();
        let random_index = rng.r#gen_range(0..shares.len());
        shares[random_index] = allocate_random_scalar(&mut cs);
        args.new_version.public_share =
            TestStateElementShareVar::from_vars(&mut shares.into_iter(), &mut cs);

        // Apply the constraints and check that they are not satisfied
        StateElementRotationGadget::rotate_version(&mut args, &mut cs)?;
        assert!(cs.check_circuit_satisfiability(&[]).is_err());
        Ok(())
    }

    /// Test a modified private share in the new version
    #[test]
    #[allow(non_snake_case)]
    fn test_rotation__modified_new_private_share() -> Result<()> {
        let mut rng = thread_rng();
        let (mut cs, mut args) = create_and_allocate_rotation_bundle();

        // Modify a random share
        let mut shares = args.new_private_share.to_vars();
        let random_index = rng.r#gen_range(0..shares.len());
        shares[random_index] = allocate_random_scalar(&mut cs);
        args.new_private_share =
            TestStateElementShareVar::from_vars(&mut shares.into_iter(), &mut cs);

        // Apply the constraints and check that they are not satisfied
        StateElementRotationGadget::rotate_version(&mut args, &mut cs)?;
        assert!(cs.check_circuit_satisfiability(&[]).is_err());
        Ok(())
    }

    /// Test an invalid nullifier
    #[test]
    #[allow(non_snake_case)]
    fn test_rotation__invalid_nullifier() -> Result<()> {
        let (mut cs, mut args) = create_and_allocate_rotation_bundle();

        args.nullifier = allocate_random_scalar(&mut cs);
        StateElementRotationGadget::rotate_version(&mut args, &mut cs)?;
        assert!(cs.check_circuit_satisfiability(&[]).is_err());
        Ok(())
    }

    /// Test an invalid recovery identifier
    #[test]
    #[allow(non_snake_case)]
    fn test_rotation__invalid_recovery_identifier() -> Result<()> {
        let (mut cs, mut args) = create_and_allocate_rotation_bundle();

        args.recovery_id = allocate_random_scalar(&mut cs);
        StateElementRotationGadget::rotate_version(&mut args, &mut cs)?;
        assert!(cs.check_circuit_satisfiability(&[]).is_err());
        Ok(())
    }
}
