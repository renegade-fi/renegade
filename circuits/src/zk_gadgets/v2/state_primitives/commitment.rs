//! Gadget for computing commitments to state elements
//!
//! A commitment to a state element is defined in terms of:
//! - The public and private shares of the state element's data. These represent
//!   a stream-cipher encryption of the data
//! - The recovery stream state of the element
//! - The share stream state of the element
//!
//! We compute a commitment as:
//!     H(private_commitment || public_commitment)
//! Where:
//! - `private_commitment` is a commitment to the private shares of the state
//!   element and its CSPRNG states. This commitment is evaluated as:
//!
//!     H(private_shares || recovery_stream_state || share_stream_state)
//!
//! - `public_commitment` is a "resumable" commitment to the public shares of
//!   the state element. This commitment is evaluated as:
//!
//!     H(H(...(H(x_1, x_2), ...), x_{n-1}), x_n)
//!
//!   That is, we reset the hasher state after each element is hashed into it.
//!   This allows us to pre-commit to a partial set of the shares and then
//!   easily resume the commitment by hashing the remaining shares into the
//!   commitment

use circuit_types::{
    PlonkCircuit,
    state_wrapper::StateWrapperVar,
    traits::{CircuitBaseType, CircuitVarType, SecretShareBaseType},
};
use mpc_relation::{Variable, errors::CircuitError, traits::Circuit};

use crate::zk_gadgets::poseidon::PoseidonHashGadget;

/// Determine the length of the shared prefix of two state element shares
///
/// Note that comparisons in this method are comparisons between pointers, not
/// values. That is, we are comparing the variable identifiers directly to
/// determine whether two variables represent the same value. This method does
/// not capture shared prefixes which come from two different variables assigned
/// to the same value.
fn determine_shared_prefix_length<V: CircuitVarType>(share1: &V, share2: &V) -> usize {
    let share1_vars = share1.to_vars();
    let share2_vars = share2.to_vars();
    assert_eq!(share1_vars.len(), share2_vars.len());

    let mut prefix_length = 0;
    for i in 0..share1_vars.len() {
        if share1_vars[i] != share2_vars[i] {
            break;
        }

        prefix_length += 1;
    }

    prefix_length
}

/// A gadget for computing commitments to state elements
pub struct CommitmentGadget;
impl CommitmentGadget {
    // ---------------------
    // | Basic Commitments |
    // ---------------------

    /// Compute the commitment to an abstract state element
    pub fn compute_commitment<T>(
        element: &StateWrapperVar<T>,
        private_share: &<T::ShareType as CircuitBaseType>::VarType,
        cs: &mut PlonkCircuit,
    ) -> Result<Variable, CircuitError>
    where
        T: CircuitBaseType + SecretShareBaseType,
        T::ShareType: CircuitBaseType,
    {
        // Serialize the commitment input
        let private_commitment = Self::compute_private_commitment(private_share, element, cs)?;
        Self::compute_commitment_from_private::<T>(private_commitment, &element.public_share, cs)
    }

    /// Compute the commitment to the private shares of a state element
    pub fn compute_private_commitment<T>(
        private_share: &<T::ShareType as CircuitBaseType>::VarType,
        element: &StateWrapperVar<T>,
        cs: &mut PlonkCircuit,
    ) -> Result<Variable, CircuitError>
    where
        T: CircuitBaseType + SecretShareBaseType,
        T::ShareType: CircuitBaseType,
    {
        let mut hasher = PoseidonHashGadget::new(cs.zero());
        hasher.batch_absorb(&private_share.to_vars(), cs)?;
        hasher.batch_absorb(&element.recovery_stream.to_vars(), cs)?;
        hasher.batch_absorb(&element.share_stream.to_vars(), cs)?;

        hasher.squeeze(cs)
    }

    /// Compute the commitment to a full state element given a commitment to the
    /// private shares
    ///
    /// As opposed to directly absorbing the public shares into the hasher, we
    /// iterative 2-1 hash the commitment and the next public share.
    ///
    /// The reason for doing this is that it creates a "resumable" partial
    /// commitment. We can partially commit to a state elements up through
    /// the public shares that won't change. Then, we can resume the
    /// commitment in the contracts by hashing the rest of the public shares
    /// into the commitment. This allows us to pre-commit to a state element
    /// e.g. before a match and then commit only to the updated shares after
    /// their values are determined.
    fn compute_commitment_from_private<T>(
        private_commitment: Variable,
        public_share: &<T::ShareType as CircuitBaseType>::VarType,
        cs: &mut PlonkCircuit,
    ) -> Result<Variable, CircuitError>
    where
        T: CircuitBaseType + SecretShareBaseType,
        T::ShareType: CircuitBaseType,
    {
        let public_share_vars = public_share.to_vars();
        let public_commitment = Self::compute_resumable_commitment(&public_share_vars, cs)?;

        // Hash the private commitment and the public commitment together
        let mut hasher = PoseidonHashGadget::new(cs.zero());
        hasher.batch_absorb(&[private_commitment, public_commitment], cs)?;
        hasher.squeeze(cs)
    }

    // -----------------------------
    // | Shared Prefix Commitments |
    // -----------------------------

    /// Compute the commitment to the public shares of two state elements which
    /// share a prefix
    ///
    /// This primitive is useful in state rotation circuits, where frequently
    /// only one or a handful of shares change between two versions of a state
    /// element which we need commitments for.
    pub fn compute_commitments_with_shared_prefix<T>(
        private_share1: &<T::ShareType as CircuitBaseType>::VarType,
        element1: &StateWrapperVar<T>,
        private_share2: &<T::ShareType as CircuitBaseType>::VarType,
        element2: &StateWrapperVar<T>,
        cs: &mut PlonkCircuit,
    ) -> Result<(Variable, Variable), CircuitError>
    where
        T: CircuitBaseType + SecretShareBaseType,
        T::ShareType: CircuitBaseType,
    {
        let (private_comm1, private_comm2) = Self::compute_private_commitments_with_shared_prefix(
            private_share1,
            private_share2,
            element1,
            element2,
            cs,
        )?;
        let (public_comm1, public_comm2) = Self::compute_public_commitments_with_shared_prefix::<T>(
            &element1.public_share,
            &element2.public_share,
            cs,
        )?;

        // Combine the commitments
        let mut hasher1 = PoseidonHashGadget::new(cs.zero());
        let mut hasher2 = hasher1.clone();
        let full_comm1 = hasher1.hash(&[private_comm1, public_comm1], cs)?;
        let full_comm2 = hasher2.hash(&[private_comm2, public_comm2], cs)?;
        Ok((full_comm1, full_comm2))
    }

    /// Compute the commitment to the private shares of two state elements which
    /// share a prefix
    ///
    /// This primitive is useful in state rotation circuits, where frequently
    /// only one or a handful of shares change between two versions of a state
    /// element which we need commitments for.
    fn compute_private_commitments_with_shared_prefix<T>(
        private_share_1: &<T::ShareType as CircuitBaseType>::VarType,
        private_share_2: &<T::ShareType as CircuitBaseType>::VarType,
        elt1: &StateWrapperVar<T>,
        elt2: &StateWrapperVar<T>,
        cs: &mut PlonkCircuit,
    ) -> Result<(Variable, Variable), CircuitError>
    where
        T: CircuitBaseType + SecretShareBaseType,
        T::ShareType: CircuitBaseType,
    {
        let prefix_length = determine_shared_prefix_length(private_share_1, private_share_2);

        // Compute the commitment to the shared prefix
        let share1_vars = private_share_1.to_vars();
        let share2_vars = private_share_2.to_vars();
        let shared_prefix = share1_vars[..prefix_length].to_vec();
        let share1_non_prefix = share1_vars[prefix_length..].to_vec();
        let share2_non_prefix = share2_vars[prefix_length..].to_vec();

        // Compute the hasher state from the shared prefix only once
        // If the shared prefix is empty, this `batch_absorb` will do nothing
        let mut hasher = PoseidonHashGadget::new(cs.zero());
        hasher.batch_absorb(&shared_prefix, cs)?;

        // Compute the commitments to each of the shares now given the prefix
        let mut hasher1 = hasher.clone();
        hasher1.batch_absorb(&share1_non_prefix, cs)?;
        hasher1.batch_absorb(&elt1.recovery_stream.to_vars(), cs)?;
        hasher1.batch_absorb(&elt1.share_stream.to_vars(), cs)?;
        let comm1 = hasher1.squeeze(cs)?;

        let mut hasher2 = hasher.clone();
        hasher2.batch_absorb(&share2_non_prefix, cs)?;
        hasher2.batch_absorb(&elt2.recovery_stream.to_vars(), cs)?;
        hasher2.batch_absorb(&elt2.share_stream.to_vars(), cs)?;
        let comm2 = hasher2.squeeze(cs)?;

        Ok((comm1, comm2))
    }

    /// Compute the commitment to the public shares of two state elements which
    /// share a prefix
    ///
    /// This primitive is useful in state rotation circuits, where frequently
    /// only one or a handful of shares change between two versions of a state
    /// element which we need commitments for.
    ///
    /// In the public case, we use a "resumable" commitment pattern
    fn compute_public_commitments_with_shared_prefix<T>(
        public_share_1: &<T::ShareType as CircuitBaseType>::VarType,
        public_share_2: &<T::ShareType as CircuitBaseType>::VarType,
        cs: &mut PlonkCircuit,
    ) -> Result<(Variable, Variable), CircuitError>
    where
        T: CircuitBaseType + SecretShareBaseType,
        T::ShareType: CircuitBaseType,
    {
        let prefix_length = determine_shared_prefix_length(public_share_1, public_share_2);

        // Compute the commitment to the shared prefix
        let share1_vars = public_share_1.to_vars();
        let share2_vars = public_share_2.to_vars();
        let shared_prefix = share1_vars[..prefix_length].to_vec();

        // Compute the resumable commitment to the shared prefix only once
        // Handle the case where the shared prefix is empty by prepending no values to
        // the hash input
        let (mut share1_values, mut share2_values) = if prefix_length > 0 {
            let partial_comm = Self::compute_resumable_commitment(&shared_prefix, cs)?;
            (vec![partial_comm], vec![partial_comm])
        } else {
            (vec![], vec![])
        };

        // Combine the partial commitment with the remaining values for each share
        share1_values.extend_from_slice(&share1_vars[prefix_length..]);
        share2_values.extend_from_slice(&share2_vars[prefix_length..]);

        // Compute the final commitments
        let comm1 = Self::compute_resumable_commitment(&share1_values, cs)?;
        let comm2 = Self::compute_resumable_commitment(&share2_values, cs)?;
        Ok((comm1, comm2))
    }

    // -----------
    // | Helpers |
    // -----------

    /// Compute a "resumable" commitment to a given set of shares
    ///
    /// A resumable commitment is one defined as:
    ///     H(H(...(H(x_1, x_2), ...), x_{n-1}), x_n)
    /// That is, we reset the hasher state after each element is hashed into it.
    /// This allows us to pre-commit to a partial set of the shares and then
    /// easily resume the commitment by hashing the remaining shares into the
    /// commitment
    fn compute_resumable_commitment(
        values: &[Variable],
        cs: &mut PlonkCircuit,
    ) -> Result<Variable, CircuitError> {
        assert!(!values.is_empty(), "Cannot compute a resumable commitment with no values");
        let mut hasher = PoseidonHashGadget::new(cs.zero());
        let mut comm = values[0];
        for value in values.iter().skip(1) {
            comm = hasher.hash(&[comm, *value], cs)?;
            hasher.reset_state(cs);
        }

        Ok(comm)
    }
}

#[cfg(test)]
mod test {
    use circuit_types::{PlonkCircuit, traits::*};
    use constants::Scalar;
    use eyre::Result;
    use itertools::Itertools;
    use mpc_relation::traits::Circuit;
    use rand::{distributions::uniform::SampleRange, thread_rng};

    use crate::{
        test_helpers::{create_random_state_wrapper, random_scalars_array, random_scalars_vec},
        zk_gadgets::comparators::EqGadget,
    };

    use super::*;

    /// The number of scalars in the test state element
    const N: usize = 50;
    /// The test type for the state element
    type TestStateElt = [Scalar; N];

    /// Test the commitment gadget
    #[test]
    fn test_commitment_gadget() -> Result<()> {
        // Generate test data
        let state_element = random_scalars_array();
        let element = create_random_state_wrapper::<TestStateElt>(state_element);
        let private_share = element.private_shares();
        let expected_commitment = element.compute_commitment();

        // Allocate in a constraint system
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let element_var = element.create_witness(&mut cs);
        let private_share_var = private_share.create_witness(&mut cs);
        let expected_commitment_var = expected_commitment.create_witness(&mut cs);

        let commitment =
            CommitmentGadget::compute_commitment(&element_var, &private_share_var, &mut cs)?;
        EqGadget::constrain_eq(&commitment, &expected_commitment_var, &mut cs)?;

        // Check satisfiability
        assert!(cs.check_circuit_satisfiability(&[]).is_ok());
        Ok(())
    }

    /// Test the commitment gadget with no shared prefix
    #[test]
    fn test_commitment_gadget_with_no_shared_prefix() -> Result<()> {
        let state1 = random_scalars_array();
        let state2 = random_scalars_array();
        let elt1 = create_random_state_wrapper::<TestStateElt>(state1);
        let elt2 = create_random_state_wrapper::<TestStateElt>(state2);
        let private_share1 = elt1.private_shares();
        let private_share2 = elt2.private_shares();
        let expected_commitment1 = elt1.compute_commitment();
        let expected_commitment2 = elt2.compute_commitment();

        // Allocate in a constraint system
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let private_share1_var = private_share1.create_witness(&mut cs);
        let private_share2_var = private_share2.create_witness(&mut cs);

        let element1_var = elt1.create_witness(&mut cs);
        let element2_var = elt2.create_witness(&mut cs);
        let expected_commitment1_var = expected_commitment1.create_witness(&mut cs);
        let expected_commitment2_var = expected_commitment2.create_witness(&mut cs);

        let (commitment1, commitment2) = CommitmentGadget::compute_commitments_with_shared_prefix(
            &private_share1_var,
            &element1_var,
            &private_share2_var,
            &element2_var,
            &mut cs,
        )?;
        EqGadget::constrain_eq(&commitment1, &expected_commitment1_var, &mut cs)?;
        EqGadget::constrain_eq(&commitment2, &expected_commitment2_var, &mut cs)?;

        // Check satisfiability
        assert!(cs.check_circuit_satisfiability(&[]).is_ok());
        Ok(())
    }

    /// Test the commitment gadget with a shared prefix
    #[test]
    fn test_commitment_gadget_with_shared_prefix() -> Result<()> {
        // Generate shared prefixes
        let mut rng = thread_rng();
        let public_prefix_length = (0..N).sample_single(&mut rng);
        let private_prefix_length = (0..N).sample_single(&mut rng);
        let shared_public_prefix = random_scalars_vec(public_prefix_length);
        let shared_private_prefix = random_scalars_vec(private_prefix_length);

        // Generate shares with duplicated values
        let mut private_share1 = random_scalars_array();
        let mut private_share2 = random_scalars_array();
        let mut public_share1 = private_share2.add_shares(&random_scalars_array());
        let mut public_share2 = private_share2.add_shares(&random_scalars_array());
        private_share1[..private_prefix_length].copy_from_slice(&shared_private_prefix);
        private_share2[..private_prefix_length].copy_from_slice(&shared_private_prefix);
        public_share1[..public_prefix_length].copy_from_slice(&shared_public_prefix);
        public_share2[..public_prefix_length].copy_from_slice(&shared_public_prefix);

        let combined_1 = private_share1.add_shares(&public_share1);
        let combined_2 = private_share2.add_shares(&public_share2);
        let mut elt1 = create_random_state_wrapper::<TestStateElt>(combined_1);
        let mut elt2 = create_random_state_wrapper::<TestStateElt>(combined_2);
        elt1.public_share = public_share1;
        elt2.public_share = public_share2;
        let expected_commitment1 = elt1.compute_commitment();
        let expected_commitment2 = elt2.compute_commitment();

        // Allocate in a constraint system
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let shared_public_vars =
            shared_public_prefix.iter().map(|v| v.create_witness(&mut cs)).collect_vec();
        let shared_private_vars =
            shared_private_prefix.iter().map(|v| v.create_witness(&mut cs)).collect_vec();

        let mut private_share1_var = private_share1.create_witness(&mut cs);
        let mut public_share1_var = public_share1.create_witness(&mut cs);
        let mut private_share2_var = private_share2.create_witness(&mut cs);
        let mut public_share2_var = public_share2.create_witness(&mut cs);
        private_share1_var[..private_prefix_length].copy_from_slice(&shared_private_vars);
        public_share1_var[..public_prefix_length].copy_from_slice(&shared_public_vars);
        private_share2_var[..private_prefix_length].copy_from_slice(&shared_private_vars);
        public_share2_var[..public_prefix_length].copy_from_slice(&shared_public_vars);

        let mut element1_var = elt1.create_witness(&mut cs);
        let mut element2_var = elt2.create_witness(&mut cs);
        element1_var.public_share = public_share1_var;
        element2_var.public_share = public_share2_var;
        let expected_commitment1_var = expected_commitment1.create_witness(&mut cs);
        let expected_commitment2_var = expected_commitment2.create_witness(&mut cs);

        let (commitment1, commitment2) = CommitmentGadget::compute_commitments_with_shared_prefix(
            &private_share1_var,
            &element1_var,
            &private_share2_var,
            &element2_var,
            &mut cs,
        )?;
        EqGadget::constrain_eq(&commitment1, &expected_commitment1_var, &mut cs)?;
        EqGadget::constrain_eq(&commitment2, &expected_commitment2_var, &mut cs)?;

        // Check satisfiability
        assert!(cs.check_circuit_satisfiability(&[]).is_ok());
        Ok(())
    }
}
