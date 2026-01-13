//! Gadget for computing nullifiers of state elements

use circuit_types::PlonkCircuit;
use darkpool_types::state_wrapper::{StateWrapperBound, StateWrapperShareBound, StateWrapperVar};
use mpc_relation::{Variable, errors::CircuitError, traits::Circuit};

use crate::zk_gadgets::primitives::poseidon::PoseidonHashGadget;
use crate::zk_gadgets::state_primitives::csprng::CSPRNGGadget;

/// A gadget for computing nullifiers of state elements
pub struct NullifierGadget;
impl NullifierGadget {
    /// Compute the nullifier of a state element
    ///
    /// A state element's nullifier is the hash of the recovery identifier for
    /// the current version of the element with the seed of the recovery stream.
    /// This recovery identifier was emitted on the last update of the element.
    /// So if the current index in the recovery stream is `i`, the recovery
    /// identifier in question is the value at index `i - 1`.
    pub fn compute_nullifier<V>(
        element: &StateWrapperVar<V>,
        cs: &mut PlonkCircuit,
    ) -> Result<Variable, CircuitError>
    where
        V: StateWrapperBound,
        V::ShareType: StateWrapperShareBound,
    {
        let last_idx = cs.sub(element.recovery_stream.index, cs.one())?;
        let recovery_id = CSPRNGGadget::get_ith(&element.recovery_stream, last_idx, cs)?;

        // Compute the nullifier as H(recovery_id || recovery_stream_seed)
        let mut hasher = PoseidonHashGadget::new(cs.zero());
        hasher.batch_absorb(&[recovery_id, element.recovery_stream.seed], cs)?;
        hasher.squeeze(cs)
    }
}

#[cfg(test)]
mod test {
    use circuit_types::{PlonkCircuit, traits::CircuitBaseType};
    use constants::Scalar;
    use eyre::Result;
    use rand::thread_rng;

    use super::*;

    use crate::{test_helpers::create_random_state_wrapper, zk_gadgets::comparators::EqGadget};

    /// Test the nullifier gadget's consistency with the native implementation
    #[test]
    fn test_nullifier_gadget_consistency() -> Result<()> {
        let mut rng = thread_rng();

        // The inner type is unimportant for this test
        let scalar = Scalar::random(&mut rng);
        let elt = create_random_state_wrapper(scalar);
        let nullifier = elt.compute_nullifier();

        // Check against the gadget
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let elt_var = elt.create_witness(&mut cs);
        let nullifier_var = NullifierGadget::compute_nullifier(&elt_var, &mut cs)?;
        let expected_var = nullifier.create_witness(&mut cs);
        EqGadget::constrain_eq(&nullifier_var, &expected_var, &mut cs)?;

        // Verify satisfiability
        assert!(cs.check_circuit_satisfiability(&[]).is_ok());
        Ok(())
    }
}
