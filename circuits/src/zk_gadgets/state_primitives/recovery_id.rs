//! Gadget for computing recovery identifiers of state elements

use circuit_types::{
    PlonkCircuit,
    state_wrapper::StateWrapperVar,
    traits::{CircuitBaseType, SecretShareBaseType},
};
use mpc_relation::{Variable, errors::CircuitError};

use crate::zk_gadgets::state_primitives::csprng::CSPRNGGadget;

/// A gadget for computing recovery identifiers of state elements
pub struct RecoveryIdGadget;
impl RecoveryIdGadget {
    /// Compute the recovery identifier for a given state element    
    ///
    /// This is just the current index in the recovery stream
    ///
    /// This method mutates the recovery stream state to advance it by one
    pub fn compute_recovery_id<V>(
        element: &mut StateWrapperVar<V>,
        cs: &mut PlonkCircuit,
    ) -> Result<Variable, CircuitError>
    where
        V: CircuitBaseType + SecretShareBaseType,
        V::ShareType: CircuitBaseType,
    {
        CSPRNGGadget::next(&mut element.recovery_stream, cs)
    }
}

#[cfg(test)]
mod test {
    use circuit_types::{PlonkCircuit, traits::CircuitBaseType};
    use constants::Scalar;
    use eyre::Result;
    use mpc_relation::traits::Circuit;
    use rand::thread_rng;

    use super::*;

    use crate::{test_helpers::create_random_state_wrapper, zk_gadgets::comparators::EqGadget};

    /// Test the recovery ID gadget's consistency with the native implementation
    #[test]
    fn test_recovery_id_gadget_consistency() -> Result<()> {
        let mut rng = thread_rng();

        // The inner type is unimportant for this test
        let scalar = Scalar::random(&mut rng);
        let elt = create_random_state_wrapper(scalar);
        let recovery_id = elt.peek_recovery_id();

        // Check against the gadget
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let mut elt_var = elt.create_witness(&mut cs);
        let recovery_id_var = RecoveryIdGadget::compute_recovery_id(&mut elt_var, &mut cs)?;
        let expected_var = recovery_id.create_witness(&mut cs);
        EqGadget::constrain_eq(&recovery_id_var, &expected_var, &mut cs)?;

        // Verify satisfiability
        assert!(cs.check_circuit_satisfiability(&[]).is_ok());
        Ok(())
    }
}
