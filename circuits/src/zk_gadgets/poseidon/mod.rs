//! Poseidon hash gadget

pub(super) mod gates;
mod hash;

pub use hash::*;

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod test {
    use circuit_types::{traits::CircuitBaseType, PlonkCircuit};
    use constants::Scalar;
    use itertools::Itertools;
    use mpc_relation::traits::Circuit;
    use rand::thread_rng;
    use renegade_crypto::hash::{compute_poseidon_hash, Poseidon2Sponge};

    use crate::zk_gadgets::poseidon::PoseidonHashGadget;

    /// Tests absorbing a series of elements into the hasher and comparing to
    /// the hasher in `renegade-crypto`
    #[test]
    fn test_sponge() {
        const N: usize = 100;
        let mut rng = thread_rng();
        let values = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();

        let expected = compute_poseidon_hash(&values);

        // Constrain the gadget result
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let mut gadget = PoseidonHashGadget::new(cs.zero());

        // Allocate the values in the constraint system
        let input_vars = values.iter().map(|v| v.create_witness(&mut cs)).collect_vec();
        let output_var = expected.create_public_var(&mut cs);

        gadget.hash(&input_vars, output_var, &mut cs).unwrap();

        // Check that the constraints are satisfied
        assert!(cs.check_circuit_satisfiability(&[expected.inner()]).is_ok());
    }

    /// Tests a batch absorb and squeeze of the hasher
    #[test]
    fn test_batch_absorb_squeeze() {
        const N: usize = 5;
        let mut rng = thread_rng();
        let absorb_values = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();

        // Compute the expected result
        let mut hasher = Poseidon2Sponge::new();
        hasher.absorb_batch(&absorb_values.iter().map(Scalar::inner).collect_vec());
        let expected_squeeze_values =
            hasher.squeeze_batch(N).into_iter().map(Scalar::new).collect_vec();

        // Compute the result in-circuit
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let mut gadget = PoseidonHashGadget::new(cs.zero());
        let absorb_vars = absorb_values.iter().map(|v| v.create_witness(&mut cs)).collect_vec();

        gadget.batch_absorb(&absorb_vars, &mut cs).unwrap();
        let squeeze_vars = gadget.batch_squeeze(N, &mut cs).unwrap();

        // Check that the squeezed values match the expected values
        for (squeeze_var, expected_value) in
            squeeze_vars.into_iter().zip(expected_squeeze_values.into_iter())
        {
            let expected_var = expected_value.create_witness(&mut cs);
            cs.enforce_equal(squeeze_var, expected_var).unwrap();
        }

        // Check that the constraints are satisfied
        assert!(cs.check_circuit_satisfiability(&[]).is_ok());
    }
}
