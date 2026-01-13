//! Gadgets for operating on CSPRNGs

use circuit_types::PlonkCircuit;
use darkpool_types::csprng::PoseidonCSPRNGVar;
use mpc_relation::traits::Circuit;
use mpc_relation::{Variable, errors::CircuitError};

use crate::zk_gadgets::primitives::poseidon::PoseidonHashGadget;

/// A gadget for operating on CSPRNGs
pub struct CSPRNGGadget;
impl CSPRNGGadget {
    /// Get the ith value from a CSPRNG
    ///
    /// Does *not* mutate the CSPRNG state
    pub fn get_ith(
        csprng_state: &PoseidonCSPRNGVar,
        i: Variable,
        cs: &mut PlonkCircuit,
    ) -> Result<Variable, CircuitError> {
        // Compute the ith value as H(seed || i)
        let mut hasher = PoseidonHashGadget::new(cs.zero());
        let input = vec![csprng_state.seed, i];
        hasher.hash(&input, cs)
    }

    /// Generate a value from a CSPRNG
    pub fn next(
        csprng_state: &mut PoseidonCSPRNGVar,
        cs: &mut PlonkCircuit,
    ) -> Result<Variable, CircuitError> {
        // Compute the next value as H(seed || index)
        let mut hasher = PoseidonHashGadget::new(cs.zero());
        let input = vec![csprng_state.seed, csprng_state.index];
        let next_value = hasher.hash(&input, cs)?;

        // Increment the index
        csprng_state.index = cs.add(csprng_state.index, cs.one())?;
        Ok(next_value)
    }

    /// Generate the next `k` values from a CSPRNG
    pub fn next_k(
        csprng_state: &mut PoseidonCSPRNGVar,
        k: usize,
        cs: &mut PlonkCircuit,
    ) -> Result<Vec<Variable>, CircuitError> {
        (0..k).map(|_| Self::next(csprng_state, cs)).collect()
    }
}

#[cfg(test)]
mod test {
    use circuit_types::{PlonkCircuit, traits::CircuitBaseType};
    use constants::Scalar;
    use darkpool_types::csprng::PoseidonCSPRNG;
    use eyre::Result;
    use mpc_relation::traits::Circuit;
    use rand::{Rng, thread_rng};

    use crate::zk_gadgets::{primitives::comparators::EqGadget, primitives::csprng::CSPRNGGadget};

    /// Get a random CSPRNG state
    fn random_csprng() -> PoseidonCSPRNG {
        let mut rng = thread_rng();
        let seed = Scalar::random(&mut rng);
        PoseidonCSPRNG::new(seed)
    }

    /// Get the ith value in a CSPRNG with the given seed
    fn get_csprng_ith(seed: Scalar, index: usize) -> Scalar {
        let mut csprng = PoseidonCSPRNG::new(seed);
        csprng.advance_by(index);
        csprng.next().unwrap()
    }

    /// Test the `ith` method
    #[test]
    fn test_get_ith() -> Result<()> {
        let mut rng = thread_rng();

        // Test data
        let index: usize = rng.r#gen();
        let csprng_state = random_csprng();
        let expected = get_csprng_ith(csprng_state.seed, index);

        // Allocate in a constraint system
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let index_var = index.create_witness(&mut cs);
        let csprng_state_var = csprng_state.create_witness(&mut cs);
        let expected_var = expected.create_witness(&mut cs);

        // Compute the gadget value and check that it matches the expected value
        let value = CSPRNGGadget::get_ith(&csprng_state_var, index_var, &mut cs)?;
        EqGadget::constrain_eq(&value, &expected_var, &mut cs)?;
        cs.check_circuit_satisfiability(&[])?;
        Ok(())
    }

    /// Test the `next` method
    #[test]
    fn test_next() -> Result<()> {
        // Test data
        let csprng_state = random_csprng();
        let seed = csprng_state.seed;

        // Compute expected values
        let expected_first = get_csprng_ith(seed, 0);
        let expected_second = get_csprng_ith(seed, 1);

        // Allocate in a constraint system
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let mut csprng_state_var = csprng_state.create_witness(&mut cs);
        let expected_first_var = expected_first.create_witness(&mut cs);
        let expected_second_var = expected_second.create_witness(&mut cs);

        // Call next() and verify it returns the first value
        let value_first = CSPRNGGadget::next(&mut csprng_state_var, &mut cs)?;
        EqGadget::constrain_eq(&value_first, &expected_first_var, &mut cs)?;

        // Call next() again and verify it returns the second value
        let value_second = CSPRNGGadget::next(&mut csprng_state_var, &mut cs)?;
        EqGadget::constrain_eq(&value_second, &expected_second_var, &mut cs)?;

        // Check satisfiability
        cs.check_circuit_satisfiability(&[])?;
        Ok(())
    }

    /// Test the `next_k` method
    #[test]
    fn test_next_k() -> Result<()> {
        let mut rng = thread_rng();

        // Test data
        let csprng_state = random_csprng();
        let seed = csprng_state.seed;
        let k: usize = rng.gen_range(1..=100);

        // Compute expected values using the CSPRNG
        let csprng = PoseidonCSPRNG::new(seed);
        let expected_values: Vec<Scalar> = csprng.take(k).collect();

        // Allocate in a constraint system
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let mut csprng_state_var = csprng_state.create_witness(&mut cs);
        let expected_vars: Vec<_> =
            expected_values.iter().map(|val| val.create_witness(&mut cs)).collect();

        // Call next_k() and verify all values match
        let values = CSPRNGGadget::next_k(&mut csprng_state_var, k, &mut cs)?;
        for (value, expected_var) in values.iter().zip(expected_vars.iter()) {
            EqGadget::constrain_eq(value, expected_var, &mut cs)?;
        }

        // Check satisfiability
        cs.check_circuit_satisfiability(&[])?;
        Ok(())
    }
}
