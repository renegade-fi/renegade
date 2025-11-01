//! Secret share gadgets

use circuit_types::{
    PlonkCircuit,
    traits::{CircuitVarType, SecretShareVarType},
};
use mpc_relation::traits::Circuit;
use mpc_relation::{Variable, errors::CircuitError};

/// A gadget for operating on secret shares
pub struct ShareGadget;
impl ShareGadget {
    /// Compute the complementary set of secret shares given a base type and one
    /// set of shares
    ///
    /// That is, compute those shares which sum with the given set of shares to
    /// produce the base type
    pub fn compute_complementary_shares<S: SecretShareVarType>(
        shares: &S,
        base: &S::Base,
        cs: &mut PlonkCircuit,
    ) -> Result<S, CircuitError> {
        // Serialize into vars
        let shares_vars = shares.to_vars();
        let base_vars = base.to_vars();

        // Compute the complementary set of shares and deserialize into the share type
        let complementary_shares_vars = base_vars
            .iter()
            .zip(shares_vars.iter())
            .map(|(b, s)| cs.sub(*b, *s))
            .collect::<Result<Vec<Variable>, CircuitError>>()?;
        let complementary_shares = S::from_vars(&mut complementary_shares_vars.into_iter(), cs);
        Ok(complementary_shares)
    }
}

#[cfg(test)]
mod test {
    use constants::Scalar;
    use eyre::Result;
    use itertools::Itertools;
    use rand::{distributions::uniform::SampleRange, thread_rng};

    use crate::{test_helpers::random_scalars_array, zk_gadgets::comparators::EqGadget};

    use super::*;
    use circuit_types::traits::CircuitBaseType;

    /// Test the complementary shares gadget
    #[test]
    fn test_compute_complementary_shares() -> Result<()> {
        // Generate test data
        const N: usize = 100;
        let share1: [Scalar; N] = random_scalars_array();
        let share2: [Scalar; N] = random_scalars_array();
        let base: [Scalar; N] = share1
            .iter()
            .zip(share2.iter())
            .map(|(s1, s2)| *s1 + *s2)
            .collect_vec()
            .try_into()
            .unwrap();

        // Allocate in a constraint system
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let share1_var = share1.create_witness(&mut cs);
        let share2_var = share2.create_witness(&mut cs);
        let base_var = base.create_witness(&mut cs);

        // Compute the complementary shares and enforce that they're equal to the other
        // shares
        let complementary_shares =
            ShareGadget::compute_complementary_shares(&share1_var, &base_var, &mut cs)?;
        EqGadget::constrain_eq(&complementary_shares, &share2_var, &mut cs)?;

        // Check satisfiability
        assert!(cs.check_circuit_satisfiability(&[]).is_ok());
        Ok(())
    }

    /// Test the complementary shares gadget with invalid shares
    #[test]
    #[allow(non_snake_case)]
    fn test_compute_complementary_shares__invalid() -> Result<()> {
        let mut rng = thread_rng();

        // Generate test data
        const N: usize = 100;
        let mut share1: [Scalar; N] = random_scalars_array();
        let share2: [Scalar; N] = random_scalars_array();
        let base: [Scalar; N] = share1
            .iter()
            .zip(share2.iter())
            .map(|(s1, s2)| *s1 + *s2)
            .collect_vec()
            .try_into()
            .unwrap();

        // Corrupt one share
        let idx = (0..N).sample_single(&mut rng);
        share1[idx] = Scalar::random(&mut rng);

        // Allocate in a constraint system
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let share1_var = share1.create_witness(&mut cs);
        let share2_var = share2.create_witness(&mut cs);
        let base_var = base.create_witness(&mut cs);

        // Compute the complementary shares and enforce that they're equal to the other
        // shares
        let complementary_shares =
            ShareGadget::compute_complementary_shares(&share1_var, &base_var, &mut cs)?;
        EqGadget::constrain_eq(&complementary_shares, &share2_var, &mut cs)?;

        // Check satisfiability
        assert!(cs.check_circuit_satisfiability(&[]).is_err());
        Ok(())
    }
}
