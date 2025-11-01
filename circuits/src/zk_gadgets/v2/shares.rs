//! Secret share gadgets

use circuit_types::{
    PlonkCircuit,
    traits::{CircuitBaseType, CircuitVarType, SecretShareVarType},
};
use itertools::Itertools;
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
        let complementary_shares_vars = shares_vars
            .iter()
            .zip(base_vars.iter())
            .map(|(s, b)| cs.sub(*s, *b))
            .collect::<Result<Vec<Variable>, CircuitError>>()?;
        let complementary_shares = S::from_vars(&mut complementary_shares_vars.into_iter(), cs);
        Ok(complementary_shares)
    }
}
