//! Gadgets for operating on CSPRNGs

use circuit_types::{PlonkCircuit, csprng_state::CSPRNGStateVar};
use mpc_relation::traits::Circuit;
use mpc_relation::{Variable, errors::CircuitError};

use crate::zk_gadgets::poseidon::PoseidonHashGadget;

/// A gadget for operating on CSPRNGs
pub struct CSPRNGGadget;
impl CSPRNGGadget {
    /// Get the ith value from a CSPRNG
    ///
    /// Does *not* mutate the CSPRNG state
    pub fn get_ith(
        csprng_state: &CSPRNGStateVar,
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
        csprng_state: &mut CSPRNGStateVar,
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
        csprng_state: &mut CSPRNGStateVar,
        k: usize,
        cs: &mut PlonkCircuit,
    ) -> Result<Vec<Variable>, CircuitError> {
        (0..k).map(|_| Self::next(csprng_state, cs)).collect()
    }
}
