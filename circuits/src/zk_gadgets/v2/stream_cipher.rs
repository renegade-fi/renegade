//! Gadgets for operating on stream ciphers

use circuit_types::{
    PlonkCircuit,
    csprng_state::PoseidonCSPRNGVar,
    traits::{CircuitVarType, SecretShareVarType},
};
use itertools::Itertools;
use mpc_relation::traits::Circuit;
use mpc_relation::{Variable, errors::CircuitError};

use crate::zk_gadgets::csprng::CSPRNGGadget;

/// A gadget for operating on stream ciphers
pub struct StreamCipherGadget;
impl StreamCipherGadget {
    /// Encrypt a set of values using the given stream cipher state    
    ///
    /// Returns the private shares (one-time pads) and the public shares
    /// (ciphertext)
    pub fn encrypt<V: SecretShareVarType>(
        value: &V::Base,
        csprng_state: &mut PoseidonCSPRNGVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(V, V), CircuitError> {
        // Generate new one-time pads (private shares) for the values
        let value_vars = value.to_vars();
        let pads = CSPRNGGadget::next_k(csprng_state, value_vars.len(), cs)?;
        let ciphertexts = value_vars
            .iter()
            .zip_eq(pads.iter())
            .map(|(value, pad)| cs.sub(*value, *pad))
            .collect::<Result<Vec<Variable>, CircuitError>>()?;

        let private_share = V::from_vars(&mut pads.into_iter(), cs);
        let public_share = V::from_vars(&mut ciphertexts.into_iter(), cs);
        Ok((private_share, public_share))
    }
}
