//! Gadgets for operating on stream ciphers

use circuit_types::{
    PlonkCircuit,
    csprng::PoseidonCSPRNGVar,
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

#[cfg(test)]
mod test {
    use circuit_types::{PlonkCircuit, balance::Balance, traits::CircuitBaseType};
    use constants::Scalar;
    use eyre::Result;
    use mpc_relation::Variable;
    use mpc_relation::traits::Circuit;

    use crate::{
        test_helpers::create_random_state_wrapper,
        test_helpers::random_scalars_array,
        zk_gadgets::{comparators::EqGadget, stream_cipher::StreamCipherGadget},
    };

    /// Test that the encrypt gadget aligns with the native implementation
    #[test]
    fn test_encrypt() -> Result<()> {
        // Create a state wrapper, the inner type is unimportant for this test
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let mut state = create_random_state_wrapper(Balance::default());
        let mut state_var = state.create_witness(&mut cs);

        // Generate test data to encrypt
        const N: usize = 10;
        let values = random_scalars_array::<N>();
        let values_var = values.create_witness(&mut cs);
        let expected_public = state.stream_cipher_encrypt::<[Scalar; N]>(&values);
        let mut expected_private = [Scalar::zero(); N];
        for (i, (v, p)) in values.into_iter().zip(expected_public.into_iter()).enumerate() {
            expected_private[i] = v - p;
        }

        // Encrypt in a constraint system
        let (private_share, public_share) = StreamCipherGadget::encrypt::<[Variable; N]>(
            &values_var,
            &mut state_var.share_stream,
            &mut cs,
        )?;

        // Check that the private and public shares match the expected values
        let expected_private_vars = expected_private.create_witness(&mut cs);
        let expected_public_vars = expected_public.create_witness(&mut cs);
        EqGadget::constrain_eq(&private_share, &expected_private_vars, &mut cs)?;
        EqGadget::constrain_eq(&public_share, &expected_public_vars, &mut cs)?;

        // Check satisfiability
        assert!(cs.check_circuit_satisfiability(&[]).is_ok());
        Ok(())
    }
}
