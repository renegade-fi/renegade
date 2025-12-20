//! Gadgets for verifying Schnorr signatures

use circuit_types::PlonkCircuit;
use circuit_types::schnorr::{SchnorrPublicKeyVar, SchnorrSignatureVar};
use circuit_types::traits::CircuitVarType;
use constants::{EmbeddedCurveConfig, ScalarField};
use jf_primitives::circuit::signature::schnorr::*;
use mpc_relation::errors::CircuitError;

/// A Schnorr signature verification gadget
pub struct SchnorrGadget;
impl SchnorrGadget {
    /// Verify a Schnorr signature
    pub fn verify_signature<T: CircuitVarType>(
        signature: &SchnorrSignatureVar,
        message: &T,
        public_key: &SchnorrPublicKeyVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let msg_vars = message.to_vars();

        // Convert the public key and signature to the jellyfish types
        let vk = public_key.clone().into();
        let sig = signature.clone().into();
        <PlonkCircuit as SignatureGadget<ScalarField, EmbeddedCurveConfig>>::verify_signature(
            cs, &vk, &msg_vars, &sig,
        )
    }
}

#[cfg(test)]
mod test {
    use ark_ff::UniformRand;
    use circuit_types::traits::CircuitBaseType;
    use constants::EmbeddedScalarField;
    use mpc_relation::traits::Circuit;
    use rand::thread_rng;

    use crate::test_helpers::{random_scalars_array, random_schnorr_keypair};

    use super::*;

    /// Test that the signature verification gadget works
    #[test]
    fn test_signature_verification() {
        const N: usize = 10;
        let msg = random_scalars_array::<N>();
        let (sk, pk) = random_schnorr_keypair();
        let sig = sk.sign(&msg).unwrap();

        // Create witness variables
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let sig_var = sig.create_witness(&mut cs);
        let pk_var = pk.create_witness(&mut cs);
        let msg_var = msg.create_witness(&mut cs);

        // Verify the signature
        SchnorrGadget::verify_signature(&sig_var, &msg_var, &pk_var, &mut cs).unwrap();

        // Check that the circuit is satisfied
        cs.check_circuit_satisfiability(&[]).unwrap();
    }

    /// Test that the signature verification gadget rejects invalid signatures
    #[test]
    fn test_signature_verification_invalid_signature() {
        const N: usize = 10;
        let mut rng = thread_rng();
        let msg = random_scalars_array::<N>();
        let (sk, pk) = random_schnorr_keypair();
        let mut sig = sk.sign(&msg).unwrap();

        // Modify the signature's s value to make it invalid
        sig.s = EmbeddedScalarField::rand(&mut rng);

        // Create witness variables
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let sig_var = sig.create_witness(&mut cs);
        let pk_var = pk.create_witness(&mut cs);
        let msg_var = msg.create_witness(&mut cs);

        // Verify the signature
        SchnorrGadget::verify_signature(&sig_var, &msg_var, &pk_var, &mut cs).unwrap();

        // Check that the circuit is NOT satisfied
        assert!(cs.check_circuit_satisfiability(&[]).is_err());
    }
}
