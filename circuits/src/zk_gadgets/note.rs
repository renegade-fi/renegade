//! Helpers for operations on notes

use circuit_types::{
    keychain::EncryptionKeyVar,
    note::{NoteVar, NOTE_CIPHERTEXT_SIZE},
    traits::CircuitVarType,
    PlonkCircuit,
};
use jf_primitives::circuit::elgamal::ElGamalEncryptionGadget;
use mpc_relation::{errors::CircuitError, traits::Circuit, Variable};

use crate::zk_gadgets::elgamal::ElGamalGadget;

use super::{elgamal::ElGamalCiphertextVar, poseidon::PoseidonHashGadget};

/// A gadget for verifying operations on notes
pub struct NoteGadget;
impl NoteGadget {
    /// Verify the encryption of a note under a given key
    pub fn verify_note_encryption(
        note: &NoteVar,
        encryption_key: &EncryptionKeyVar,
        randomness: Variable,
        expected_ciphertext: &ElGamalCiphertextVar<NOTE_CIPHERTEXT_SIZE>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let plaintext_fields = [note.mint, note.amount, note.blinder];
        ElGamalGadget::check_ciphertext(
            &plaintext_fields,
            encryption_key,
            randomness,
            expected_ciphertext,
            cs,
        )
    }

    /// Verify a commitment to a note
    pub fn verify_note_commitment(
        note: &NoteVar,
        expected_commitment: Variable,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let mut hasher = PoseidonHashGadget::new(cs.zero() /* zero_var */);
        hasher.batch_absorb(&note.to_vars(), cs)?;

        hasher.constrained_squeeze(expected_commitment, cs)
    }
}
