//! Helpers for operations on notes

use circuit_types::{
    PlonkCircuit,
    elgamal::{ElGamalCiphertextVar, EncryptionKeyVar},
    note::{NOTE_CIPHERTEXT_SIZE, NoteVar},
    traits::CircuitVarType,
};
use mpc_relation::{Variable, errors::CircuitError, traits::Circuit};

use crate::zk_gadgets::elgamal::ElGamalGadget;

use super::{comparators::EqGadget, poseidon::PoseidonHashGadget};

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
        let comm = Self::compute_note_commitment(note, cs)?;
        EqGadget::constrain_eq(&comm, &expected_commitment, cs)
    }

    /// Verify the nullifier of a note
    pub fn verify_note_nullifier(
        note_comm: Variable,
        note_blinder: Variable,
        expected_nullifier: Variable,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let nullifier = Self::compute_note_nullifier(note_comm, note_blinder, cs)?;
        EqGadget::constrain_eq(&nullifier, &expected_nullifier, cs)
    }

    /// Compute the commitment to a note
    pub fn compute_note_commitment(
        note: &NoteVar,
        cs: &mut PlonkCircuit,
    ) -> Result<Variable, CircuitError> {
        let mut hasher = PoseidonHashGadget::new(cs.zero() /* zero_var */);
        hasher.batch_absorb(&note.to_vars(), cs)?;

        hasher.squeeze(cs)
    }

    /// Compute the nullifier of a note
    pub fn compute_note_nullifier(
        note_comm: Variable,
        note_blinder: Variable,
        cs: &mut PlonkCircuit,
    ) -> Result<Variable, CircuitError> {
        let mut hasher = PoseidonHashGadget::new(cs.zero() /* zero_var */);
        hasher.batch_absorb(&[note_comm, note_blinder], cs)?;

        hasher.squeeze(cs)
    }
}
