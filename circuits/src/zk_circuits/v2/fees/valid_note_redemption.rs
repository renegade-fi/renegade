//! Defines the `VALID NOTE REDEMPTION` circuit
//!
//! This circuit proves that a note redemption is valid.
//!
//! This circuit is very simple, it is essentially a proof that a note's
//! commitment is a valid Merkle leaf and that its nullifier has been correctly
//! computed. We redeem notes into EoA balances, so no balance updates are
//! needed.
//!
//! The contracts will take care of nullifying the note and dispensing the funds
//! to the recipient.

use circuit_macros::circuit_type;
use circuit_types::merkle::{MerkleOpening, MerkleRoot};
use circuit_types::note::Note;
use circuit_types::traits::{BaseType, CircuitBaseType, CircuitVarType};
use circuit_types::{Nullifier, PlonkCircuit};
use constants::{MERKLE_HEIGHT, Scalar, ScalarField};
use mpc_plonk::errors::PlonkError;
use mpc_relation::{Variable, errors::CircuitError, traits::Circuit};
use serde::{Deserialize, Serialize};

use crate::SingleProverCircuit;
use crate::zk_gadgets::merkle::PoseidonMerkleHashGadget;
use crate::zk_gadgets::note::NoteGadget;

// ----------------------
// | Circuit Definition |
// ----------------------

/// A type alias for the `ValidNoteRedemption` circuit with default
/// size parameters attached
pub type SizedValidNoteRedemption = ValidNoteRedemption<MERKLE_HEIGHT>;

/// The `VALID NOTE REDEMPTION` circuit
pub struct ValidNoteRedemption<const MERKLE_HEIGHT: usize>;

impl<const MERKLE_HEIGHT: usize> ValidNoteRedemption<MERKLE_HEIGHT> {
    /// Apply the circuit constraints to a given constraint system
    pub fn circuit(
        statement: &ValidNoteRedemptionStatementVar,
        witness: &ValidNoteRedemptionWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let note = &statement.note;

        // Verify the note's Merkle opening
        let note_commitment = NoteGadget::compute_note_commitment(note, cs)?;
        PoseidonMerkleHashGadget::compute_and_constrain_root_prehashed(
            note_commitment,
            &witness.note_opening,
            statement.note_root,
            cs,
        )?;

        // Verify the note's nullifier
        NoteGadget::verify_note_nullifier(
            note_commitment,
            note.blinder,
            statement.note_nullifier,
            cs,
        )
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for `VALID NOTE REDEMPTION`
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidNoteRedemptionWitness<const MERKLE_HEIGHT: usize> {
    /// The opening of the note to the Merkle root
    pub note_opening: MerkleOpening<MERKLE_HEIGHT>,
}

/// A `VALID NOTE REDEMPTION` witness with default const generic
/// sizing parameters
pub type SizedValidNoteRedemptionWitness = ValidNoteRedemptionWitness<MERKLE_HEIGHT>;

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for `VALID NOTE REDEMPTION`
#[circuit_type(singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidNoteRedemptionStatement {
    /// The note being redeemed
    pub note: Note,
    /// The Merkle root to which the note opens
    pub note_root: MerkleRoot,
    /// The nullifier of the note
    pub note_nullifier: Nullifier,
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl<const MERKLE_HEIGHT: usize> SingleProverCircuit for ValidNoteRedemption<MERKLE_HEIGHT> {
    type Witness = ValidNoteRedemptionWitness<MERKLE_HEIGHT>;
    type Statement = ValidNoteRedemptionStatement;

    fn name() -> String {
        format!("Valid Note Redemption ({MERKLE_HEIGHT})")
    }

    fn apply_constraints(
        witness_var: ValidNoteRedemptionWitnessVar<MERKLE_HEIGHT>,
        statement_var: ValidNoteRedemptionStatementVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), PlonkError> {
        Self::circuit(&statement_var, &witness_var, cs).map_err(PlonkError::CircuitError)
    }
}

// ---------
// | Tests |
// ---------

#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    use circuit_types::note::Note;

    use crate::{
        test_helpers::{check_constraints_satisfied, random_address, random_amount},
        zk_circuits::v2::fees::valid_note_redemption::{
            SizedValidNoteRedemption, SizedValidNoteRedemptionWitness,
        },
        zk_gadgets::test_helpers::create_merkle_opening,
    };

    use super::ValidNoteRedemptionStatement;

    /// The height of the Merkle tree to test on
    const MERKLE_HEIGHT: usize = 10;

    // -----------
    // | Helpers |
    // -----------

    /// Check that the constraints are satisfied on the given witness and
    /// statement
    pub fn check_constraints(
        witness: &SizedValidNoteRedemptionWitness,
        statement: &ValidNoteRedemptionStatement,
    ) -> bool {
        check_constraints_satisfied::<SizedValidNoteRedemption>(witness, statement)
    }

    /// Construct a witness and statement with valid data
    pub fn create_dummy_witness_statement()
    -> (SizedValidNoteRedemptionWitness, ValidNoteRedemptionStatement) {
        // Create a random note
        let note = random_note();
        let note_commitment = note.commitment();
        let note_nullifier = note.nullifier();

        // Create a Merkle opening for the note
        let (note_root, note_opening) = create_merkle_opening::<MERKLE_HEIGHT>(note_commitment);

        // Build the witness and statement
        let witness = SizedValidNoteRedemptionWitness { note_opening };
        let statement = ValidNoteRedemptionStatement { note, note_root, note_nullifier };
        (witness, statement)
    }

    /// Create a random note
    fn random_note() -> Note {
        Note::new(random_address(), random_amount(), random_address())
    }
}

#[cfg(test)]
mod test {

    use crate::test_helpers::random_scalar;

    use super::*;
    use circuit_types::traits::SingleProverCircuit;
    use rand::{Rng, thread_rng};

    /// A helper to print the number of constraints in the circuit
    ///
    /// Useful when benchmarking the circuit
    #[test]
    fn test_n_constraints() {
        let layout = ValidNoteRedemption::<10>::get_circuit_layout().unwrap();

        let n_gates = layout.n_gates;
        let circuit_size = layout.circuit_size();
        println!("Number of constraints: {n_gates}");
        println!("Next power of two: {circuit_size}");
    }

    /// Test that constraints are satisfied on a valid witness and statement
    #[test]
    fn test_valid_note_redemption_constraints() {
        let (witness, statement) = test_helpers::create_dummy_witness_statement();
        assert!(test_helpers::check_constraints(&witness, &statement));
    }

    // --- Invalid Test Cases --- //

    /// Test the case in which the note root is incorrect
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid__wrong_note_root() {
        let (witness, mut statement) = test_helpers::create_dummy_witness_statement();
        statement.note_root = random_scalar();

        // Check that the constraints are not satisfied
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the note nullifier is incorrect
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid__wrong_note_nullifier() {
        let (witness, mut statement) = test_helpers::create_dummy_witness_statement();
        statement.note_nullifier = random_scalar();

        // Check that the constraints are not satisfied
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the Merkle opening is incorrect
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid__wrong_merkle_opening() {
        let mut rng = thread_rng();
        let (mut witness, statement) = test_helpers::create_dummy_witness_statement();

        // Corrupt a random element in the Merkle opening
        let random_index = rng.gen_range(0..witness.note_opening.elems.len());
        witness.note_opening.elems[random_index] = random_scalar();

        // Check that the constraints are not satisfied
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }
}
