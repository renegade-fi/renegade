//! Defines the `VALID PRIVATE PROTOCOL FEE PAYMENT` circuit
//!
//! This circuit proves that a protocol fee payment from a balance is valid.

use alloy_primitives::Address;
use circuit_macros::circuit_type;
use circuit_types::elgamal::{ElGamalCiphertext, EncryptionKey};
use circuit_types::merkle::{MerkleOpening, MerkleRoot};
use circuit_types::note::{NOTE_CIPHERTEXT_SIZE, NoteVar};
use circuit_types::traits::{BaseType, CircuitBaseType, CircuitVarType};
use circuit_types::{Commitment, Nullifier, PlonkCircuit};
use circuit_types::{
    balance::{BalanceShareVar, DarkpoolStateBalance, DarkpoolStateBalanceVar},
    ser_embedded_scalar_field,
};
use constants::{EmbeddedScalarField, MERKLE_HEIGHT, Scalar, ScalarField};
use mpc_plonk::errors::PlonkError;
use mpc_relation::{Variable, errors::CircuitError, traits::Circuit};
use serde::{Deserialize, Serialize};

use crate::SingleProverCircuit;
use crate::zk_gadgets::comparators::{EqGadget, EqZeroGadget};
use crate::zk_gadgets::note::NoteGadget;
use crate::zk_gadgets::shares::ShareGadget;
use crate::zk_gadgets::state_rotation::{StateElementRotationArgs, StateElementRotationGadget};
use crate::zk_gadgets::stream_cipher::StreamCipherGadget;

// ----------------------
// | Circuit Definition |
// ----------------------

/// A type alias for the `ValidPrivateProtocolFeePayment` circuit with default
/// size parameters attached
pub type SizedValidPrivateProtocolFeePayment = ValidPrivateProtocolFeePayment<MERKLE_HEIGHT>;

/// The `VALID PRIVATE PROTOCOL FEE PAYMENT` circuit
pub struct ValidPrivateProtocolFeePayment<const MERKLE_HEIGHT: usize>;

impl<const MERKLE_HEIGHT: usize> ValidPrivateProtocolFeePayment<MERKLE_HEIGHT> {
    /// Apply the circuit constraints to a given constraint system
    pub fn circuit(
        statement: &ValidPrivateProtocolFeePaymentStatementVar,
        witness: &ValidPrivateProtocolFeePaymentWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Verify the encryption and commitment of a note
        Self::verify_note(statement, witness, cs)?;

        // Verify the state transition of the balance
        let old_balance_private_shares = ShareGadget::compute_complementary_shares(
            &witness.old_balance.public_share,
            &witness.old_balance.inner,
            cs,
        )?;

        let (new_balance, new_balance_private_shares) = Self::compute_post_payment_balance(
            &old_balance_private_shares,
            statement,
            witness,
            cs,
        )?;

        // Verify state element rotation
        let mut rotation_args = StateElementRotationArgs {
            old_version: witness.old_balance.clone(),
            old_private_share: old_balance_private_shares,
            old_opening: witness.old_balance_opening.clone(),
            merkle_root: statement.merkle_root,
            nullifier: statement.old_balance_nullifier,
            new_version: new_balance,
            new_private_share: new_balance_private_shares,
            new_commitment: statement.new_balance_commitment,
            recovery_id: statement.recovery_id,
        };
        StateElementRotationGadget::rotate_version(&mut rotation_args, cs)
    }

    /// Create a note for the fee payment
    pub fn verify_note(
        statement: &ValidPrivateProtocolFeePaymentStatementVar,
        witness: &ValidPrivateProtocolFeePaymentWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Verify that the protocol fee balance is not zero
        // No payment is needed in this case
        let balance = &witness.old_balance.inner;
        let protocol_fee_balance_zero = EqZeroGadget::eq_zero(&balance.protocol_fee_balance, cs)?;
        cs.enforce_false(protocol_fee_balance_zero)?;

        // Build the note
        let note = NoteVar {
            mint: balance.mint,
            // Must pay the full protocol fee balance
            amount: balance.protocol_fee_balance,
            receiver: statement.protocol_fee_receiver,
            blinder: witness.blinder,
        };

        // Verify the encryption of the note
        NoteGadget::verify_note_encryption(
            &note,
            &statement.protocol_encryption_key,
            witness.encryption_randomness,
            &statement.note_ciphertext,
            cs,
        )?;

        // Verify the commitment of the note
        NoteGadget::verify_note_commitment(&note, statement.note_commitment, cs)?;
        Ok(())
    }

    /// Compute the post-payment balance
    ///
    /// Returns the new balance, the new private shares, and the new public
    /// shares.
    pub fn compute_post_payment_balance(
        old_balance_private_shares: &BalanceShareVar,
        statement: &ValidPrivateProtocolFeePaymentStatementVar,
        witness: &ValidPrivateProtocolFeePaymentWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(DarkpoolStateBalanceVar, BalanceShareVar), CircuitError> {
        // Update the balance
        let mut new_balance = witness.old_balance.clone();
        let mut new_balance_private_shares = old_balance_private_shares.clone();

        // Re-encrypt the protocol fee balance field as it's changed
        new_balance.inner.protocol_fee_balance = cs.zero();
        let (new_fee_private_share, new_fee_public_share) = StreamCipherGadget::encrypt::<Variable>(
            &new_balance.inner.protocol_fee_balance,
            &mut new_balance.share_stream,
            cs,
        )?;
        new_balance_private_shares.protocol_fee_balance = new_fee_private_share;
        new_balance.public_share.protocol_fee_balance = new_fee_public_share;
        EqGadget::constrain_eq(
            &new_fee_public_share,
            &statement.new_protocol_fee_balance_share,
            cs,
        )?;

        Ok((new_balance, new_balance_private_shares))
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for `VALID PRIVATE PROTOCOL FEE PAYMENT`
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidPrivateProtocolFeePaymentWitness<const MERKLE_HEIGHT: usize> {
    /// The old balance
    pub old_balance: DarkpoolStateBalance,
    /// The opening of the old balance to the Merkle root
    pub old_balance_opening: MerkleOpening<MERKLE_HEIGHT>,
    /// The blinder samples for the note
    pub blinder: Scalar,
    /// The randomness used in the encryption of the note
    #[serde(with = "ser_embedded_scalar_field")]
    pub encryption_randomness: EmbeddedScalarField,
}

/// A `VALID PRIVATE PROTOCOL FEE PAYMENT` witness with default const generic
/// sizing parameters
pub type SizedValidPrivateProtocolFeePaymentWitness =
    ValidPrivateProtocolFeePaymentWitness<MERKLE_HEIGHT>;

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for `VALID PRIVATE PROTOCOL FEE PAYMENT`
#[circuit_type(singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidPrivateProtocolFeePaymentStatement {
    // --- Balance State Transition Elements --- //
    /// The Merkle root to which the balance opens
    pub merkle_root: MerkleRoot,
    /// The nullifier of the previous balance
    pub old_balance_nullifier: Nullifier,
    /// The commitment to the new balance
    pub new_balance_commitment: Commitment,
    /// The new recovery identifier of the balance
    pub recovery_id: Scalar,
    /// The new encrypted protocol fee balance (public share) of the balance
    pub new_protocol_fee_balance_share: Scalar,

    // --- Note Encryption Elements --- //
    /// The protocol fee receiver
    pub protocol_fee_receiver: Address,
    /// The commitment to the note
    pub note_commitment: Commitment,
    /// The note ciphertext
    ///
    /// This will be verified to be encrypted under the protocol key.
    pub note_ciphertext: ElGamalCiphertext<NOTE_CIPHERTEXT_SIZE>,
    /// The key under which the note is claimed to be encrypted
    pub protocol_encryption_key: EncryptionKey,
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl<const MERKLE_HEIGHT: usize> SingleProverCircuit
    for ValidPrivateProtocolFeePayment<MERKLE_HEIGHT>
{
    type Witness = ValidPrivateProtocolFeePaymentWitness<MERKLE_HEIGHT>;
    type Statement = ValidPrivateProtocolFeePaymentStatement;

    fn name() -> String {
        format!("Valid Private Protocol Fee Payment ({MERKLE_HEIGHT})")
    }

    fn apply_constraints(
        witness_var: ValidPrivateProtocolFeePaymentWitnessVar<MERKLE_HEIGHT>,
        statement_var: ValidPrivateProtocolFeePaymentStatementVar,
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
    use alloy_primitives::Address;
    use circuit_types::{
        balance::{Balance, DarkpoolStateBalance},
        note::Note,
    };
    use constants::Scalar;
    use rand::thread_rng;

    use crate::{
        test_helpers::{
            check_constraints_satisfied, random_address, random_amount,
            random_elgamal_encryption_key,
        },
        zk_circuits::v2::fees::valid_private_protocol_fee_payment::{
            SizedValidPrivateProtocolFeePayment, SizedValidPrivateProtocolFeePaymentWitness,
        },
        zk_gadgets::test_helpers::{create_merkle_opening, create_state_wrapper},
    };

    use super::ValidPrivateProtocolFeePaymentStatement;

    /// The height of the Merkle tree to test on
    const MERKLE_HEIGHT: usize = 10;

    // -----------
    // | Helpers |
    // -----------

    /// Check that the constraints are satisfied on the given witness and
    /// statement
    pub fn check_constraints(
        witness: &SizedValidPrivateProtocolFeePaymentWitness,
        statement: &ValidPrivateProtocolFeePaymentStatement,
    ) -> bool {
        check_constraints_satisfied::<SizedValidPrivateProtocolFeePayment>(witness, statement)
    }

    /// Construct a witness and statement with valid data
    pub fn create_dummy_witness_statement()
    -> (SizedValidPrivateProtocolFeePaymentWitness, ValidPrivateProtocolFeePaymentStatement) {
        // Sample random protocol constants
        let protocol_fee_receiver = random_address();
        let protocol_encryption_key = random_elgamal_encryption_key();

        // The address to which protocol fees are paid
        let old_balance = create_state_wrapper(Balance {
            mint: random_address(),
            relayer_fee_recipient: Address::ZERO,
            owner: random_address(),
            one_time_authority: Address::ZERO,
            relayer_fee_balance: random_amount(),
            protocol_fee_balance: random_amount(),
            amount: random_amount(),
        });

        // Compute commitment, nullifier, and Merkle opening for the old balance
        let old_balance_commitment = old_balance.compute_commitment();
        let old_balance_nullifier = old_balance.compute_nullifier();
        let (merkle_root, old_balance_opening) =
            create_merkle_opening::<MERKLE_HEIGHT>(old_balance_commitment);

        // Create the note for the protocol fee payment
        let note = create_note(&old_balance.inner, protocol_fee_receiver);
        let (note_ciphertext, encryption_randomness) = note.encrypt(&protocol_encryption_key);
        let note_commitment = note.commitment();

        // Create the new balance with protocol fee balance = 0
        // Then compute recovery_id, which will advance the recovery stream
        let mut new_balance = create_new_balance(&old_balance);
        let recovery_id = new_balance.compute_recovery_id();
        let new_balance_commitment = new_balance.compute_commitment();

        // Build the witness and statement
        let witness = SizedValidPrivateProtocolFeePaymentWitness {
            old_balance,
            old_balance_opening,
            blinder: note.blinder,
            encryption_randomness,
        };

        let statement = ValidPrivateProtocolFeePaymentStatement {
            merkle_root,
            old_balance_nullifier,
            new_balance_commitment,
            recovery_id,
            new_protocol_fee_balance_share: new_balance.public_share.protocol_fee_balance,
            protocol_fee_receiver,
            note_commitment,
            note_ciphertext,
            protocol_encryption_key,
        };

        (witness, statement)
    }

    /// Create a note for the given balance's protocol fee payment
    fn create_note(balance: &Balance, protocol_fee_receiver: Address) -> Note {
        let mut rng = thread_rng();
        let blinder = Scalar::random(&mut rng);
        Note {
            mint: balance.mint,
            amount: balance.protocol_fee_balance,
            receiver: protocol_fee_receiver,
            blinder,
        }
    }

    /// Create a new balance from the given old balance with the protocol fee
    /// balance zeroed out
    ///
    /// Returns the new balance, the new private shares, and the new public
    /// shares.
    fn create_new_balance(old_balance: &DarkpoolStateBalance) -> DarkpoolStateBalance {
        let mut new_balance = old_balance.clone();
        new_balance.inner.protocol_fee_balance = 0;
        let new_fee_balance_public_share = new_balance.stream_cipher_encrypt(&Scalar::zero());
        new_balance.public_share.protocol_fee_balance = new_fee_balance_public_share;

        new_balance
    }
}

#[cfg(test)]
mod test {

    use crate::test_helpers::{random_address, random_elgamal_encryption_key, random_scalar};

    use super::*;
    use circuit_types::{note::Note, traits::SingleProverCircuit};
    use rand::{Rng, RngCore, thread_rng};

    /// A helper to print the number of constraints in the circuit
    ///
    /// Useful when benchmarking the circuit
    #[test]
    fn test_n_constraints() {
        let layout = ValidPrivateProtocolFeePayment::<10>::get_circuit_layout().unwrap();

        let n_gates = layout.n_gates;
        let circuit_size = layout.circuit_size();
        println!("Number of constraints: {n_gates}");
        println!("Next power of two: {circuit_size}");
    }

    /// Test that constraints are satisfied on a valid witness and statement
    #[test]
    fn test_valid_protocol_fee_payment_constraints() {
        let (witness, statement) = test_helpers::create_dummy_witness_statement();
        assert!(test_helpers::check_constraints(&witness, &statement));
    }

    // --- Invalid Note Test Cases --- //

    /// Test the case in which the note does not pay for the full balance
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_note__partial_payment() {
        let (mut witness, mut statement) = test_helpers::create_dummy_witness_statement();
        let balance = &witness.old_balance.inner;
        let invalid_note = Note {
            mint: balance.mint,
            amount: balance.protocol_fee_balance - 1,
            receiver: statement.protocol_fee_receiver,
            blinder: witness.blinder,
        };
        (statement.note_ciphertext, witness.encryption_randomness) =
            invalid_note.encrypt(&statement.protocol_encryption_key);
        statement.note_commitment = invalid_note.commitment();

        // Check that the constraints are not satisfied
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the note mint is incorrect
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_note__incorrect_mint() {
        let (mut witness, mut statement) = test_helpers::create_dummy_witness_statement();
        let balance = &witness.old_balance.inner;
        let invalid_note = Note {
            mint: random_address(),
            amount: balance.protocol_fee_balance,
            receiver: statement.protocol_fee_receiver,
            blinder: witness.blinder,
        };
        (statement.note_ciphertext, witness.encryption_randomness) =
            invalid_note.encrypt(&statement.protocol_encryption_key);
        statement.note_commitment = invalid_note.commitment();

        // Check that the constraints are not satisfied
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the note's receive is not correct
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_note__incorrect_receiver() {
        let (witness, mut statement) = test_helpers::create_dummy_witness_statement();
        statement.protocol_fee_receiver = random_address();

        // Check that the constraints are not satisfied
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the note's blinder doesn't match the witness
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_note__incorrect_blinder() {
        let (mut witness, statement) = test_helpers::create_dummy_witness_statement();
        witness.blinder = random_scalar();

        // Check that the constraints are not satisfied
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the note's commitment has been tampered with
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_note__tampered_commitment() {
        let (witness, mut statement) = test_helpers::create_dummy_witness_statement();
        statement.note_commitment = random_scalar();

        // Check that the constraints are not satisfied
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the note's ciphertext has been tampered with
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_note__tampered_ciphertext() {
        let mut rng = thread_rng();
        let (witness, mut statement) = test_helpers::create_dummy_witness_statement();

        // Modify one index in the ciphertext
        let mut ciphertext_scalars = statement.note_ciphertext.to_scalars();
        let random_idx = rng.gen_range(0..ciphertext_scalars.len());
        ciphertext_scalars[random_idx] = random_scalar();
        statement.note_ciphertext =
            ElGamalCiphertext::from_scalars(&mut ciphertext_scalars.into_iter());

        // Check that the constraints are not satisfied
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the protocol encryption key is incorrect
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_note__incorrect_encryption_key() {
        let (witness, mut statement) = test_helpers::create_dummy_witness_statement();
        statement.protocol_encryption_key = random_elgamal_encryption_key();

        // Check that the constraints are not satisfied
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the encryption randomness is incorrect
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_note__incorrect_encryption_randomness() {
        let mut rng = thread_rng();
        let (mut witness, statement) = test_helpers::create_dummy_witness_statement();
        witness.encryption_randomness = From::<u64>::from(rng.next_u64());

        // Check that the constraints are not satisfied
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    // Other state rotation test cases are covered by the state rotation gadgets
    // in the `StateElementRotationGadget` test suite
}
