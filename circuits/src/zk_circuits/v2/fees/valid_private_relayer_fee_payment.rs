//! Defines the `VALID PRIVATE RELAYER FEE PAYMENT` circuit
//!
//! This circuit proves that a relayer fee payment from a balance is valid.

use alloy_primitives::Address;
use circuit_macros::circuit_type;
use circuit_types::balance::{BalanceShareVar, DarkpoolStateBalance, DarkpoolStateBalanceVar};
use circuit_types::merkle::{MerkleOpening, MerkleRoot};
use circuit_types::note::NoteVar;
use circuit_types::traits::{BaseType, CircuitBaseType, CircuitVarType};
use circuit_types::{Commitment, Nullifier, PlonkCircuit};
use constants::{MERKLE_HEIGHT, Scalar, ScalarField};
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

/// A type alias for the `ValidPrivateRelayerFeePayment` circuit with default
/// size parameters attached
pub type SizedValidPrivateRelayerFeePayment = ValidPrivateRelayerFeePayment<MERKLE_HEIGHT>;

/// The `VALID PRIVATE RELAYER FEE PAYMENT` circuit
pub struct ValidPrivateRelayerFeePayment<const MERKLE_HEIGHT: usize>;

impl<const MERKLE_HEIGHT: usize> ValidPrivateRelayerFeePayment<MERKLE_HEIGHT> {
    /// Apply the circuit constraints to a given constraint system
    pub fn circuit(
        statement: &ValidPrivateRelayerFeePaymentStatementVar,
        witness: &ValidPrivateRelayerFeePaymentWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Verify the construction and commitment of a note
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
        statement: &ValidPrivateRelayerFeePaymentStatementVar,
        witness: &ValidPrivateRelayerFeePaymentWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Verify that the relayer fee balance is not zero
        // No payment is needed in this case
        let balance = &witness.old_balance.inner;
        let relayer_fee_balance_zero = EqZeroGadget::eq_zero(&balance.relayer_fee_balance, cs)?;
        cs.enforce_false(relayer_fee_balance_zero)?;

        // Build the note
        let note = NoteVar {
            mint: balance.mint,
            // Must pay the full relayer fee balance
            amount: balance.relayer_fee_balance,
            receiver: balance.relayer_fee_recipient,
            blinder: witness.blinder,
        };
        EqGadget::constrain_eq(&statement.relayer_fee_receiver, &note.receiver, cs)?;

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
        statement: &ValidPrivateRelayerFeePaymentStatementVar,
        witness: &ValidPrivateRelayerFeePaymentWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(DarkpoolStateBalanceVar, BalanceShareVar), CircuitError> {
        // Update the balance
        let mut new_balance = witness.old_balance.clone();
        let mut new_balance_private_shares = old_balance_private_shares.clone();

        // Re-encrypt the relayer fee balance field as it's changed
        new_balance.inner.relayer_fee_balance = cs.zero();
        let (new_fee_private_share, new_fee_public_share) = StreamCipherGadget::encrypt::<Variable>(
            &new_balance.inner.relayer_fee_balance,
            &mut new_balance.share_stream,
            cs,
        )?;
        new_balance_private_shares.relayer_fee_balance = new_fee_private_share;
        new_balance.public_share.relayer_fee_balance = new_fee_public_share;
        EqGadget::constrain_eq(
            &new_fee_public_share,
            &statement.new_relayer_fee_balance_share,
            cs,
        )?;

        Ok((new_balance, new_balance_private_shares))
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for `VALID PRIVATE RELAYER FEE PAYMENT`
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidPrivateRelayerFeePaymentWitness<const MERKLE_HEIGHT: usize> {
    /// The old balance
    pub old_balance: DarkpoolStateBalance,
    /// The opening of the old balance to the Merkle root
    pub old_balance_opening: MerkleOpening<MERKLE_HEIGHT>,
    /// The blinder samples for the note
    pub blinder: Scalar,
}

/// A `VALID PRIVATE RELAYER FEE PAYMENT` witness with default const generic
/// sizing parameters
pub type SizedValidPrivateRelayerFeePaymentWitness =
    ValidPrivateRelayerFeePaymentWitness<MERKLE_HEIGHT>;

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for `VALID PRIVATE RELAYER FEE PAYMENT`
#[circuit_type(singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidPrivateRelayerFeePaymentStatement {
    // --- Balance State Transition Elements --- //
    /// The Merkle root to which the balance opens
    pub merkle_root: MerkleRoot,
    /// The nullifier of the previous balance
    pub old_balance_nullifier: Nullifier,
    /// The commitment to the new balance
    pub new_balance_commitment: Commitment,
    /// The new recovery identifier of the balance
    pub recovery_id: Scalar,
    /// The new encrypted relayer fee balance (public share) of the balance
    pub new_relayer_fee_balance_share: Scalar,

    // --- Note Elements --- //
    /// The relayer fee receiver
    ///
    /// This is constrained to be the same as the address on the balance itself.
    /// We leak this value so that the contracts may check that the fee receiver
    /// has signed the note encryption. This allows us to verify the encryption
    /// out-of-circuit by allowing the recipient to authorize it.
    pub relayer_fee_receiver: Address,
    /// The commitment to the note
    pub note_commitment: Commitment,
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl<const MERKLE_HEIGHT: usize> SingleProverCircuit
    for ValidPrivateRelayerFeePayment<MERKLE_HEIGHT>
{
    type Witness = ValidPrivateRelayerFeePaymentWitness<MERKLE_HEIGHT>;
    type Statement = ValidPrivateRelayerFeePaymentStatement;

    fn name() -> String {
        format!("Valid Private Relayer Fee Payment ({MERKLE_HEIGHT})")
    }

    fn apply_constraints(
        witness_var: ValidPrivateRelayerFeePaymentWitnessVar<MERKLE_HEIGHT>,
        statement_var: ValidPrivateRelayerFeePaymentStatementVar,
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
            check_constraints_satisfied, create_merkle_opening, create_random_state_wrapper,
            random_address, random_amount,
        },
        zk_circuits::v2::fees::valid_private_relayer_fee_payment::{
            SizedValidPrivateRelayerFeePayment, SizedValidPrivateRelayerFeePaymentWitness,
        },
    };

    use super::ValidPrivateRelayerFeePaymentStatement;

    /// The height of the Merkle tree to test on
    const MERKLE_HEIGHT: usize = 10;

    // -----------
    // | Helpers |
    // -----------

    /// Check that the constraints are satisfied on the given witness and
    /// statement
    pub fn check_constraints(
        witness: &SizedValidPrivateRelayerFeePaymentWitness,
        statement: &ValidPrivateRelayerFeePaymentStatement,
    ) -> bool {
        check_constraints_satisfied::<SizedValidPrivateRelayerFeePayment>(witness, statement)
    }

    /// Construct a witness and statement with valid data
    pub fn create_dummy_witness_statement()
    -> (SizedValidPrivateRelayerFeePaymentWitness, ValidPrivateRelayerFeePaymentStatement) {
        // The balance from which relayer fees are paid
        let old_balance = create_random_state_wrapper(Balance {
            mint: random_address(),
            relayer_fee_recipient: random_address(),
            owner: random_address(),
            one_time_authority: Address::ZERO,
            relayer_fee_balance: random_amount(),
            protocol_fee_balance: random_amount(),
            amount: random_amount(),
        });
        create_dummy_witness_statement_with_balance(old_balance)
    }

    /// Create a dummy witness and statement with a given balance
    pub fn create_dummy_witness_statement_with_balance(
        old_balance: DarkpoolStateBalance,
    ) -> (SizedValidPrivateRelayerFeePaymentWitness, ValidPrivateRelayerFeePaymentStatement) {
        // Compute commitment, nullifier, and Merkle opening for the old balance
        let old_balance_commitment = old_balance.compute_commitment();
        let old_balance_nullifier = old_balance.compute_nullifier();
        let (merkle_root, old_balance_opening) =
            create_merkle_opening::<MERKLE_HEIGHT>(old_balance_commitment);

        // Create the note for the relayer fee payment
        let note = create_note(&old_balance.inner);
        let note_commitment = note.commitment();
        let relayer_fee_recipient = old_balance.inner.relayer_fee_recipient;

        // Create the new balance with relayer fee balance = 0
        let mut new_balance = create_new_balance(&old_balance);
        let recovery_id = new_balance.compute_recovery_id();
        let new_balance_commitment = new_balance.compute_commitment();

        // Build the witness and statement
        let witness = SizedValidPrivateRelayerFeePaymentWitness {
            old_balance,
            old_balance_opening,
            blinder: note.blinder,
        };

        let statement = ValidPrivateRelayerFeePaymentStatement {
            merkle_root,
            old_balance_nullifier,
            new_balance_commitment,
            recovery_id,
            new_relayer_fee_balance_share: new_balance.public_share.relayer_fee_balance,
            relayer_fee_receiver: relayer_fee_recipient,
            note_commitment,
        };

        (witness, statement)
    }

    /// Create a note for the given balance's relayer fee payment
    fn create_note(balance: &Balance) -> Note {
        let mut rng = thread_rng();
        let blinder = Scalar::random(&mut rng);
        Note {
            mint: balance.mint,
            amount: balance.relayer_fee_balance,
            receiver: balance.relayer_fee_recipient,
            blinder,
        }
    }

    /// Create a new balance from the given old balance with the relayer fee
    /// balance zeroed out
    ///
    /// Returns the new balance, the new private shares, and the new public
    /// shares.
    fn create_new_balance(old_balance: &DarkpoolStateBalance) -> DarkpoolStateBalance {
        let mut new_balance = old_balance.clone();
        new_balance.inner.relayer_fee_balance = 0;
        let new_fee_balance_public_share = new_balance.stream_cipher_encrypt(&Scalar::zero());
        new_balance.public_share.relayer_fee_balance = new_fee_balance_public_share;

        new_balance
    }
}

#[cfg(test)]
mod test {

    use crate::test_helpers::{
        create_random_state_wrapper, random_address, random_amount, random_scalar,
    };

    use super::test_helpers::create_dummy_witness_statement_with_balance;
    use super::*;
    use alloy_primitives::Address;
    use circuit_types::{balance::Balance, note::Note, traits::SingleProverCircuit};

    /// A helper to print the number of constraints in the circuit
    ///
    /// Useful when benchmarking the circuit
    #[test]
    fn test_n_constraints() {
        let layout = ValidPrivateRelayerFeePayment::<10>::get_circuit_layout().unwrap();

        let n_gates = layout.n_gates;
        let circuit_size = layout.circuit_size();
        println!("Number of constraints: {n_gates}");
        println!("Next power of two: {circuit_size}");
    }

    /// Test that constraints are satisfied on a valid witness and statement
    #[test]
    fn test_valid_relayer_fee_payment_constraints() {
        let (witness, statement) = test_helpers::create_dummy_witness_statement();
        assert!(test_helpers::check_constraints(&witness, &statement));
    }

    // --- Invalid Note Test Cases --- //

    /// Test the case in which the relayer fee balance is zero
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid__zero_relayer_fee_balance() {
        let balance = create_random_state_wrapper(Balance {
            mint: random_address(),
            relayer_fee_recipient: random_address(),
            owner: random_address(),
            one_time_authority: Address::ZERO,
            relayer_fee_balance: 0u128,
            protocol_fee_balance: random_amount(),
            amount: random_amount(),
        });

        let (witness, statement) = create_dummy_witness_statement_with_balance(balance);

        // Check that the constraints are not satisfied
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the note does not pay for the full balance
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_note__partial_payment() {
        let (witness, mut statement) = test_helpers::create_dummy_witness_statement();
        let balance = &witness.old_balance.inner;
        let invalid_note = Note {
            mint: balance.mint,
            amount: balance.relayer_fee_balance - 1,
            receiver: statement.relayer_fee_receiver,
            blinder: witness.blinder,
        };
        statement.note_commitment = invalid_note.commitment();

        // Check that the constraints are not satisfied
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the note mint is incorrect
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_note__incorrect_mint() {
        let (witness, mut statement) = test_helpers::create_dummy_witness_statement();
        let balance = &witness.old_balance.inner;
        let invalid_note = Note {
            mint: random_address(),
            amount: balance.relayer_fee_balance,
            receiver: statement.relayer_fee_receiver,
            blinder: witness.blinder,
        };
        statement.note_commitment = invalid_note.commitment();

        // Check that the constraints are not satisfied
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the note's receiver is not correct
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_note__incorrect_receiver() {
        let (witness, mut statement) = test_helpers::create_dummy_witness_statement();
        statement.relayer_fee_receiver = random_address();

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

    // Other state rotation test cases are covered by the state rotation gadgets
    // in the `StateElementRotationGadget` test suite
}
