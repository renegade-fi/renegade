//! Defines the `VALID PUBLIC RELAYER FEE PAYMENT` circuit
//!
//! This circuit proves that a public relayer fee payment from a balance is
//! valid. Since the note is public, there is no encryption or commitment
//! needed.

use circuit_macros::circuit_type;
use circuit_types::balance::{BalanceShareVar, DarkpoolStateBalance, DarkpoolStateBalanceVar};
use circuit_types::merkle::{MerkleOpening, MerkleRoot};
use circuit_types::note::Note;
use circuit_types::traits::{BaseType, CircuitBaseType, CircuitVarType};
use circuit_types::{Commitment, Nullifier, PlonkCircuit};
use constants::{MERKLE_HEIGHT, Scalar, ScalarField};
use mpc_plonk::errors::PlonkError;
use mpc_relation::{Variable, errors::CircuitError, traits::Circuit};
use serde::{Deserialize, Serialize};

use crate::SingleProverCircuit;
use crate::zk_gadgets::comparators::{EqGadget, EqZeroGadget};
use crate::zk_gadgets::{
    ShareGadget, StateElementRotationArgs, StateElementRotationGadget, StreamCipherGadget,
};

// ----------------------
// | Circuit Definition |
// ----------------------

/// A type alias for the `ValidPublicRelayerFeePayment` circuit with default
/// size parameters attached
pub type SizedValidPublicRelayerFeePayment = ValidPublicRelayerFeePayment<MERKLE_HEIGHT>;

/// The `VALID PUBLIC RELAYER FEE PAYMENT` circuit
pub struct ValidPublicRelayerFeePayment<const MERKLE_HEIGHT: usize>;

impl<const MERKLE_HEIGHT: usize> ValidPublicRelayerFeePayment<MERKLE_HEIGHT> {
    /// Apply the circuit constraints to a given constraint system
    pub fn circuit(
        statement: &ValidPublicRelayerFeePaymentStatementVar,
        witness: &ValidPublicRelayerFeePaymentWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Verify the note
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

    /// Verify the note
    pub fn verify_note(
        statement: &ValidPublicRelayerFeePaymentStatementVar,
        witness: &ValidPublicRelayerFeePaymentWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let note = &statement.note;
        let balance = &witness.old_balance.inner;

        // Verify that the relayer fee balance is not zero
        // No payment is needed in this case
        let relayer_fee_balance_zero = EqZeroGadget::eq_zero(&balance.relayer_fee_balance, cs)?;
        cs.enforce_false(relayer_fee_balance_zero)?;

        // Verify the note matches the balance
        // The receiver must be the same as the balance's relayer fee recipient
        // The blinder is unused as nothing is encrypted.
        EqGadget::constrain_eq(&note.mint, &balance.mint, cs)?;
        EqGadget::constrain_eq(&note.amount, &balance.relayer_fee_balance, cs)?;
        EqGadget::constrain_eq(&note.receiver, &balance.relayer_fee_recipient, cs)
    }

    /// Compute the post-payment balance
    ///
    /// Returns the new balance, the new private shares, and the new public
    /// shares.
    pub fn compute_post_payment_balance(
        old_balance_private_shares: &BalanceShareVar,
        statement: &ValidPublicRelayerFeePaymentStatementVar,
        witness: &ValidPublicRelayerFeePaymentWitnessVar<MERKLE_HEIGHT>,
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

/// The witness type for `VALID PUBLIC RELAYER FEE PAYMENT`
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidPublicRelayerFeePaymentWitness<const MERKLE_HEIGHT: usize> {
    /// The old balance
    pub old_balance: DarkpoolStateBalance,
    /// The opening of the old balance to the Merkle root
    pub old_balance_opening: MerkleOpening<MERKLE_HEIGHT>,
}

/// A `VALID PUBLIC RELAYER FEE PAYMENT` witness with default const generic
/// sizing parameters
pub type SizedValidPublicRelayerFeePaymentWitness =
    ValidPublicRelayerFeePaymentWitness<MERKLE_HEIGHT>;

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for `VALID PUBLIC RELAYER FEE PAYMENT`
#[circuit_type(singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidPublicRelayerFeePaymentStatement {
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
    ///
    /// Leaked here to enable recovery logic to compute the new balance state
    pub new_relayer_fee_balance_share: Scalar,

    // --- Note Elements --- //
    /// The note which is being created
    pub note: Note,
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl<const MERKLE_HEIGHT: usize> SingleProverCircuit
    for ValidPublicRelayerFeePayment<MERKLE_HEIGHT>
{
    type Witness = ValidPublicRelayerFeePaymentWitness<MERKLE_HEIGHT>;
    type Statement = ValidPublicRelayerFeePaymentStatement;

    fn name() -> String {
        format!("Valid Public Relayer Fee Payment ({MERKLE_HEIGHT})")
    }

    fn apply_constraints(
        witness_var: ValidPublicRelayerFeePaymentWitnessVar<MERKLE_HEIGHT>,
        statement_var: ValidPublicRelayerFeePaymentStatementVar,
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
        zk_circuits::fees::valid_public_relayer_fee_payment::{
            SizedValidPublicRelayerFeePayment, SizedValidPublicRelayerFeePaymentWitness,
        },
    };

    use super::ValidPublicRelayerFeePaymentStatement;

    /// The height of the Merkle tree to test on
    const MERKLE_HEIGHT: usize = 10;

    // -----------
    // | Helpers |
    // -----------

    /// Check that the constraints are satisfied on the given witness and
    /// statement
    pub fn check_constraints(
        witness: &SizedValidPublicRelayerFeePaymentWitness,
        statement: &ValidPublicRelayerFeePaymentStatement,
    ) -> bool {
        check_constraints_satisfied::<SizedValidPublicRelayerFeePayment>(witness, statement)
    }

    /// Construct a witness and statement with valid data
    pub fn create_dummy_witness_statement()
    -> (SizedValidPublicRelayerFeePaymentWitness, ValidPublicRelayerFeePaymentStatement) {
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
    ) -> (SizedValidPublicRelayerFeePaymentWitness, ValidPublicRelayerFeePaymentStatement) {
        // Compute commitment, nullifier, and Merkle opening for the old balance
        let old_balance_commitment = old_balance.compute_commitment();
        let old_balance_nullifier = old_balance.compute_nullifier();
        let (merkle_root, old_balance_opening) =
            create_merkle_opening::<MERKLE_HEIGHT>(old_balance_commitment);

        // Create the note for the relayer fee payment
        let note = create_note(&old_balance.inner);

        // Create the new balance with relayer fee balance = 0
        let mut new_balance = create_new_balance(&old_balance);

        // Compute recovery_id, which will advance the recovery stream
        let recovery_id = new_balance.compute_recovery_id();
        let new_balance_commitment = new_balance.compute_commitment();

        // Build the witness and statement
        let witness = SizedValidPublicRelayerFeePaymentWitness { old_balance, old_balance_opening };

        let statement = ValidPublicRelayerFeePaymentStatement {
            merkle_root,
            old_balance_nullifier,
            new_balance_commitment,
            recovery_id,
            new_relayer_fee_balance_share: new_balance.public_share.relayer_fee_balance,
            note,
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

    use crate::test_helpers::{create_random_state_wrapper, random_address, random_amount};

    use super::test_helpers::create_dummy_witness_statement_with_balance;
    use super::*;
    use alloy_primitives::Address;
    use circuit_types::{balance::Balance, traits::SingleProverCircuit};

    /// A helper to print the number of constraints in the circuit
    ///
    /// Useful when benchmarking the circuit
    #[test]
    fn test_n_constraints() {
        let layout = ValidPublicRelayerFeePayment::<10>::get_circuit_layout().unwrap();

        let n_gates = layout.n_gates;
        let circuit_size = layout.circuit_size();
        println!("Number of constraints: {n_gates}");
        println!("Next power of two: {circuit_size}");
    }

    /// Test that constraints are satisfied on a valid witness and statement
    #[test]
    fn test_valid_public_relayer_fee_payment_constraints() {
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
        statement.note.amount = balance.relayer_fee_balance - 1;

        // Check that the constraints are not satisfied
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the note mint is incorrect
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_note__incorrect_mint() {
        let (witness, mut statement) = test_helpers::create_dummy_witness_statement();
        statement.note.mint = random_address();

        // Check that the constraints are not satisfied
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the note receiver is incorrect
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_note__incorrect_receiver() {
        let (witness, mut statement) = test_helpers::create_dummy_witness_statement();
        statement.note.receiver = random_address();

        // Check that the constraints are not satisfied
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the note amount exceeds the relayer fee balance
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_note__over_payment() {
        let (witness, mut statement) = test_helpers::create_dummy_witness_statement();
        let balance = &witness.old_balance.inner;
        statement.note.amount = balance.relayer_fee_balance + 1;

        // Check that the constraints are not satisfied
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    // Other state rotation test cases are covered by the state rotation gadgets
    // in the `StateElementRotationGadget` test suite
}
