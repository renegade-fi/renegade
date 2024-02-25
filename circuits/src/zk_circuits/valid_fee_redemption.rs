//! Settles a note into the recipient wallet, nullifying the note in the global
//! state

use circuit_macros::circuit_type;
use circuit_types::elgamal::DecryptionKey;
use circuit_types::keychain::PublicSigningKey;
use circuit_types::PlonkCircuit;
use circuit_types::{
    merkle::{MerkleOpening, MerkleRoot},
    note::{Note, NoteVar},
    traits::{BaseType, CircuitBaseType, CircuitVarType, SingleProverCircuit},
    wallet::{Nullifier, WalletShare, WalletShareStateCommitment, WalletVar},
};
use constants::{Scalar, ScalarField};
use mpc_plonk::errors::PlonkError;
use mpc_relation::errors::CircuitError;
use mpc_relation::{traits::Circuit, Variable};

use crate::zk_gadgets::comparators::{EqGadget, EqVecGadget};
use crate::zk_gadgets::elgamal::ElGamalGadget;
use crate::zk_gadgets::merkle::PoseidonMerkleHashGadget;
use crate::zk_gadgets::note::NoteGadget;
use crate::zk_gadgets::select::CondSelectGadget;
use crate::zk_gadgets::wallet_operations::{AmountGadget, WalletGadget};

// ----------------------
// | Circuit Definition |
// ----------------------

/// The `VALID FEE REDEMPTION` circuit
pub struct ValidFeeRedemption<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MERKLE_HEIGHT: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized;
impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MERKLE_HEIGHT: usize>
    ValidFeeRedemption<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    fn circuit(
        statement: &ValidFeeRedemptionStatementVar<MAX_BALANCES, MAX_ORDERS>,
        witness: &ValidFeeRedemptionWitnessVar<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // --- Input Validity --- //
        // Verify the nullifier and Merkle opening of the original wallet
        WalletGadget::validate_wallet_transition(
            &witness.old_wallet_public_shares,
            &witness.old_wallet_private_shares,
            &witness.wallet_opening,
            statement.wallet_root,
            statement.wallet_nullifier,
            cs,
        )?;

        // Verify the commitment to the new wallet private shares
        let expected_commit =
            WalletGadget::compute_private_commitment(&witness.new_wallet_private_shares, cs)?;
        EqGadget::constrain_eq(&expected_commit, &statement.new_wallet_commitment, cs)?;

        // Verify the Merkle opening of the note
        let note_commit = NoteGadget::compute_note_commitment(&witness.note, cs)?;
        PoseidonMerkleHashGadget::compute_and_constrain_root_prehashed(
            note_commit,
            &witness.note_opening,
            statement.note_root,
            cs,
        )?;

        // Verify the nullifier of the note
        NoteGadget::verify_note_nullifier(
            note_commit,
            witness.note.blinder,
            statement.note_nullifier,
            cs,
        )?;

        // --- Authorization --- //
        let old_wallet = WalletGadget::wallet_from_shares(
            &witness.old_wallet_public_shares,
            &witness.old_wallet_private_shares,
            cs,
        )?;
        let new_wallet = WalletGadget::wallet_from_shares(
            &statement.new_wallet_public_shares,
            &witness.new_wallet_private_shares,
            cs,
        )?;

        // Verify the public root key of the recipient
        EqGadget::constrain_eq(&old_wallet.keys.pk_root, &statement.recipient_root_key, cs)?;

        // Verify that the recipient is the intended recipient of the note
        ElGamalGadget::verify_decryption_key(&witness.recipient_key, &witness.note.receiver, cs)?;

        // --- State Transition --- //
        Self::verify_wallet_transition(
            witness.receive_index,
            &witness.note,
            &old_wallet,
            &new_wallet,
            cs,
        )
    }

    /// Verify the state transition of the wallet after settlement
    fn verify_wallet_transition(
        receiver_idx: Variable,
        note: &NoteVar,
        old_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS>,
        new_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // All orders should remain the same
        EqGadget::constrain_eq(&old_wallet.orders, &new_wallet.orders, cs)?;

        // The match fee and managing cluster key should remain the same
        EqGadget::constrain_eq(&old_wallet.match_fee, &new_wallet.match_fee, cs)?;
        EqGadget::constrain_eq(&old_wallet.managing_cluster, &new_wallet.managing_cluster, cs)?;

        // The match key should remain the same, the root key may rotate
        EqGadget::constrain_eq(&old_wallet.keys.pk_match, &new_wallet.keys.pk_match, cs)?;

        // Verify the balance updates
        let zero_var = cs.zero();
        let one_var = cs.one();
        let mut curr_idx = zero_var;
        let mut found = cs.false_var();

        for (old_bal, new_bal) in old_wallet.balances.iter().zip(new_wallet.balances.iter()) {
            // Mask the index
            let is_receive_idx = EqGadget::eq(&curr_idx, &receiver_idx, cs)?;
            let is_not_receive_idx = cs.logic_neg(is_receive_idx)?;
            found = cs.logic_or(found, is_receive_idx)?;

            // If the index is the receive index, the mint of the balance should match the
            // note, otherwise it should match the pre-update wallet mint
            let matches_note_mint = EqGadget::eq(&new_bal.mint, &note.mint, cs)?;
            let is_receive_and_note_mint = cs.logic_and(is_receive_idx, matches_note_mint)?;
            let old_new_mints_equal = EqGadget::eq(&old_bal.mint, &new_bal.mint, cs)?;
            let not_receive_and_mint_matches =
                cs.logic_and(is_not_receive_idx, old_new_mints_equal)?;

            let valid_new_mint =
                cs.logic_or(is_receive_and_note_mint, not_receive_and_mint_matches)?;
            cs.enforce_true(valid_new_mint)?;

            // Verify the old balance was either the same mint as the note, or a completely
            // zero'd balance
            let was_zerod = EqVecGadget::eq_zero_vec(
                &[old_bal.amount, old_bal.relayer_fee_balance, old_bal.protocol_fee_balance],
                cs,
            )?;
            let old_mint_equals_note_mint = EqGadget::eq(&old_bal.mint, &note.mint, cs)?;
            let valid_mint_replacement = cs.logic_or(was_zerod, old_mint_equals_note_mint)?;

            let valid_old_mint = cs.logic_or(is_not_receive_idx, valid_mint_replacement)?;
            cs.enforce_true(valid_old_mint)?;

            // Verify the amount field update
            let amount_delta =
                CondSelectGadget::select(&note.amount, &zero_var, is_receive_idx, cs)?;
            let expected_amount = cs.add(old_bal.amount, amount_delta)?;
            EqGadget::constrain_eq(&expected_amount, &new_bal.amount, cs)?;

            // Verify that the amount remains valid after settlement
            AmountGadget::constrain_valid_amount(new_bal.amount, cs)?;

            // The relayer and protocol fee balances should never change in note settlement
            EqGadget::constrain_eq(&old_bal.relayer_fee_balance, &new_bal.relayer_fee_balance, cs)?;
            EqGadget::constrain_eq(
                &old_bal.protocol_fee_balance,
                &new_bal.protocol_fee_balance,
                cs,
            )?;

            curr_idx = cs.add(curr_idx, one_var)?;
        }
        cs.enforce_true(found)?;

        Ok(())
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for the `VALID FEE REDEMPTION` circuit
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug)]
pub struct ValidFeeRedemptionWitness<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MERKLE_HEIGHT: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// The private shares of the wallet before update    
    pub old_wallet_private_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The blinded public shares of the wallet before update
    pub old_wallet_public_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The private shares of the wallet after update
    pub new_wallet_private_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The opening of the old wallet to the first Merkle root
    pub wallet_opening: MerkleOpening<MERKLE_HEIGHT>,
    /// The opening fo the note to the second Merkle root
    pub note_opening: MerkleOpening<MERKLE_HEIGHT>,
    /// The note being settled into the recipient's wallet
    pub note: Note,
    /// The decryption key of the recipient, used to authorize note redemption
    pub recipient_key: DecryptionKey,
    /// The index into the receiver's balances to which the note is settled
    pub receive_index: usize,
}

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for the `VALID FEE REDEMPTION` circuit
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug)]
pub struct ValidFeeRedemptionStatement<const MAX_BALANCES: usize, const MAX_ORDERS: usize>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// The Merkle root to which wallet inclusion is proven to
    pub wallet_root: MerkleRoot,
    /// The Merkle root to which note inclusion is proven to
    pub note_root: MerkleRoot,
    /// The nullifier of the pre-update wallet
    pub wallet_nullifier: Nullifier,
    /// The nullifier of the note
    pub note_nullifier: Nullifier,
    /// The commitment to the new wallet
    pub new_wallet_commitment: WalletShareStateCommitment,
    /// The blinded public shares of the post-update wallet
    pub new_wallet_public_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The root key of the recipient
    ///
    /// The recipient signs the commitment to their new wallet shares so that
    /// the state transition is authorized. This is done instead of
    /// in-circuit reblinding
    pub recipient_root_key: PublicSigningKey,
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MERKLE_HEIGHT: usize>
    SingleProverCircuit for ValidFeeRedemption<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    type Statement = ValidFeeRedemptionStatement<MAX_BALANCES, MAX_ORDERS>;
    type Witness = ValidFeeRedemptionWitness<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>;

    fn name() -> String {
        format!("ValidFeeRedemption ({MAX_BALANCES}, {MAX_ORDERS}, {MERKLE_HEIGHT})")
    }

    fn apply_constraints(
        witness_var: <Self::Witness as CircuitBaseType>::VarType,
        statement_var: <Self::Statement as CircuitBaseType>::VarType,
        cs: &mut PlonkCircuit,
    ) -> Result<(), PlonkError> {
        Self::circuit(&statement_var, &witness_var, cs).map_err(PlonkError::CircuitError)
    }
}

#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    use circuit_types::{
        balance::Balance,
        elgamal::DecryptionKey,
        native_helpers::{
            compute_wallet_private_share_commitment, compute_wallet_share_commitment,
            compute_wallet_share_nullifier, note_commitment, note_nullifier, reblind_wallet,
        },
        note::Note,
        wallet::Wallet,
    };
    use rand::thread_rng;

    use crate::zk_circuits::{
        test_helpers::{create_multi_opening, create_wallet_shares},
        valid_fee_redemption::ValidFeeRedemptionWitness,
    };

    use super::ValidFeeRedemptionStatement;

    /// Create a witness and statement for the `VALID FEE REDEMPTION` circuit
    pub fn create_witness_and_statement<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
        const MERKLE_HEIGHT: usize,
    >(
        wallet: &Wallet<MAX_BALANCES, MAX_ORDERS>,
        note: &Note,
    ) -> (
        ValidFeeRedemptionStatement<MAX_BALANCES, MAX_ORDERS>,
        ValidFeeRedemptionWitness<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>,
    )
    where
        [(); MAX_BALANCES + MAX_ORDERS]: Sized,
    {
        let mut rng = thread_rng();

        // Reset the note key to a pair with known decryption key
        let mut note = note.clone();
        let (dec, enc) = DecryptionKey::random_pair(&mut rng);
        note.receiver = enc;

        // Construct the updated wallets
        let old_wallet = wallet.clone();
        let mut new_wallet = wallet.clone();
        let receive_index = settle_note(&mut new_wallet, &note);

        // Create shares for the old wallet
        let (old_wallet_private_shares, old_wallet_public_shares) =
            create_wallet_shares(&old_wallet);

        // Create openings and nullifiers for the old wallet and note
        let old_wallet_comm =
            compute_wallet_share_commitment(&old_wallet_public_shares, &old_wallet_private_shares);
        let old_note_comm = note_commitment(&note);

        let (root, openings) = create_multi_opening(&[old_wallet_comm, old_note_comm]);
        let (wallet_opening, note_opening) = (openings[0].clone(), openings[1].clone());
        let wallet_nullifier = compute_wallet_share_nullifier(old_wallet_comm, wallet.blinder);
        let note_nullifier = note_nullifier(old_note_comm, note.blinder);

        // Create shares for the new wallet
        let (new_wallet_private_shares, new_wallet_public_shares) =
            reblind_wallet(&old_wallet_private_shares, &new_wallet);

        let new_wallet_commitment =
            compute_wallet_private_share_commitment(&new_wallet_private_shares);

        // Create the witness and statement
        let statement = ValidFeeRedemptionStatement {
            wallet_root: root,
            note_root: root,
            wallet_nullifier,
            note_nullifier,
            new_wallet_commitment,
            new_wallet_public_shares,
            recipient_root_key: wallet.keys.pk_root.clone(),
        };

        let witness = ValidFeeRedemptionWitness {
            old_wallet_private_shares,
            old_wallet_public_shares,
            new_wallet_private_shares,
            wallet_opening,
            note_opening,
            note,
            recipient_key: dec,
            receive_index,
        };

        (statement, witness)
    }

    /// Find a balance to settle the given note into or otherwise create an
    /// empty one and add the note to it
    ///
    /// Return the index at which the balance is found
    pub fn settle_note<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
        wallet: &mut Wallet<MAX_BALANCES, MAX_ORDERS>,
        note: &Note,
    ) -> usize
    where
        [(); MAX_BALANCES + MAX_ORDERS]: Sized,
    {
        let idx = find_balance_for_note(wallet, note);

        // Add the note to the balance
        wallet.balances[idx].amount += note.amount;
        idx
    }

    /// Find a balance to settle the given note or create an empty one
    fn find_balance_for_note<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
        wallet: &mut Wallet<MAX_BALANCES, MAX_ORDERS>,
        note: &Note,
    ) -> usize
    where
        [(); MAX_BALANCES + MAX_ORDERS]: Sized,
    {
        // Attempt to find an existing balance in the wallet that matches the note's
        // mint
        for (index, balance) in wallet.balances.iter().enumerate() {
            if balance.mint == note.mint {
                return index;
            }
        }

        // Find a zero'd balance
        for (index, balance) in wallet.balances.iter().enumerate() {
            if balance.is_zero() {
                wallet.balances[index] = Balance::new_from_mint(note.mint.clone());
                return index;
            }
        }

        panic!("Wallet is full")
    }
}

#[cfg(test)]
mod test {
    use circuit_types::{
        balance::Balance,
        elgamal::DecryptionKey,
        keychain::PublicSigningKey,
        merkle::{MerkleOpening, MerkleRoot},
        native_helpers::{
            compute_wallet_share_commitment, compute_wallet_share_nullifier, note_commitment,
            note_nullifier,
        },
        note::Note,
        wallet::{Nullifier, Wallet},
        Amount, AMOUNT_BITS,
    };
    use constants::Scalar;
    use rand::{thread_rng, Rng, RngCore};
    use renegade_crypto::fields::{scalar_to_biguint, scalar_to_u128};

    use crate::zk_circuits::{
        check_constraint_satisfaction,
        test_helpers::{create_multi_opening, INITIAL_WALLET, MAX_BALANCES, MAX_ORDERS},
        valid_fee_redemption::test_helpers::create_witness_and_statement,
    };

    use super::{ValidFeeRedemption, ValidFeeRedemptionStatement, ValidFeeRedemptionWitness};

    // -----------
    // | Helpers |
    // -----------

    /// The Merkle height used for testing
    const MERKLE_HEIGHT: usize = 5;

    /// Check that the constraints for the circuit are satisfied on the given
    /// witness, statement pair
    fn check_constraints_satisfied(
        witness: &ValidFeeRedemptionWitness<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>,
        statement: &ValidFeeRedemptionStatement<MAX_BALANCES, MAX_ORDERS>,
    ) -> bool {
        check_constraint_satisfaction::<ValidFeeRedemption<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>>(
            &witness, &statement,
        )
    }

    /// Get a wallet and note for testing
    fn get_testing_wallet_and_note() -> (Wallet<MAX_BALANCES, MAX_ORDERS>, Note) {
        let mut rng = thread_rng();

        // Zero all balances in the wallet for simplicity
        let mut wallet = INITIAL_WALLET.clone();
        for balance in wallet.balances.iter_mut() {
            *balance = Balance::default();
        }

        // Create a note with a mint that is not in the wallet
        let mint = scalar_to_biguint(&Scalar::random(&mut rng));
        let amount = Amount::from(rng.next_u64());

        let (_, enc) = DecryptionKey::random_pair(&mut rng);
        let note = Note { mint, amount, receiver: enc, blinder: Scalar::random(&mut rng) };

        (wallet, note)
    }

    /// Compute a new opening and nullifier for a note
    fn recompute_note_opening_nullifier(
        note: &Note,
    ) -> (MerkleRoot, MerkleOpening<MERKLE_HEIGHT>, Nullifier) {
        let note_comm = note_commitment(&note);
        let (root, opening) = create_multi_opening(&[note_comm]);
        let nullifier = note_nullifier(note_comm, note.blinder);

        (root, opening[0].clone(), nullifier)
    }

    // -----------------------
    // | Valid Witness Tests |
    // -----------------------

    /// Test a valid witness and statement
    #[test]
    fn test_valid_witness() {
        let (wallet, note) = get_testing_wallet_and_note();
        let (statement, witness) = create_witness_and_statement(&wallet, &note);

        assert!(check_constraints_satisfied(&witness, &statement));
    }

    /// Test a valid witness wherein the note is settled into an existing
    /// balance
    #[test]
    #[allow(non_snake_case)]
    fn test_valid_witness__existing_balance() {
        let mut rng = thread_rng();
        let (mut wallet, note) = get_testing_wallet_and_note();
        let idx = rng.gen_range(0..MAX_BALANCES);
        let initial_amt = Amount::from(rng.next_u64());
        wallet.balances[idx] = Balance::new_from_mint_and_amount(note.mint.clone(), initial_amt);

        // Create the witness and statement
        let (statement, witness) = create_witness_and_statement(&wallet, &note);

        // Check that the constraints are satisfied
        assert!(check_constraints_satisfied(&witness, &statement));
        // Check that the note was settled into the correct balance
        assert_eq!(witness.receive_index, idx);
    }

    // ----------------------
    // | Invalid Note Tests |
    // ----------------------

    /// Test the case in which the note mint is incorrect
    #[test]
    fn test_invalid_note_mint() {
        let mut rng = thread_rng();
        let (wallet, note) = get_testing_wallet_and_note();
        let (mut statement, mut witness) = create_witness_and_statement(&wallet, &note);

        // Modify the mint
        witness.note.mint = scalar_to_biguint(&Scalar::random(&mut rng));

        // Recompute the nullifier and opening
        let (root, opening, nullifier) = recompute_note_opening_nullifier(&witness.note);
        statement.note_root = root;
        statement.note_nullifier = nullifier;
        witness.note_opening = opening;

        assert!(!check_constraints_satisfied(&witness, &statement));
    }

    /// Test the case in which a note is settled into an existing balance with
    /// an invalid mint
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_note_mint__existing_balance() {
        let mut rng = thread_rng();
        let (mut wallet, note) = get_testing_wallet_and_note();

        let idx = rng.gen_range(0..MAX_BALANCES);

        let (mut statement, mut witness) = create_witness_and_statement(&wallet, &note);
        assert_eq!(witness.receive_index, idx);

        // Modify the note to have a different mint
        witness.note.mint = scalar_to_biguint(&Scalar::random(&mut rng));

        // Recompute the nullifier and opening
        let (root, opening, nullifier) = recompute_note_opening_nullifier(&witness.note);
        statement.note_root = root;
        statement.note_nullifier = nullifier;
        witness.note_opening = opening;

        assert!(!check_constraints_satisfied(&witness, &statement));
    }

    /// Test the case in which the note amount is incorrectly settled into the
    /// balance
    #[test]
    fn test_invalid_note_amount() {
        let mut rng = thread_rng();
        let (wallet, note) = get_testing_wallet_and_note();
        let (mut statement, mut witness) = create_witness_and_statement(&wallet, &note);

        // Recompute the nullifier and opening
        let (root, opening, nullifier) = recompute_note_opening_nullifier(&witness.note);
        statement.note_root = root;
        statement.note_nullifier = nullifier;
        witness.note_opening = opening;

        assert!(!check_constraints_satisfied(&witness, &statement));
    }

    /// Test the case in which the receiver field of the note does not match the
    /// decryption key
    #[test]
    fn test_invalid_note_receiver() {
        let (wallet, note) = get_testing_wallet_and_note();
        let (statement, mut witness) = create_witness_and_statement(&wallet, &note);

        // Modify the receiver
        let (dec, _) = DecryptionKey::random_pair(&mut thread_rng());
        witness.recipient_key = dec;

        assert!(!check_constraints_satisfied(&witness, &statement));
    }

    /// Test the case in which the note nullifier is incorrect
    #[test]
    fn test_invalid_note_nullifier() {
        let mut rng = thread_rng();
        let (wallet, note) = get_testing_wallet_and_note();
        let (mut statement, witness) = create_witness_and_statement(&wallet, &note);

        // Modify the nullifier
        statement.note_nullifier = Scalar::random(&mut rng);

        assert!(!check_constraints_satisfied(&witness, &statement));
    }

    /// Test the case in which the recipient's root key is incorrectly specified
    #[test]
    fn test_invalid_root_key() {
        let (wallet, note) = get_testing_wallet_and_note();
        let (mut statement, witness) = create_witness_and_statement(&wallet, &note);

        // Modify the root key in the statement
        statement.recipient_root_key = PublicSigningKey::default();

        assert!(!check_constraints_satisfied(&witness, &statement));
    }

    // ----------------------------------
    // | Invalid State Transition Tests |
    // ----------------------------------

    /// Test the case in which an order is modified in the wallet
    #[test]
    fn test_order_modified() {
        let mut rng = thread_rng();
        let (wallet, note) = get_testing_wallet_and_note();
        let (mut statement, witness) = create_witness_and_statement(&wallet, &note);

        // Modify the new public shares in the statement
        let idx = rng.gen_range(0..MAX_ORDERS);
        statement.new_wallet_public_shares.orders[idx].amount += Scalar::one();

        assert!(!check_constraints_satisfied(&witness, &statement));
    }

    /// Test the cases in which the keys, match fee, or managing cluster are
    /// modified
    #[test]
    fn test_spurious_wallet_modifications() {
        let (wallet, note) = get_testing_wallet_and_note();
        let (original_statement, witness) = create_witness_and_statement(&wallet, &note);

        // Modify the public match key
        let mut statement = original_statement.clone();
        statement.new_wallet_public_shares.keys.pk_match.key += Scalar::one();

        assert!(!check_constraints_satisfied(&witness, &statement));

        // Modify the match fee
        let mut statement = original_statement.clone();
        statement.new_wallet_public_shares.match_fee.repr += Scalar::one();

        assert!(!check_constraints_satisfied(&witness, &statement));

        // Modify the managing cluster
        let mut statement = original_statement.clone();
        statement.new_wallet_public_shares.managing_cluster.x += Scalar::one();

        assert!(!check_constraints_satisfied(&witness, &statement));
    }

    /// Test the case in which a non-receive balance is modified
    #[test]
    fn test_non_receive_balance_update() {
        let (wallet, note) = get_testing_wallet_and_note();
        let (original_statement, witness) = create_witness_and_statement(&wallet, &note);

        assert!(MAX_BALANCES == 2, "update this test to generate a unique index");
        let idx = MAX_BALANCES - 1 - witness.receive_index;

        // Modify the amount of a non-receive balance
        let mut statement = original_statement.clone();
        statement.new_wallet_public_shares.balances[idx].amount += Scalar::one();

        assert!(!check_constraints_satisfied(&witness, &statement));

        // Modify the mint of a non-receive balance
        let mut statement = original_statement.clone();
        statement.new_wallet_public_shares.balances[idx].mint += Scalar::one();

        assert!(!check_constraints_satisfied(&witness, &statement));
    }

    /// Test the case in which the receive balance has a mint different than the
    /// note
    #[test]
    fn test_invalid_receive_balance_mint() {
        let mut rng = thread_rng();
        let (wallet, note) = get_testing_wallet_and_note();
        let (mut statement, witness) = create_witness_and_statement(&wallet, &note);

        // Modify the mint of the receive balance
        let idx = witness.receive_index;
        statement.new_wallet_public_shares.balances[idx].mint = Scalar::random(&mut rng);

        assert!(!check_constraints_satisfied(&witness, &statement));
    }

    /// Test the case in which the receive balance amount is incorrectly updated
    #[test]
    fn test_invalid_receive_amount() {
        let (wallet, note) = get_testing_wallet_and_note();
        let (mut statement, witness) = create_witness_and_statement(&wallet, &note);

        // Modify the amount of the receive balance
        let idx = witness.receive_index;
        statement.new_wallet_public_shares.balances[idx].amount += Scalar::one();

        assert!(!check_constraints_satisfied(&witness, &statement));
    }

    /// Test the case in which settling the note overflows the balance
    #[test]
    fn test_overflowing_receive_amount() {
        let (mut wallet, note) = get_testing_wallet_and_note();
        let max_amount_scalar = Scalar::from(2u8).pow(AMOUNT_BITS as u64) - Scalar::one();
        let max_amount = scalar_to_u128(&max_amount_scalar);
        wallet.balances[0] = Balance::new_from_mint_and_amount(note.mint.clone(), max_amount);

        let (statement, witness) = create_witness_and_statement(&wallet, &note);

        assert!(!check_constraints_satisfied(&witness, &statement));
    }

    /// Test the case in which the note recipient clobbers an existing balance
    #[test]
    fn test_existing_balance_clobbered() {
        let mut rng = thread_rng();
        let (wallet, note) = get_testing_wallet_and_note();
        let (mut statement, mut witness) = create_witness_and_statement(&wallet, &note);

        // Modify the original balance to be of a different mint
        // We also make sure the balance has a non-zero amount, zero'd balances are
        // allowed to be overwritten
        let modification = Scalar::random(&mut rng);
        let idx = witness.receive_index;
        witness.old_wallet_private_shares.balances[idx].mint = modification;
        witness.old_wallet_private_shares.balances[idx].amount += Scalar::one();
        statement.new_wallet_public_shares.balances[idx].amount += Scalar::one();

        // Recompute the opening and nullifier
        let comm = compute_wallet_share_commitment(
            &witness.old_wallet_public_shares,
            &witness.old_wallet_private_shares,
        );
        let (root, opening) = create_multi_opening(&[comm]);
        let nullifier = compute_wallet_share_nullifier(comm, wallet.blinder);

        witness.wallet_opening = opening[0].clone();
        statement.wallet_root = root;
        statement.wallet_nullifier = nullifier;

        assert!(!check_constraints_satisfied(&witness, &statement));
    }
}
