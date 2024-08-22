//! Settles fees out of a wallet and into a note, which is committed into the
//! global Merkle state

use std::iter;

use circuit_types::{
    balance::BalanceVar,
    elgamal::{ElGamalCiphertext, ElGamalCiphertextVar, EncryptionKey, EncryptionKeyVar},
    merkle::{MerkleOpening, MerkleRoot},
    note::{Note, NoteVar, NOTE_CIPHERTEXT_SIZE},
    traits::{BaseType, CircuitBaseType, CircuitVarType, SingleProverCircuit},
    wallet::{Nullifier, WalletShare, WalletShareStateCommitment, WalletShareVar, WalletVar},
    PlonkCircuit,
};
use constants::{
    EmbeddedScalarField, Scalar, ScalarField, MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT,
};
use mpc_plonk::errors::PlonkError;
use mpc_relation::{errors::CircuitError, traits::Circuit, BoolVar, Variable};

use circuit_macros::circuit_type;
use serde::{Deserialize, Serialize};

use crate::zk_gadgets::{
    comparators::{EqGadget, EqZeroGadget},
    note::NoteGadget,
    select::CondSelectGadget,
    wallet_operations::{AmountGadget, WalletGadget},
};

// ----------------------
// | Circuit Definition |
// ----------------------

/// A type alias for the `ValidOfflineFeeSettlement` circuit with default
/// sizing
pub type SizedValidOfflineFeeSettlement =
    ValidOfflineFeeSettlement<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>;
/// A type alias for the `ValidOfflineFeeSettlementStatement` with default
/// sizing
pub type SizedValidOfflineFeeSettlementStatement =
    ValidOfflineFeeSettlementStatement<MAX_BALANCES, MAX_ORDERS>;
/// A type alias for the `ValidOfflineFeeSettlementWitness` with default
pub type SizedValidOfflineFeeSettlementWitness =
    ValidOfflineFeeSettlementWitness<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>;

/// The `VALID OFFLINE FEE SETTLEMENT` circuit
pub struct ValidOfflineFeeSettlement<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MERKLE_HEIGHT: usize,
>;
impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MERKLE_HEIGHT: usize>
    ValidOfflineFeeSettlement<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    fn circuit(
        statement: &ValidOfflineFeeSettlementStatementVar<MAX_BALANCES, MAX_ORDERS>,
        witness: &ValidOfflineFeeSettlementWitnessVar<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // --- Input Validity --- //

        // Verify the nullifier and opening of the wallet
        WalletGadget::validate_wallet_transition(
            &witness.original_wallet_public_shares,
            &witness.original_wallet_private_shares,
            &witness.merkle_opening,
            statement.merkle_root,
            statement.nullifier,
            cs,
        )?;

        // Check the commitment to the new wallet shares
        let new_wallet_comm =
            WalletGadget::compute_private_commitment(&witness.updated_wallet_private_shares, cs)?;
        EqGadget::constrain_eq(&new_wallet_comm, &statement.updated_wallet_commitment, cs)?;

        // Reconstruct the old and new wallets
        let old_wallet = WalletGadget::wallet_from_shares(
            &witness.original_wallet_public_shares,
            &witness.original_wallet_private_shares,
            cs,
        )?;
        let new_wallet = WalletGadget::wallet_from_shares(
            &statement.updated_wallet_public_shares,
            &witness.updated_wallet_private_shares,
            cs,
        )?;

        // --- Note Construction & Encryption --- //
        // Select the encryption key to use based on whether the fee is being paid to
        // the protocol
        let key = CondSelectGadget::select(
            &statement.protocol_key,
            &old_wallet.managing_cluster,
            statement.is_protocol_fee,
            cs,
        )?;

        // Verify the note encryption and its commitment
        Self::verify_note_encryption_commitment(
            &witness.note,
            &key,
            witness.encryption_randomness,
            &statement.note_ciphertext,
            statement.note_commitment,
            cs,
        )?;

        // Verify that the note correctly spends the balance
        let send_bal = Self::get_balance_at_idx(witness.send_index, &old_wallet, cs)?;
        Self::verify_note_construction(
            &witness.note,
            statement.is_protocol_fee,
            &send_bal,
            &key,
            cs,
        )?;

        // --- Reblind and State Transition --- //

        // Verify that the sender's wallet is correctly reblinded and updated
        Self::verify_sender_reblind(
            &witness.original_wallet_private_shares,
            &witness.updated_wallet_private_shares,
            &statement.updated_wallet_public_shares,
            cs,
        )?;
        Self::verify_sender_state_transition(
            witness.send_index,
            statement.is_protocol_fee,
            &old_wallet,
            &new_wallet,
            cs,
        )
    }

    /// Verify coherence between the note and the send balance
    fn verify_note_construction(
        note: &NoteVar,
        is_protocol_fee: BoolVar,
        send_bal: &BalanceVar,
        enc_key: &EncryptionKeyVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // The note's mint should match the send balance
        EqGadget::constrain_eq(&note.mint, &send_bal.mint, cs)?;
        let note_mint_zero = EqZeroGadget::eq_zero(&note.mint, cs)?;
        cs.enforce_false(note_mint_zero)?;

        // The amount should either be the full relayer balance or the full protocol
        // balance
        let expected_amount = CondSelectGadget::select(
            &send_bal.protocol_fee_balance,
            &send_bal.relayer_fee_balance,
            is_protocol_fee,
            cs,
        )?;
        EqGadget::constrain_eq(&note.amount, &expected_amount, cs)?;
        AmountGadget::constrain_valid_amount(note.amount, cs)?;

        // The note's recipient should match the key we encrypted under
        EqGadget::constrain_eq(&note.receiver, enc_key, cs)
    }

    /// Verify the note encryption and its commitment
    fn verify_note_encryption_commitment(
        note: &NoteVar,
        key: &EncryptionKeyVar,
        randomness: Variable,
        expected_ciphertext: &ElGamalCiphertextVar<NOTE_CIPHERTEXT_SIZE>,
        expected_commitment: Variable,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Verify the ciphertext
        NoteGadget::verify_note_encryption(note, key, randomness, expected_ciphertext, cs)?;

        // Verify the commitment
        NoteGadget::verify_note_commitment(note, expected_commitment, cs)
    }

    /// Verify the reblinding of the sender's wallet
    fn verify_sender_reblind(
        old_private_shares: &WalletShareVar<MAX_BALANCES, MAX_ORDERS>,
        new_private_shares: &WalletShareVar<MAX_BALANCES, MAX_ORDERS>,
        new_public_shares: &WalletShareVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Reblind the sender's wallet
        let (expected_private_shares, new_blinder) = WalletGadget::reblind(old_private_shares, cs)?;

        // Check the private shares
        EqGadget::constrain_eq(&expected_private_shares, new_private_shares, cs)?;

        // Check the new public blinder share
        let public_blinder = cs.sub(new_blinder, expected_private_shares.blinder)?;
        EqGadget::constrain_eq(&public_blinder, &new_public_shares.blinder, cs)
    }

    /// Verify the state transition of the sender's wallet
    fn verify_sender_state_transition(
        send_index: Variable,
        is_protocol_fee: BoolVar,
        old_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS>,
        new_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // All orders should be the same
        EqGadget::constrain_eq(&old_wallet.orders, &new_wallet.orders, cs)?;

        // The keys, match fee, and managing cluster should be the same
        EqGadget::constrain_eq(&old_wallet.keys, &new_wallet.keys, cs)?;
        EqGadget::constrain_eq(&old_wallet.match_fee, &new_wallet.match_fee, cs)?;
        EqGadget::constrain_eq(&old_wallet.managing_cluster, &new_wallet.managing_cluster, cs)?;

        // Check the balance updates
        let zero_var = cs.zero();
        let one_var = cs.one();
        let is_relayer_fee = cs.logic_neg(is_protocol_fee)?;
        let mut curr_idx = cs.zero();
        let mut found = cs.false_var();

        for (old_bal, new_bal) in old_wallet.balances.iter().zip(new_wallet.balances.iter()) {
            // Mask the index
            let is_send = EqGadget::eq(&curr_idx, &send_index, cs)?;
            found = cs.logic_or(found, is_send)?;

            // The mint and amount should always be the same in the pre and post balances
            EqGadget::constrain_eq(&old_bal.mint, &new_bal.mint, cs)?;
            EqGadget::constrain_eq(&old_bal.amount, &new_bal.amount, cs)?;

            // Compute the expected relayer fee balance post-update
            let is_send_and_relayer = cs.logic_and(is_send, is_relayer_fee)?;
            let expected_relayer_fee_bal = CondSelectGadget::select(
                &zero_var,
                &old_bal.relayer_fee_balance,
                is_send_and_relayer,
                cs,
            )?;
            EqGadget::constrain_eq(&expected_relayer_fee_bal, &new_bal.relayer_fee_balance, cs)?;

            // Compute the expected protocol fee balance post-update
            let is_send_and_protocol = cs.logic_and(is_send, is_protocol_fee)?;
            let expected_protocol_fee_bal = CondSelectGadget::select(
                &zero_var,
                &old_bal.protocol_fee_balance,
                is_send_and_protocol,
                cs,
            )?;
            EqGadget::constrain_eq(&expected_protocol_fee_bal, &new_bal.protocol_fee_balance, cs)?;

            // Increment the index
            curr_idx = cs.add(curr_idx, one_var)?;
        }
        cs.enforce_true(found)?;

        Ok(())
    }

    /// Get the balance at a given index in a wallet
    fn get_balance_at_idx(
        idx: Variable,
        wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<BalanceVar, CircuitError> {
        let zero_var = cs.zero();
        let one_var = cs.one();
        let mut curr_idx = cs.zero();
        let mut found = cs.false_var();
        let mut curr_balance = BalanceVar::from_vars(&mut iter::repeat(zero_var), cs);

        for bal in wallet.balances.iter() {
            // Mask the index
            let is_curr = EqGadget::eq(&curr_idx, &idx, cs)?;
            found = cs.logic_or(found, is_curr)?;

            // Select the balance if the index is the requested one
            curr_balance = CondSelectGadget::select(bal, &curr_balance, is_curr, cs)?;

            // Increment the index
            curr_idx = cs.add(curr_idx, one_var)?;
        }
        cs.enforce_true(found)?;

        Ok(curr_balance)
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for the `VALID OFFLINE FEE SETTLEMENT` circuit
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug)]
pub struct ValidOfflineFeeSettlementWitness<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MERKLE_HEIGHT: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// The pre-update wallet private shares
    pub original_wallet_private_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The pre-update wallet public shares
    pub original_wallet_public_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The post-update wallet private shares
    pub updated_wallet_private_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The Merkle opening of the original wallet
    pub merkle_opening: MerkleOpening<MERKLE_HEIGHT>,
    /// The note generated by settling the fee
    pub note: Note,
    /// The encryption randomness used to encrypt the note
    pub encryption_randomness: EmbeddedScalarField,
    /// The index into the sender's balances from which the fee is settled
    pub send_index: usize,
}

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for the `VALID OFFLINE FEE SETTLEMENT` circuit
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidOfflineFeeSettlementStatement<const MAX_BALANCES: usize, const MAX_ORDERS: usize>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// The Merkle root to which inclusion of the original wallet is proven
    pub merkle_root: MerkleRoot,
    /// The nullifier of the original wallet
    pub nullifier: Nullifier,
    /// The commitment to the updated wallet's private shares
    pub updated_wallet_commitment: WalletShareStateCommitment,
    /// The blinded public shares of the post-update wallet
    pub updated_wallet_public_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The ciphertext of the note
    pub note_ciphertext: ElGamalCiphertext<NOTE_CIPHERTEXT_SIZE>,
    /// The commitment to the note
    pub note_commitment: Scalar,
    /// The encryption key of the protocol
    pub protocol_key: EncryptionKey,
    /// Whether or not the fee is being paid to the protocol
    pub is_protocol_fee: bool,
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MERKLE_HEIGHT: usize>
    SingleProverCircuit for ValidOfflineFeeSettlement<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    type Statement = ValidOfflineFeeSettlementStatement<MAX_BALANCES, MAX_ORDERS>;
    type Witness = ValidOfflineFeeSettlementWitness<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>;

    fn name() -> String {
        format!("ValidOfflineFeeSettlement ({MAX_BALANCES}, {MAX_ORDERS}, {MERKLE_HEIGHT})",)
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
        native_helpers::{
            compute_wallet_private_share_commitment, compute_wallet_share_commitment,
            compute_wallet_share_nullifier, encrypt_note, note_commitment, reblind_wallet,
        },
        note::Note,
        wallet::Wallet,
        Amount,
    };
    use constants::Scalar;
    use rand::{thread_rng, Rng, RngCore};

    use crate::zk_circuits::test_helpers::{
        create_multi_opening, create_wallet_shares, PROTOCOL_KEY,
    };

    use super::{ValidOfflineFeeSettlementStatement, ValidOfflineFeeSettlementWitness};

    /// Create a witness and statement for the `VALID OFFLINE FEE SETTLEMENT`
    /// circuit
    pub fn create_witness_statement<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
        const MERKLE_HEIGHT: usize,
    >(
        wallet: &Wallet<MAX_BALANCES, MAX_ORDERS>,
    ) -> (
        ValidOfflineFeeSettlementStatement<MAX_BALANCES, MAX_ORDERS>,
        ValidOfflineFeeSettlementWitness<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>,
    )
    where
        [(); MAX_BALANCES + MAX_ORDERS]: Sized,
    {
        let mut rng = thread_rng();
        let mut wallet = wallet.clone();
        let mut updated_wallet = wallet.clone();

        // Choose a balance to settle the fee from
        let is_protocol = rng.gen_bool(0.5);
        let send_index = rng.gen_range(0..MAX_BALANCES);

        let send_bal = &mut wallet.balances[send_index];
        let updated_bal = &mut updated_wallet.balances[send_index];
        let send_mint = send_bal.mint.clone();
        let send_amt = Amount::from(rng.next_u64());

        // Modify the balances and select the key to encrypt under
        let key = if is_protocol {
            send_bal.protocol_fee_balance = send_amt;
            updated_bal.protocol_fee_balance = Amount::from(0u8);
            *PROTOCOL_KEY
        } else {
            send_bal.relayer_fee_balance = send_amt;
            updated_bal.relayer_fee_balance = Amount::from(0u8);
            wallet.managing_cluster
        };

        // Create secret shares for the wallets
        let (original_wallet_private_shares, original_wallet_public_shares) =
            create_wallet_shares(&wallet);

        let (updated_wallet_private_shares, updated_wallet_public_shares) =
            reblind_wallet(&original_wallet_private_shares, &updated_wallet);

        // Create an opening for the original wallet
        let commitment = compute_wallet_share_commitment(
            &original_wallet_public_shares,
            &original_wallet_private_shares,
        );
        let (root, opening) = create_multi_opening(&[commitment]);
        let nullifier = compute_wallet_share_nullifier(commitment, wallet.blinder);

        let new_wallet_commitment =
            compute_wallet_private_share_commitment(&updated_wallet_private_shares);

        // Create the note
        let note = Note {
            mint: send_mint,
            amount: send_amt,
            receiver: key,
            blinder: Scalar::random(&mut rng),
        };
        let (cipher, randomness) = encrypt_note(&note, &key);
        let note_commitment = note_commitment(&note);

        let witness = ValidOfflineFeeSettlementWitness {
            original_wallet_private_shares,
            original_wallet_public_shares,
            updated_wallet_private_shares,
            merkle_opening: opening[0].clone(),
            note,
            encryption_randomness: randomness,
            send_index,
        };

        let statement = ValidOfflineFeeSettlementStatement {
            merkle_root: root,
            nullifier,
            updated_wallet_commitment: new_wallet_commitment,
            updated_wallet_public_shares,
            note_ciphertext: cipher,
            note_commitment,
            protocol_key: *PROTOCOL_KEY,
            is_protocol_fee: is_protocol,
        };

        (statement, witness)
    }
}

#[cfg(test)]
mod test {
    use circuit_types::{
        elgamal::{DecryptionKey, ElGamalCiphertext},
        native_helpers::{compute_wallet_private_share_commitment, encrypt_note, note_commitment},
        note::{Note, NOTE_CIPHERTEXT_SIZE},
        traits::BaseType,
        wallet::WalletShare,
        Amount,
    };
    use constants::{EmbeddedScalarField, Scalar};
    use rand::{thread_rng, Rng, RngCore};
    use renegade_crypto::fields::scalar_to_biguint;

    use crate::zk_circuits::{
        check_constraint_satisfaction,
        test_helpers::{INITIAL_WALLET, MAX_BALANCES, MAX_ORDERS},
    };

    use super::{
        test_helpers::create_witness_statement, ValidOfflineFeeSettlement,
        ValidOfflineFeeSettlementStatement, ValidOfflineFeeSettlementWitness,
    };

    // -----------
    // | Helpers |
    // -----------

    /// The Merkle height used for testing
    const MERKLE_HEIGHT: usize = 5;

    /// Check whether constraints are satisfied on the given witness and
    /// statement
    fn check_constraints_satisfied(
        statement: &ValidOfflineFeeSettlementStatement<MAX_BALANCES, MAX_ORDERS>,
        witness: &ValidOfflineFeeSettlementWitness<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>,
    ) -> bool {
        check_constraint_satisfaction::<
            ValidOfflineFeeSettlement<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>,
        >(witness, statement)
    }

    /// Re-encrypt and re-commit to a note that has been modified
    ///
    /// Returns the new ciphertext, encryption randomness, and commitment
    fn reencrypt_recommit_note(
        note: &Note,
    ) -> (ElGamalCiphertext<NOTE_CIPHERTEXT_SIZE>, EmbeddedScalarField, Scalar) {
        let (cipher, new_rand) = encrypt_note(note, &note.receiver);
        let new_commitment = note_commitment(note);
        (cipher, new_rand, new_commitment)
    }

    // -----------------------
    // | Valid Witness Tests |
    // -----------------------

    /// Test a valid witness and statement pair
    #[test]
    fn test_valid_witness() {
        let wallet = INITIAL_WALLET.clone();
        let (statement, witness) = create_witness_statement(&wallet);

        assert!(check_constraints_satisfied(&statement, &witness));
    }

    // ----------------------
    // | Invalid Note Tests |
    // ----------------------

    /// Test the case in which the note ciphertext is incorrect
    #[test]
    fn test_invalid_note_ciphertext() {
        let mut rng = thread_rng();
        let wallet = INITIAL_WALLET.clone();
        let (mut statement, witness) = create_witness_statement(&wallet);

        // Modify the note ciphertext
        let idx = rng.gen_range(0..statement.note_ciphertext.ciphertext.len() - 1);
        statement.note_ciphertext.ciphertext[idx] += Scalar::one();

        assert!(!check_constraints_satisfied(&statement, &witness));
    }

    /// Test the case in which the note commitment is incorrect
    #[test]
    fn test_invalid_note_commitment() {
        let mut rng = thread_rng();
        let wallet = INITIAL_WALLET.clone();
        let (mut statement, witness) = create_witness_statement(&wallet);

        // Modify the note commitment
        statement.note_commitment = Scalar::random(&mut rng);

        assert!(!check_constraints_satisfied(&statement, &witness));
    }

    /// Test the case in which the note has an invalid mint
    #[test]
    fn test_invalid_note_mint() {
        let mut rng = thread_rng();
        let wallet = INITIAL_WALLET.clone();

        let (mut statement, mut witness) = create_witness_statement(&wallet);
        witness.note.mint = scalar_to_biguint(&Scalar::random(&mut rng));

        // Re-encrypt the modified note
        let (cipher, randomness, commitment) = reencrypt_recommit_note(&witness.note);
        statement.note_ciphertext = cipher;
        statement.note_commitment = commitment;
        witness.encryption_randomness = randomness;

        assert!(!check_constraints_satisfied(&statement, &witness));
    }

    /// Test the case in which the note has an invalid amount
    #[test]
    fn test_invalid_note_amount() {
        let mut rng = thread_rng();
        let wallet = INITIAL_WALLET.clone();

        let (mut statement, mut witness) = create_witness_statement(&wallet);
        witness.note.amount = Amount::from(rng.next_u64());

        // Re-encrypt the modified note
        let (cipher, randomness, commitment) = reencrypt_recommit_note(&witness.note);
        statement.note_ciphertext = cipher;
        statement.note_commitment = commitment;
        witness.encryption_randomness = randomness;

        assert!(!check_constraints_satisfied(&statement, &witness));
    }

    /// Test the case in which the note recipient is invalid
    #[test]
    fn test_invalid_note_recipient() {
        let mut rng = thread_rng();
        let wallet = INITIAL_WALLET.clone();
        let (mut statement, mut witness) = create_witness_statement(&wallet);

        let (_, enc) = DecryptionKey::random_pair(&mut rng);
        witness.note.receiver = enc;

        // Re-encrypt the modified note
        // The note encryption should remain the same to isolate the correct constraint
        let (_, _, commitment) = reencrypt_recommit_note(&witness.note);
        statement.note_commitment = commitment;

        assert!(!check_constraints_satisfied(&statement, &witness));
    }

    // -------------------------
    // | Invalid Reblind Tests |
    // -------------------------

    /// Test the case in which a private share of the reblinded wallet is
    /// modified
    #[test]
    fn test_modified_shares() {
        let mut rng = thread_rng();
        let wallet = INITIAL_WALLET.clone();
        let (mut statement, mut witness) = create_witness_statement(&wallet);

        let idx = rng.gen_range(0..WalletShare::<MAX_BALANCES, MAX_ORDERS>::NUM_SCALARS);
        let modification = Scalar::random(&mut rng);

        // Modify the private shares
        let mut private_shares = witness.updated_wallet_private_shares.to_scalars();
        private_shares[idx] += modification;
        witness.updated_wallet_private_shares =
            WalletShare::from_scalars(&mut private_shares.into_iter());
        statement.updated_wallet_commitment =
            compute_wallet_private_share_commitment(&witness.updated_wallet_private_shares);

        // Make an analogous modification to the public shares so that the wallet
        // remains unchanged
        let mut public_shares = statement.updated_wallet_public_shares.to_scalars();
        public_shares[idx] -= modification;
        statement.updated_wallet_public_shares =
            WalletShare::from_scalars(&mut public_shares.into_iter());

        assert!(!check_constraints_satisfied(&statement, &witness));
    }

    /// Tests the case in which the public blinder share is incorrectly modified
    #[test]
    fn test_invalid_public_blinder() {
        let mut rng = thread_rng();
        let wallet = INITIAL_WALLET.clone();
        let (mut statement, witness) = create_witness_statement(&wallet);

        let modification = Scalar::random(&mut rng);
        statement.updated_wallet_public_shares.blinder += modification;

        // Reblind the public shares under the new implied blinder
        let new_blinder = witness.updated_wallet_private_shares.blinder
            + statement.updated_wallet_public_shares.blinder;
        let old_blinder = new_blinder - modification;

        let public_shares = statement.updated_wallet_public_shares;
        let unblinded = public_shares.unblind_shares(old_blinder);
        let reblinded = unblinded.blind_shares(new_blinder);
        statement.updated_wallet_public_shares = reblinded;

        assert!(!check_constraints_satisfied(&statement, &witness));
    }

    // ----------------------------------
    // | Invalid State Transition Tests |
    // ----------------------------------

    /// Test the case in which an order is modified in the sender's wallet
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_update__order_modified() {
        let wallet = INITIAL_WALLET.clone();
        let (mut statement, witness) = create_witness_statement(&wallet);

        // Modify the order
        let idx = thread_rng().gen_range(0..MAX_ORDERS);
        statement.updated_wallet_public_shares.orders[idx].amount += Scalar::one();

        assert!(!check_constraints_satisfied(&statement, &witness));
    }

    /// Test the cases in which the keys, match fee, or managing cluster are
    /// modified in the update
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_update__spurious_modifications() {
        let wallet = INITIAL_WALLET.clone();
        let (original_statement, witness) = create_witness_statement(&wallet);

        // Modify the keys
        let mut statement = original_statement.clone();
        statement.updated_wallet_public_shares.keys.pk_match.key += Scalar::one();

        assert!(!check_constraints_satisfied(&statement, &witness));

        // Modify the keychain nonce
        let mut statement = original_statement.clone();
        statement.updated_wallet_public_shares.keys.nonce += Scalar::one();

        assert!(!check_constraints_satisfied(&statement, &witness));

        // Modify the match fee
        let mut statement = original_statement.clone();
        statement.updated_wallet_public_shares.match_fee.repr += Scalar::one();

        assert!(!check_constraints_satisfied(&statement, &witness));

        // Modify the managing cluster
        let mut statement = original_statement.clone();
        statement.updated_wallet_public_shares.managing_cluster.y += Scalar::one();

        assert!(!check_constraints_satisfied(&statement, &witness));
    }

    /// Test the case in which a balance other than the send balance is modified
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_update__balance_modified() {
        let wallet = INITIAL_WALLET.clone();
        let (original_statement, witness) = create_witness_statement(&wallet);

        assert_eq!(MAX_BALANCES, 2, "update this test to index a unique balance properly");
        let idx = MAX_BALANCES - 1 - witness.send_index;

        // Modify the balance mint
        let mut statement = original_statement.clone();
        statement.updated_wallet_public_shares.balances[idx].mint += Scalar::one();

        assert!(!check_constraints_satisfied(&statement, &witness));

        // Modify the balance amount
        let mut statement = original_statement.clone();
        statement.updated_wallet_public_shares.balances[idx].amount += Scalar::one();

        assert!(!check_constraints_satisfied(&statement, &witness));

        // Modify the relayer fee balance
        let mut statement = original_statement.clone();
        statement.updated_wallet_public_shares.balances[idx].relayer_fee_balance += Scalar::one();

        assert!(!check_constraints_satisfied(&statement, &witness));

        // Modify the protocol fee balance
        let mut statement = original_statement.clone();
        statement.updated_wallet_public_shares.balances[idx].protocol_fee_balance += Scalar::one();

        assert!(!check_constraints_satisfied(&statement, &witness));
    }

    /// Test the case in which the send balance is modified in an invalid way
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_update__send_balance_modified() {
        let wallet = INITIAL_WALLET.clone();
        let (original_statement, witness) = create_witness_statement(&wallet);
        let idx = witness.send_index;

        // Modify the mint
        let mut statement = original_statement.clone();
        statement.updated_wallet_public_shares.balances[idx].mint += Scalar::one();

        assert!(!check_constraints_satisfied(&statement, &witness));

        // Modify the amount
        let mut statement = original_statement.clone();
        statement.updated_wallet_public_shares.balances[idx].amount += Scalar::one();

        assert!(!check_constraints_satisfied(&statement, &witness));

        // Modify the balance that was not sent from
        let mut statement = original_statement.clone();
        let bal = &mut statement.updated_wallet_public_shares.balances[idx];
        if statement.is_protocol_fee {
            bal.relayer_fee_balance += Scalar::one();
        } else {
            bal.protocol_fee_balance += Scalar::one();
        }

        assert!(!check_constraints_satisfied(&statement, &witness));
    }

    /// Test the case in which the send balance is not zero'd
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_update__send_balance_not_zeroed() {
        let wallet = INITIAL_WALLET.clone();
        let (mut statement, witness) = create_witness_statement(&wallet);

        let bal = &mut statement.updated_wallet_public_shares.balances[witness.send_index];
        if statement.is_protocol_fee {
            bal.protocol_fee_balance += Scalar::one();
        } else {
            bal.relayer_fee_balance += Scalar::one();
        }

        assert!(!check_constraints_satisfied(&statement, &witness));
    }
}
