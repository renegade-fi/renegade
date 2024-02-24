//! Settles fees out of a wallet and into a note, which is committed into the
//! global Merkle state

use std::iter;

use circuit_types::{
    balance::BalanceVar,
    keychain::{EncryptionKey, EncryptionKeyVar},
    merkle::{MerkleOpening, MerkleRoot},
    note::{Note, NoteVar, NOTE_CIPHERTEXT_SIZE},
    traits::{BaseType, CircuitBaseType, CircuitVarType, SingleProverCircuit},
    wallet::{Nullifier, WalletShare, WalletShareStateCommitment, WalletShareVar, WalletVar},
    PlonkCircuit,
};
use constants::{EmbeddedScalarField, Scalar, ScalarField};
use mpc_plonk::errors::PlonkError;
use mpc_relation::{errors::CircuitError, traits::Circuit, BoolVar, Variable};

use circuit_macros::circuit_type;

use crate::zk_gadgets::{
    comparators::EqGadget,
    elgamal::{ElGamalCiphertext, ElGamalCiphertextVar},
    note::NoteGadget,
    select::CondSelectGadget,
    wallet_operations::WalletGadget,
};

// ----------------------
// | Circuit Definition |
// ----------------------

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

        // Verify that the note correctly spends the balance
        let send_bal = Self::get_balance_at_idx(witness.send_index, &old_wallet, cs)?;
        Self::verify_note_construction(
            &witness.note,
            statement.is_protocol_fee,
            &send_bal,
            &key,
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

        // The amount should either be the full relayer balance or the full protocol
        // balance
        let expected_amount = CondSelectGadget::select(
            &send_bal.protocol_fee_balance,
            &send_bal.relayer_fee_balance,
            is_protocol_fee,
            cs,
        )?;
        EqGadget::constrain_eq(&note.amount, &expected_amount, cs)?;

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
#[derive(Clone, Debug)]
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
