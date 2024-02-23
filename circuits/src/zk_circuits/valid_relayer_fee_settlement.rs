//! Allows a relayer to settle a fee it is owed from a user wallet into its own

use std::iter;

use circuit_macros::circuit_type;
use circuit_types::{
    balance::BalanceVar,
    keychain::{DecryptionKey, PublicSigningKey},
    merkle::{MerkleOpening, MerkleRoot},
    traits::{BaseType, CircuitBaseType, CircuitVarType, SingleProverCircuit},
    wallet::{Nullifier, WalletShare, WalletShareStateCommitment, WalletShareVar, WalletVar},
    PlonkCircuit,
};
use constants::{Scalar, ScalarField, MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT};
use mpc_plonk::errors::PlonkError;
use mpc_relation::{errors::CircuitError, traits::Circuit, Variable};

use crate::zk_gadgets::{
    comparators::{EqGadget, EqVecGadget, EqZeroGadget},
    elgamal::ElGamalGadget,
    select::CondSelectGadget,
    wallet_operations::{AmountGadget, WalletGadget},
};

// ----------------------
// | Circuit Definition |
// ----------------------

/// A type alias for the `ValidRelayerFeeSettlement` circuit with default sizing
/// parameters attached
pub type SizedValidRelayerFeeSettlement =
    ValidRelayerFeeSettlement<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>;

/// The `VALID RELAYER FEE SETTLEMENT` circuit
pub struct ValidRelayerFeeSettlement<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MERKLE_HEIGHT: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized;

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MERKLE_HEIGHT: usize>
    ValidRelayerFeeSettlement<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    fn circuit(
        statement: &ValidRelayerFeeSettlementStatementVar<MAX_BALANCES, MAX_ORDERS>,
        witness: &ValidRelayerFeeSettlementWitnessVar<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // --- Input Validity --- //

        // Check the sender wallet's nullifier and Merkle opening

        // Sender wallet
        WalletGadget::validate_wallet_transition(
            &witness.sender_public_shares,
            &witness.sender_private_shares,
            &witness.sender_opening,
            statement.sender_root,
            statement.sender_nullifier,
            cs,
        )?;
        let old_sender_wallet = WalletGadget::wallet_from_shares(
            &witness.sender_public_shares,
            &witness.sender_private_shares,
            cs,
        )?;

        // Recipient wallet
        WalletGadget::validate_wallet_transition(
            &witness.recipient_public_shares,
            &witness.recipient_private_shares,
            &witness.recipient_opening,
            statement.recipient_root,
            statement.recipient_nullifier,
            cs,
        )?;
        let old_recipient_wallet = WalletGadget::wallet_from_shares(
            &witness.recipient_public_shares,
            &witness.recipient_private_shares,
            cs,
        )?;

        // Check the commitment to the private shares of the new wallet
        // Sender wallet
        let sender_wallet_commitment =
            WalletGadget::compute_private_commitment(&witness.sender_updated_private_shares, cs)?;
        cs.enforce_equal(sender_wallet_commitment, statement.sender_wallet_commitment)?;

        // Recipient wallet
        let recipient_wallet_commitment = WalletGadget::compute_private_commitment(
            &witness.recipient_updated_private_shares,
            cs,
        )?;
        cs.enforce_equal(recipient_wallet_commitment, statement.recipient_wallet_commitment)?;

        // --- Authorization --- //
        // Validate that the given decryption key corresponds to the encryption key that
        // the sender's wallet has authorized for fees
        ElGamalGadget::verify_decryption_key(
            &witness.recipient_decryption_key,
            &old_sender_wallet.managing_cluster,
            cs,
        )?;

        // Validate that the root key in the statement is the recipient's root key
        EqGadget::constrain_eq(
            &old_recipient_wallet.keys.pk_root,
            &statement.recipient_pk_root,
            cs,
        )?;

        // --- Reblind Validity --- //
        Self::validate_sender_reblind(
            &witness.sender_private_shares,
            &witness.sender_updated_private_shares,
            &statement.sender_updated_public_shares,
            cs,
        )?;

        // --- Sender Wallet State Transition --- //

        // Recover the new sender wallet
        let new_sender_wallet = WalletGadget::wallet_from_shares(
            &statement.sender_updated_public_shares,
            &witness.sender_updated_private_shares,
            cs,
        )?;
        Self::validate_sender_wallet_transition(
            witness.sender_balance_index,
            &old_sender_wallet,
            &new_sender_wallet,
            cs,
        )?;

        // The send balance cannot be zero
        let send_bal =
            Self::get_balance_at_index(witness.sender_balance_index, &old_sender_wallet, cs)?;
        let zero_mint = EqZeroGadget::eq_zero(&send_bal.mint, cs)?;
        cs.enforce_false(zero_mint)?;

        // --- Recipient Wallet State Transition --- //

        // Recover the new recipient wallet
        let new_recipient_wallet = WalletGadget::wallet_from_shares(
            &statement.recipient_updated_public_shares,
            &witness.recipient_updated_private_shares,
            cs,
        )?;
        Self::validate_recipient_wallet_transition(
            witness.recipient_balance_index,
            &send_bal,
            &old_recipient_wallet,
            &new_recipient_wallet,
            cs,
        )
    }

    /// Validate the reblind of the sender's wallet
    fn validate_sender_reblind(
        original_private_share: &WalletShareVar<MAX_BALANCES, MAX_ORDERS>,
        new_private_share: &WalletShareVar<MAX_BALANCES, MAX_ORDERS>,
        new_blinded_public_share: &WalletShareVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Sample new private shares for the wallet
        let (sampled_private_share, new_blinder) =
            WalletGadget::reblind(original_private_share, cs)?;

        // Verify that the private shares are correctly sampled
        EqGadget::constrain_eq(new_private_share, &sampled_private_share, cs)?;

        // Verify the blinder of the public shares, the rest of the shares are verified
        // implicitly in the state transition
        let expected_public_blinder = cs.sub(new_blinder, sampled_private_share.blinder)?;
        EqGadget::constrain_eq(&expected_public_blinder, &new_blinded_public_share.blinder, cs)
    }

    /// Validate the state transition of the sender's wallet
    fn validate_sender_wallet_transition(
        send_idx: Variable,
        old_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS>,
        new_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // All order should remain the same
        EqGadget::constrain_eq(&old_wallet.orders, &new_wallet.orders, cs)?;

        // The keys, match fee and managing cluster key should remain the same
        EqGadget::constrain_eq(&old_wallet.keys, &new_wallet.keys, cs)?;
        EqGadget::constrain_eq(&old_wallet.match_fee, &new_wallet.match_fee, cs)?;
        EqGadget::constrain_eq(&old_wallet.managing_cluster, &new_wallet.managing_cluster, cs)?;

        // The balances should remain the same except for the balance that pays the fee
        let zero_var = cs.zero();
        let one_var = cs.one();
        let mut curr_idx = cs.zero();
        let mut was_found = cs.false_var();

        for (old_bal, new_bal) in old_wallet.balances.iter().zip(new_wallet.balances.iter()) {
            // Check the index
            let is_send_idx = EqGadget::eq(&curr_idx, &send_idx, cs)?;
            was_found = cs.logic_or(was_found, is_send_idx)?;

            // Compute the expected relayer fee balance
            let expected_relayer_fee_balance =
                CondSelectGadget::select(&zero_var, &old_bal.relayer_fee_balance, is_send_idx, cs)?;

            // Check the balance, the mint, amount, and protocol balance should remain the
            // same, regardless of whether this balances pays the fee
            let mut expected_bal = old_bal.clone();
            expected_bal.relayer_fee_balance = expected_relayer_fee_balance;

            EqGadget::constrain_eq(new_bal, &expected_bal, cs)?;
            curr_idx = cs.add(curr_idx, one_var)?;
        }
        cs.enforce_true(was_found)?;

        Ok(())
    }

    /// Validate the state transition of the recipient's wallet
    fn validate_recipient_wallet_transition(
        receive_idx: Variable,
        sender_balance: &BalanceVar,
        old_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS>,
        new_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // All order should remain the same
        EqGadget::constrain_eq(&old_wallet.orders, &new_wallet.orders, cs)?;

        // The match fee and managing cluster key should remain the same
        EqGadget::constrain_eq(&old_wallet.match_fee, &new_wallet.match_fee, cs)?;
        EqGadget::constrain_eq(&old_wallet.managing_cluster, &new_wallet.managing_cluster, cs)?;

        // The match key must be the same as the old wallet, but the root key may rotate
        EqGadget::constrain_eq(&old_wallet.keys.pk_match, &new_wallet.keys.pk_match, cs)?;

        // The balances must all remain the same except for the balance that receives
        // the fee
        let one_var = cs.one();
        let mut curr_idx = cs.zero();
        let mut was_found = cs.false_var();

        for (old_bal, new_bal) in old_wallet.balances.iter().zip(new_wallet.balances.iter()) {
            // Mask the index
            let is_receive_idx = EqGadget::eq(&curr_idx, &receive_idx, cs)?;
            was_found = cs.logic_or(was_found, is_receive_idx)?;

            // Constrain the mint of the updated balance
            // If the balance receives the fee, the mint may either:
            // - Be the same as in the old wallet
            // - Overwrite a zero'd balance
            let mints_equal = EqGadget::eq(&old_bal.mint, &new_bal.mint, cs)?;
            let was_zero = EqVecGadget::eq_zero_vec(&[old_bal.clone()], cs)?;
            let mints_equal_or_zero = cs.logic_or(mints_equal, was_zero)?;
            cs.enforce_true(mints_equal_or_zero)?;

            // The new balance mint must be the sender balance mint if this balance receives
            // the fee
            let expected_mint =
                CondSelectGadget::select(&sender_balance.mint, &old_bal.mint, is_receive_idx, cs)?;
            EqGadget::constrain_eq(&new_bal.mint, &expected_mint, cs)?;

            // Compute the expected amount of the new balance
            let new_amount = cs.add(old_bal.amount, sender_balance.relayer_fee_balance)?;
            let expected_amount =
                CondSelectGadget::select(&new_amount, &old_bal.amount, is_receive_idx, cs)?;
            EqGadget::constrain_eq(&new_bal.amount, &expected_amount, cs)?;

            // Check that the recipient's balance amount is still a valid amount
            AmountGadget::constrain_valid_amount(new_bal.amount, cs)?;

            // The relayer and protocol fee balances of the recipient must remain the same
            cs.enforce_equal(old_bal.relayer_fee_balance, new_bal.relayer_fee_balance)?;
            cs.enforce_equal(old_bal.protocol_fee_balance, new_bal.protocol_fee_balance)?;

            curr_idx = cs.add(curr_idx, one_var)?;
        }
        cs.enforce_true(was_found)?;

        Ok(())
    }

    /// Return the balance at the given index in a wallet
    fn get_balance_at_index(
        idx: Variable,
        wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<BalanceVar, CircuitError> {
        let zero_var = cs.zero();
        let one_var = cs.one();
        let mut curr_idx = cs.zero();
        let mut was_found = cs.false_var();
        let mut curr_bal = BalanceVar::from_vars(&mut iter::repeat(zero_var), cs);

        for bal in wallet.balances.iter() {
            // Check the index
            let is_send_idx = EqGadget::eq(&curr_idx, &idx, cs)?;
            was_found = cs.logic_or(was_found, is_send_idx)?;

            // Check the balance
            curr_bal = CondSelectGadget::select(bal, &curr_bal, is_send_idx, cs)?;
            curr_idx = cs.add(curr_idx, one_var)?;
        }
        cs.enforce_true(was_found)?;

        Ok(curr_bal)
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for `VALID RELAYER FEE SETTLEMENT` circuit
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug)]
pub struct ValidRelayerFeeSettlementWitness<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MERKLE_HEIGHT: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// The public shares of the sender before update
    pub sender_public_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The private shares of the sender before update
    pub sender_private_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The private shares of the sender after update
    pub sender_updated_private_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The public shares of the recipient before update
    pub recipient_public_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The private shares of the recipient before update
    pub recipient_private_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The private shares of the recipient after update
    pub recipient_updated_private_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The opening of the sender's wallet to the first Merkle root
    pub sender_opening: MerkleOpening<MERKLE_HEIGHT>,
    /// The opening of the recipient's wallet to the second Merkle root
    pub recipient_opening: MerkleOpening<MERKLE_HEIGHT>,
    /// The decryption key of the recipient
    pub recipient_decryption_key: DecryptionKey,
    /// The index within the sender's balances from which the relayer fee is
    /// paid
    pub sender_balance_index: usize,
    /// The index within the recipient's balances to which the relayer fee is
    /// paid
    pub recipient_balance_index: usize,
}

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for `VALID RELAYER FEE SETTLEMENT` circuit
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug)]
pub struct ValidRelayerFeeSettlementStatement<const MAX_BALANCES: usize, const MAX_ORDERS: usize>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// The root of the Merkle tree that inclusion of the sender's wallet is
    /// proven with respect to
    pub sender_root: MerkleRoot,
    /// The root of the Merkle tree that inclusion of the recipient's wallet is
    /// proven with respect to
    pub recipient_root: MerkleRoot,
    /// The nullifier of the sender's pre-update wallet
    pub sender_nullifier: Nullifier,
    /// The nullifier of the recipient's pre-update wallet
    pub recipient_nullifier: Nullifier,
    /// The commitment to the sender's new wallet shares
    pub sender_wallet_commitment: WalletShareStateCommitment,
    /// The commitment to the recipient's new wallet shares
    pub recipient_wallet_commitment: WalletShareStateCommitment,
    /// The public shares of the sender's post-update wallet
    pub sender_updated_public_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The public shares of the recipient's post-update wallet
    pub recipient_updated_public_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The public root key of the recipient's wallet
    ///
    /// We doxx this key here to allow the contract to verify a signature of the
    /// new wallet shares, so we also allow the key to rotate to prevent
    /// wallet tracking
    pub recipient_pk_root: PublicSigningKey,
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MERKLE_HEIGHT: usize>
    SingleProverCircuit for ValidRelayerFeeSettlement<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    type Statement = ValidRelayerFeeSettlementStatement<MAX_BALANCES, MAX_ORDERS>;
    type Witness = ValidRelayerFeeSettlementWitness<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>;

    fn name() -> String {
        format!(
            "Valid Relayer Fee Settlement Circuit ({MAX_BALANCES}, {MAX_ORDERS}, {MERKLE_HEIGHT})"
        )
    }

    fn apply_constraints(
        witness_var: <Self::Witness as CircuitBaseType>::VarType,
        statement_var: <Self::Statement as CircuitBaseType>::VarType,
        cs: &mut PlonkCircuit,
    ) -> Result<(), PlonkError> {
        Self::circuit(&statement_var, &witness_var, cs).map_err(PlonkError::CircuitError)
    }
}
