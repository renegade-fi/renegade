//! Allows a relayer to settle a fee it is owed from a user wallet into its own

use std::iter;

use circuit_macros::circuit_type;
use circuit_types::{
    balance::BalanceVar,
    elgamal::DecryptionKey,
    keychain::PublicSigningKey,
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
            let was_zero = EqVecGadget::eq_zero_vec(
                &[old_bal.amount, old_bal.relayer_fee_balance, old_bal.protocol_fee_balance],
                cs,
            )?;
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

#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    //! Helper methods for testing the `VALID RELAYER FEE SETTLEMENT` circuit

    use circuit_types::{
        elgamal::DecryptionKey,
        native_helpers::{
            compute_wallet_private_share_commitment, compute_wallet_share_commitment,
            compute_wallet_share_nullifier, reblind_wallet,
        },
        wallet::Wallet,
        Amount,
    };
    use rand::{thread_rng, Rng, RngCore};

    use crate::zk_circuits::test_helpers::{create_multi_opening, create_wallet_shares};

    use super::{ValidRelayerFeeSettlementStatement, ValidRelayerFeeSettlementWitness};

    /// Create a valid witness and statement for the `VALID RELAYER FEE
    /// SETTLEMENT` circuit
    pub fn create_witness_statement<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
        const MERKLE_HEIGHT: usize,
    >(
        sender_wallet: &Wallet<MAX_BALANCES, MAX_ORDERS>,
        recipient_wallet: &Wallet<MAX_BALANCES, MAX_ORDERS>,
    ) -> (
        ValidRelayerFeeSettlementStatement<MAX_BALANCES, MAX_ORDERS>,
        ValidRelayerFeeSettlementWitness<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>,
    )
    where
        [(); MAX_BALANCES + MAX_ORDERS]: Sized,
    {
        let mut rng = thread_rng();
        let mut sender_wallet = sender_wallet.clone();
        let mut recipient_wallet = recipient_wallet.clone();

        // Pick balances to send and receive the fees from
        let send_idx = rng.gen_range(0..MAX_BALANCES);
        let receive_idx = rng.gen_range(0..MAX_BALANCES);
        recipient_wallet.balances[receive_idx].mint = sender_wallet.balances[send_idx].mint.clone();

        let (dec, enc) = DecryptionKey::random_pair(&mut rng);
        sender_wallet.managing_cluster = enc;

        let send_amt = Amount::from(rng.next_u64());
        sender_wallet.balances[send_idx].relayer_fee_balance = send_amt;

        // Create the updated sender wallet
        let mut updated_sender_wallet = sender_wallet.clone();
        updated_sender_wallet.balances[send_idx].relayer_fee_balance = Amount::from(0u8);

        let (sender_private_shares, sender_public_shares) = create_wallet_shares(&sender_wallet);
        let (sender_updated_private_shares, sender_updated_public_shares) =
            reblind_wallet(&sender_private_shares, &updated_sender_wallet);

        // Create the updated recipient wallet
        let mut updated_recipient_wallet = recipient_wallet.clone();
        updated_recipient_wallet.balances[receive_idx].amount += send_amt;

        let (recipient_private_shares, recipient_public_shares) =
            create_wallet_shares(&recipient_wallet);
        let (recipient_updated_private_shares, recipient_updated_public_shares) =
            reblind_wallet(&recipient_private_shares, &updated_recipient_wallet);

        // Create Merkle openings
        let old_sender_commitment =
            compute_wallet_share_commitment(&sender_public_shares, &sender_private_shares);
        let old_recipient_commitment =
            compute_wallet_share_commitment(&recipient_public_shares, &recipient_private_shares);
        let (root, openings) =
            create_multi_opening(&[old_sender_commitment, old_recipient_commitment]);
        let (sender_opening, recipient_opening) = (openings[0].clone(), openings[1].clone());

        // Create the witness
        let witness = ValidRelayerFeeSettlementWitness {
            sender_public_shares,
            sender_private_shares,
            sender_updated_private_shares: sender_updated_private_shares.clone(),
            recipient_public_shares,
            recipient_private_shares,
            recipient_updated_private_shares: recipient_updated_private_shares.clone(),
            sender_opening,
            recipient_opening,
            recipient_decryption_key: dec,
            sender_balance_index: send_idx,
            recipient_balance_index: receive_idx,
        };

        let statement = ValidRelayerFeeSettlementStatement {
            sender_root: root,
            recipient_root: root,
            sender_wallet_commitment: compute_wallet_private_share_commitment(
                &sender_updated_private_shares,
            ),
            recipient_wallet_commitment: compute_wallet_private_share_commitment(
                &recipient_updated_private_shares,
            ),
            sender_nullifier: compute_wallet_share_nullifier(
                old_sender_commitment,
                sender_wallet.blinder,
            ),
            recipient_nullifier: compute_wallet_share_nullifier(
                old_recipient_commitment,
                recipient_wallet.blinder,
            ),
            recipient_pk_root: recipient_wallet.keys.pk_root,
            sender_updated_public_shares,
            recipient_updated_public_shares,
        };

        (statement, witness)
    }
}

#[cfg(test)]
mod test {
    #![allow(non_snake_case)]

    use ark_mpc::algebra::Scalar;
    use circuit_types::{
        balance::Balance,
        elgamal::DecryptionKey,
        keychain::PublicSigningKey,
        native_helpers::{
            compute_wallet_private_share_commitment, compute_wallet_share_commitment,
            compute_wallet_share_nullifier,
        },
        traits::BaseType,
        wallet::{Wallet, WalletShare},
        AMOUNT_BITS,
    };
    use num_bigint::BigUint;
    use rand::{thread_rng, Rng};
    use renegade_crypto::fields::scalar_to_u128;

    use crate::zk_circuits::{
        check_constraint_satisfaction,
        test_helpers::{create_multi_opening, INITIAL_WALLET, MAX_BALANCES, MAX_ORDERS},
        valid_relayer_fee_settlement::test_helpers::create_witness_statement,
    };

    use super::{
        ValidRelayerFeeSettlement, ValidRelayerFeeSettlementStatement,
        ValidRelayerFeeSettlementWitness,
    };

    // -----------
    // | Helpers |
    // -----------

    /// The Merkle height used for testing
    const MERKLE_HEIGHT: usize = 5;
    /// A statement type with the testing constants attached
    type SizedStatement = ValidRelayerFeeSettlementStatement<MAX_BALANCES, MAX_ORDERS>;
    /// A witness type with the testing constants attached
    type SizedWitness = ValidRelayerFeeSettlementWitness<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>;

    /// Get a pair of initial wallets to test the circuit with
    fn get_initial_wallets() -> (Wallet<MAX_BALANCES, MAX_ORDERS>, Wallet<MAX_BALANCES, MAX_ORDERS>)
    {
        let mut rng = thread_rng();
        let mut sender_wallet = INITIAL_WALLET.clone();
        let mut recipient_wallet = INITIAL_WALLET.clone();
        sender_wallet.blinder = Scalar::random(&mut rng);
        recipient_wallet.blinder = Scalar::random(&mut rng);

        (sender_wallet, recipient_wallet)
    }

    /// Return whether the constraints are satisfied for the given witness and
    /// statement
    fn check_constraints_satisfied(statement: &SizedStatement, witness: &SizedWitness) -> bool {
        check_constraint_satisfaction::<
            ValidRelayerFeeSettlement<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>,
        >(witness, statement)
    }

    // ---------
    // | Tests |
    // ---------

    /// Tests constraint satisfaction on a valid witness and statement
    #[test]
    fn test_valid_witness() {
        let (sender_wallet, recipient_wallet) = get_initial_wallets();
        let (statement, witness) = create_witness_statement(&sender_wallet, &recipient_wallet);

        assert!(check_constraints_satisfied(&statement, &witness));
    }

    /// Test the case in which a fee is settled into a wallet with zero'd
    /// balances
    #[test]
    fn test_valid_witness__zero_initial_receiver_balance() {
        let (sender_wallet, mut recipient_wallet) = get_initial_wallets();
        for bal in recipient_wallet.balances.iter_mut() {
            *bal = Balance::default();
        }

        let (mut statement, mut witness) =
            create_witness_statement(&sender_wallet, &recipient_wallet);

        // Update the receive balance to be of a different mint in the original wallet,
        // and replaced in the new wallet
        let idx = witness.recipient_balance_index;
        witness.recipient_private_shares.balances[idx].mint += Scalar::one();

        // Update the state validity fields
        let new_comm = compute_wallet_share_commitment(
            &witness.recipient_public_shares,
            &witness.recipient_private_shares,
        );
        let (root, openings) = create_multi_opening(&[new_comm]);
        let nullifier = compute_wallet_share_nullifier(new_comm, recipient_wallet.blinder);

        statement.recipient_root = root;
        statement.recipient_nullifier = nullifier;
        witness.recipient_opening = openings[0].clone();

        assert!(check_constraints_satisfied(&statement, &witness));
    }

    // -------------------------
    // | Invalid Authorization |
    // -------------------------

    /// Test the case in which the prover provides an invalid decryption key
    #[test]
    fn test_invalid_decryption_key() {
        let mut rng = thread_rng();
        let (sender_wallet, recipient_wallet) = get_initial_wallets();
        let (statement, mut witness) = create_witness_statement(&sender_wallet, &recipient_wallet);

        witness.recipient_decryption_key = DecryptionKey::random(&mut rng);
        assert!(!check_constraints_satisfied(&statement, &witness));
    }

    /// Test the case in which the recipient's root key does not match the one
    /// in the statement
    #[test]
    fn test_invalid_root_key() {
        let (sender_wallet, recipient_wallet) = get_initial_wallets();
        let (mut statement, witness) = create_witness_statement(&sender_wallet, &recipient_wallet);

        // Zero out the signing key
        let mut zero_iter = std::iter::repeat(Scalar::zero());
        statement.recipient_pk_root = PublicSigningKey::from_scalars(&mut zero_iter);
        assert!(!check_constraints_satisfied(&statement, &witness));
    }

    // -------------------
    // | Invalid Reblind |
    // -------------------

    /// Tests the case in which a share of the sender's wallet is
    /// modified
    #[test]
    fn test_invalid_sender_reblind__random_modification() {
        let mut rng = thread_rng();
        let (sender_wallet, recipient_wallet) = get_initial_wallets();
        let (mut statement, mut witness) =
            create_witness_statement(&sender_wallet, &recipient_wallet);

        // Choose a point modification
        let shares_len = WalletShare::<MAX_BALANCES, MAX_ORDERS>::NUM_SCALARS;
        let modification_idx = rng.gen_range(0..shares_len);
        let modification = Scalar::random(&mut rng);

        // Modify the private shares
        let mut private_shares = witness.sender_updated_private_shares.to_scalars();
        private_shares[modification_idx] += modification;
        witness.sender_updated_private_shares =
            WalletShare::from_scalars(&mut private_shares.into_iter());
        statement.sender_wallet_commitment =
            compute_wallet_private_share_commitment(&witness.sender_updated_private_shares);

        // Modify the public shares in the opposite way, so that the wallet remains
        // intact
        let mut public_shares = statement.sender_updated_public_shares.to_scalars();
        public_shares[modification_idx] -= modification;
        statement.sender_updated_public_shares =
            WalletShare::from_scalars(&mut public_shares.into_iter());

        assert!(!check_constraints_satisfied(&statement, &witness));
    }

    /// Tests the case in which the public blinder share is incorrect
    #[test]
    fn test_invalid_public_blinder_share() {
        let mut rng = thread_rng();
        let (sender_wallet, recipient_wallet) = get_initial_wallets();
        let (mut statement, mut witness) =
            create_witness_statement(&sender_wallet, &recipient_wallet);

        // Modify the blinder shares so that the wallet remains intact
        let modification = Scalar::random(&mut rng);
        witness.sender_updated_private_shares.blinder += modification;
        statement.sender_updated_public_shares.blinder -= modification;
        statement.sender_wallet_commitment =
            compute_wallet_private_share_commitment(&witness.sender_updated_private_shares);

        assert!(!check_constraints_satisfied(&statement, &witness));
    }

    // ------------------------------------------
    // | Invalid Sender Wallet State Transition |
    // ------------------------------------------

    /// Test the case in which the send balance is zero
    #[test]
    fn test_invalid_settlement__send_balance_zero() {
        let (mut sender_wallet, recipient_wallet) = get_initial_wallets();
        for bal in sender_wallet.balances.iter_mut() {
            bal.mint = BigUint::from(0u8);
        }

        let (statement, witness) = create_witness_statement(&sender_wallet, &recipient_wallet);
        assert!(!check_constraints_satisfied(&statement, &witness));
    }

    /// Test the case in which a field on the sender's orders are modified
    #[test]
    fn test_invalid_settlement__order_modified() {
        let mut rng = thread_rng();
        let (sender_wallet, recipient_wallet) = get_initial_wallets();
        let (mut statement, witness) = create_witness_statement(&sender_wallet, &recipient_wallet);

        // Modify the sender's orders
        let idx = rng.gen_range(0..MAX_ORDERS);
        statement.sender_updated_public_shares.orders[idx].amount += Scalar::one();

        assert!(!check_constraints_satisfied(&statement, &witness));
    }

    /// Test the case in which the misc fields of the sender's wallet are
    /// modified
    #[test]
    fn test_invalid_settlement__spurious_modifications() {
        let mut rng = thread_rng();
        let (sender_wallet, recipient_wallet) = get_initial_wallets();
        let (original_statement, witness) =
            create_witness_statement(&sender_wallet, &recipient_wallet);

        // Modify the keys
        let mut statement = original_statement.clone();
        statement.sender_updated_public_shares.keys.pk_match.key = Scalar::random(&mut rng);
        assert!(!check_constraints_satisfied(&statement, &witness));

        // Modify the match fee
        let mut statement = original_statement.clone();
        statement.sender_updated_public_shares.match_fee.repr += Scalar::one();
        assert!(!check_constraints_satisfied(&statement, &witness));

        // Modify the managing cluster
        let mut statement = original_statement.clone();
        statement.sender_updated_public_shares.managing_cluster.x = Scalar::random(&mut rng);
        assert!(!check_constraints_satisfied(&statement, &witness));
    }

    /// Test the case in which a non-send balance was modified on the sender's
    /// wallet
    #[test]
    fn test_invalid_settlement__non_send_balance_modified() {
        let (sender_wallet, recipient_wallet) = get_initial_wallets();
        let (mut statement, witness) = create_witness_statement(&sender_wallet, &recipient_wallet);

        // Modify a non-send balance
        assert_eq!(MAX_BALANCES, 2, "update this test");
        let idx = (MAX_BALANCES - 1) - witness.sender_balance_index;
        statement.sender_updated_public_shares.balances[idx].amount += Scalar::one();

        assert!(!check_constraints_satisfied(&statement, &witness));
    }

    /// Test the case in which the send balance was modified in a field other
    /// than the relayer fee balance
    #[test]
    fn test_invalid_settlement__send_balance_modified() {
        let mut rng = thread_rng();
        let (sender_wallet, recipient_wallet) = get_initial_wallets();
        let (mut statement, witness) = create_witness_statement(&sender_wallet, &recipient_wallet);

        // Modify the send balance
        let idx = witness.sender_balance_index;
        statement.sender_updated_public_shares.balances[idx].mint = Scalar::random(&mut rng);

        assert!(!check_constraints_satisfied(&statement, &witness));
    }

    /// Test the case in which the sender's balance has a non-zero
    /// `relayer_fee_balance` after update
    #[test]
    fn test_invalid_settlement__non_zero_relayer_fee_balance() {
        let (sender_wallet, recipient_wallet) = get_initial_wallets();
        let (mut statement, witness) = create_witness_statement(&sender_wallet, &recipient_wallet);

        // Set the relayer fee balance to a non-zero value
        let idx = witness.sender_balance_index;
        statement.sender_updated_public_shares.balances[idx].relayer_fee_balance = Scalar::one();

        assert!(!check_constraints_satisfied(&statement, &witness));
    }

    // ---------------------------------------------
    // | Invalid Recipient Wallet State Transition |
    // ---------------------------------------------

    /// Test the case in which a field on the recipient's orders are modified
    #[test]
    fn test_invalid_settlement__recipient_order_modified() {
        let mut rng = thread_rng();
        let (sender_wallet, recipient_wallet) = get_initial_wallets();
        let (mut statement, witness) = create_witness_statement(&sender_wallet, &recipient_wallet);

        // Modify the recipient's orders
        let idx = rng.gen_range(0..MAX_ORDERS);
        statement.recipient_updated_public_shares.orders[idx].amount += Scalar::one();

        assert!(!check_constraints_satisfied(&statement, &witness));
    }

    /// Test the case in which the misc fields of the recipient's wallet are
    /// modified
    #[test]
    fn test_invalid_settlement__recipient_spurious_modifications() {
        let mut rng = thread_rng();
        let (sender_wallet, recipient_wallet) = get_initial_wallets();
        let (original_statement, witness) =
            create_witness_statement(&sender_wallet, &recipient_wallet);

        // Modify the match fee
        let mut statement = original_statement.clone();
        statement.recipient_updated_public_shares.match_fee.repr += Scalar::one();
        assert!(!check_constraints_satisfied(&statement, &witness));

        // Modify the managing cluster
        let mut statement = original_statement.clone();
        statement.recipient_updated_public_shares.managing_cluster.x = Scalar::random(&mut rng);
        assert!(!check_constraints_satisfied(&statement, &witness));

        // Modify the match key
        let mut statement = original_statement.clone();
        statement.recipient_updated_public_shares.keys.pk_match.key = Scalar::random(&mut rng);
        assert!(!check_constraints_satisfied(&statement, &witness));
    }

    /// Test the case in which a non-receive balance was modified on the
    /// recipient's wallet
    #[test]
    fn test_invalid_settlement__non_receive_balance_modified() {
        let mut rng = thread_rng();
        let (sender_wallet, recipient_wallet) = get_initial_wallets();
        let (original_statement, witness) =
            create_witness_statement(&sender_wallet, &recipient_wallet);

        assert_eq!(MAX_BALANCES, 2, "update this test");
        let idx = (MAX_BALANCES - 1) - witness.recipient_balance_index;

        // Modify a non-receive balance amount
        let mut statement = original_statement.clone();
        statement.recipient_updated_public_shares.balances[idx].amount += Scalar::one();

        assert!(!check_constraints_satisfied(&statement, &witness));

        // Modify a non-receive balance mint
        let mut statement = original_statement.clone();
        statement.recipient_updated_public_shares.balances[idx].mint = Scalar::random(&mut rng);

        assert!(!check_constraints_satisfied(&statement, &witness));
    }

    /// Test the case in which the prover settles the fee into an existing
    /// balance of a different mint
    #[test]
    fn test_invalid_settlement__receive_balance_clobbers_existing_balance() {
        let mut rng = thread_rng();
        let (sender_wallet, recipient_wallet) = get_initial_wallets();
        let (mut statement, mut witness) =
            create_witness_statement(&sender_wallet, &recipient_wallet);

        // Set the mint of the original wallet to a different value
        let idx = witness.recipient_balance_index;
        witness.recipient_public_shares.balances[idx].mint = Scalar::random(&mut rng);
        witness.recipient_private_shares.balances[idx].mint = Scalar::random(&mut rng);

        let new_comm = compute_wallet_share_commitment(
            &witness.recipient_public_shares,
            &witness.recipient_private_shares,
        );
        let (new_root, opening) = create_multi_opening(&[new_comm]);
        let blinder =
            witness.recipient_public_shares.blinder + witness.recipient_private_shares.blinder;
        let new_nullifier = compute_wallet_share_nullifier(new_comm, blinder);

        statement.recipient_root = new_root;
        statement.recipient_nullifier = new_nullifier;
        witness.recipient_opening = opening[0].clone();

        assert!(!check_constraints_satisfied(&statement, &witness));
    }

    /// Test the case in which the recipient's receive balance is incorrectly
    /// updated
    #[test]
    fn test_invalid_settlement__receive_balance_updated_incorrectly() {
        let (sender_wallet, recipient_wallet) = get_initial_wallets();
        let (mut statement, witness) = create_witness_statement(&sender_wallet, &recipient_wallet);

        // Set the amount of the receive balance to a different value
        let idx = witness.recipient_balance_index;
        statement.recipient_updated_public_shares.balances[idx].amount += Scalar::one();

        assert!(!check_constraints_satisfied(&statement, &witness));
    }

    /// Test the case in which the recipient's balance overflows after the fee
    /// is settled
    #[test]
    fn test_invalid_settlement__receive_balance_overflow() {
        let (sender_wallet, mut recipient_wallet) = get_initial_wallets();

        // Set the receiver balances so that they will always overflow
        let max_amount_scalar = Scalar::from(2u8).pow(AMOUNT_BITS as u64) - Scalar::one();
        let max_amount = scalar_to_u128(&max_amount_scalar);

        for bal in recipient_wallet.balances.iter_mut() {
            bal.amount = max_amount;
        }

        let (statement, witness) = create_witness_statement(&sender_wallet, &recipient_wallet);
        assert!(!check_constraints_satisfied(&statement, &witness));
    }

    /// Test the case in which any recipient balance is modified in the protocol
    /// and relayer fees
    #[test]
    fn test_invalid_settlement__protocol_relayer_fee_modified() {
        let mut rng = thread_rng();
        let (sender_wallet, recipient_wallet) = get_initial_wallets();
        let (original_statement, witness) =
            create_witness_statement(&sender_wallet, &recipient_wallet);

        // Modify the relayer fee balance
        let mut statement = original_statement.clone();
        let idx = rng.gen_range(0..MAX_BALANCES);
        statement.recipient_updated_public_shares.balances[idx].relayer_fee_balance =
            Scalar::random(&mut rng);

        assert!(!check_constraints_satisfied(&statement, &witness));

        // Modify the protocol fee balance
        let mut statement = original_statement.clone();
        statement.recipient_updated_public_shares.balances[idx].protocol_fee_balance =
            Scalar::random(&mut rng);

        assert!(!check_constraints_satisfied(&statement, &witness));
    }

    /// Test the case in which the recipient's receive mint is not the same as
    /// the sender's send mint
    #[test]
    fn test_invalid_settlement__recipient_mint_mismatch() {
        let mut rng = thread_rng();
        let (sender_wallet, recipient_wallet) = get_initial_wallets();
        let (mut statement, mut witness) =
            create_witness_statement(&sender_wallet, &recipient_wallet);

        // Set the mint of the receive balance to a different value
        let idx = witness.recipient_balance_index;
        let new_mint = Scalar::random(&mut rng);
        statement.recipient_updated_public_shares.balances[idx].mint += new_mint;
        witness.recipient_public_shares.balances[idx].mint += new_mint;

        // Regenerate the opening and nullifier for the recipient wallet
        let new_comm = compute_wallet_share_commitment(
            &witness.recipient_public_shares,
            &witness.recipient_private_shares,
        );
        let (new_root, opening) = create_multi_opening(&[new_comm]);
        let blinder =
            witness.recipient_public_shares.blinder + witness.recipient_private_shares.blinder;
        let new_nullifier = compute_wallet_share_nullifier(new_comm, blinder);
        statement.recipient_root = new_root;
        statement.recipient_nullifier = new_nullifier;
        witness.recipient_opening = opening[0].clone();

        assert!(!check_constraints_satisfied(&statement, &witness));
    }
}
