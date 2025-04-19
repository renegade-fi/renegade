//! Defines the `VALID WALLET UPDATE` circuit
//!
//! This circuit proves that a user-generated update to a wallet is valid, and
//! that the state nullification/creation is computed correctly

use ark_ff::{One, Zero};
use circuit_macros::circuit_type;
use circuit_types::{
    keychain::PublicSigningKey,
    merkle::{MerkleOpening, MerkleRoot},
    traits::{BaseType, CircuitBaseType, CircuitVarType},
    transfers::{ExternalTransfer, ExternalTransferVar},
    wallet::{Nullifier, WalletShare, WalletShareStateCommitment, WalletVar},
    PlonkCircuit,
};
use constants::{Scalar, ScalarField, MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT};
use mpc_plonk::errors::PlonkError;
use mpc_relation::{errors::CircuitError, traits::Circuit, BoolVar, Variable};
use serde::{Deserialize, Serialize};

use crate::{
    zk_gadgets::{
        comparators::{EqGadget, EqVecGadget, EqZeroGadget, NotEqualGadget},
        select::CondSelectGadget,
        wallet_operations::{AmountGadget, PriceGadget, WalletGadget},
    },
    SingleProverCircuit,
};

// ----------------------
// | Circuit Definition |
// ----------------------

/// A type alias for the `ValidWalletUpdate` circuit with default size
/// parameters attached
pub type SizedValidWalletUpdate = ValidWalletUpdate<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>;

/// The `VALID WALLET UPDATE` circuit
pub struct ValidWalletUpdate<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MERKLE_HEIGHT: usize,
>;
impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MERKLE_HEIGHT: usize>
    ValidWalletUpdate<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// Apply the circuit constraints to a given constraint system
    pub fn circuit(
        statement: &ValidWalletUpdateStatementVar<MAX_BALANCES, MAX_ORDERS>,
        witness: &ValidWalletUpdateWitnessVar<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // -- State Validity -- //

        // Recover the wallet then verify merkle opening and nullifier
        WalletGadget::validate_wallet_transition(
            &witness.old_wallet_public_shares,
            &witness.old_wallet_private_shares,
            &witness.old_shares_opening,
            statement.merkle_root,
            statement.old_shares_nullifier,
            cs,
        )?;

        // Verify that the new blinder has been sampled from the old blinder directly
        // The blinder stream is seeded by the old blinder's private share
        let public_blinder = statement.new_public_shares.blinder;
        let blinder_seed = witness.old_wallet_private_shares.blinder;
        WalletGadget::validate_public_blinder_from_seed(public_blinder, blinder_seed, cs)?;

        // Validate the commitment to the new wallet secret shares
        let new_wallet_commitment = WalletGadget::compute_wallet_share_commitment(
            &statement.new_public_shares,
            &witness.new_wallet_private_shares,
            cs,
        )?;
        cs.enforce_equal(new_wallet_commitment, statement.new_wallet_commitment)?;

        // Recover the old and new wallets from shares
        let old_wallet = WalletGadget::wallet_from_shares(
            &witness.old_wallet_public_shares,
            &witness.old_wallet_private_shares,
            cs,
        )?;

        let new_wallet = WalletGadget::wallet_from_shares(
            &statement.new_public_shares,
            &witness.new_wallet_private_shares,
            cs,
        )?;

        // -- Authorization -- //

        // Check pk_root in the statement corresponds to pk_root in the wallet
        EqGadget::constrain_eq(&statement.old_pk_root, &old_wallet.keys.pk_root, cs)?;

        // -- State transition validity -- //
        Self::verify_wallet_transition(
            &old_wallet,
            &new_wallet,
            witness.transfer_index,
            &statement.external_transfer,
            cs,
        )
    }

    /// Verify a state transition between two wallets
    fn verify_wallet_transition(
        old_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS>,
        new_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS>,
        transfer_idx: Variable,
        external_transfer: &ExternalTransferVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Validate the new wallet's orders
        Self::validate_new_orders(new_wallet, cs)?;

        // Validate the transfer
        let transfer_is_zero = EqZeroGadget::eq_zero(external_transfer, cs)?;
        Self::validate_external_transfer(transfer_is_zero, external_transfer, cs)?;

        // Validate updates to the balances within the wallet
        Self::validate_balance_updates(
            old_wallet,
            new_wallet,
            transfer_idx,
            transfer_is_zero,
            external_transfer,
            cs,
        )?;

        // The match_fee and managing_cluster should remain unchanged
        //
        // Note that the keys are allowed to change to enable key rotation. The actual
        // wallet transition is authorized by a signature from the old root key
        // (checked on-chain) so rotation is protected outside of the circuit
        EqGadget::constrain_eq(&old_wallet.max_match_fee, &new_wallet.max_match_fee, cs)?;
        EqGadget::constrain_eq(&old_wallet.managing_cluster, &new_wallet.managing_cluster, cs)
    }

    // ----------
    // | Orders |
    // ----------

    /// Validates the orders of the new wallet
    ///
    /// The order sides are implicitly constrained binary by their
    /// representation as a `BoolVar`
    fn validate_new_orders(
        new_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        for order in new_wallet.orders.iter() {
            // Check that the amount is valid
            AmountGadget::constrain_valid_amount(order.amount, cs)?;
            // Check that the worst case price is valid
            PriceGadget::constrain_valid_price(order.worst_case_price, cs)?;

            // If either base or quote mint is zero then the whole order should be zero
            let base_mint_zero = EqZeroGadget::eq_zero(&order.base_mint, cs)?;
            let quote_mint_zero = EqZeroGadget::eq_zero(&order.quote_mint, cs)?;
            let order_zero = EqZeroGadget::eq_zero(order, cs)?;

            let either_mint_zero = cs.logic_or(base_mint_zero, quote_mint_zero)?;

            // If both mints are zero the order should also be zero, if either
            // mint is non-zero then the order is necessarily
            // non-zero so constraining these two booleans to equal
            // one another is equivalent to the "if" statement above
            cs.enforce_equal(either_mint_zero.into(), order_zero.into())?;

            // The mints cannot equal one another, unless they represent the zero order
            let mints_not_equal = NotEqualGadget::not_equal(order.base_mint, order.quote_mint, cs)?;
            let mint_not_equal_or_zero = cs.logic_or(mints_not_equal, order_zero)?;
            cs.enforce_true(mint_not_equal_or_zero)?;
        }

        Ok(())
    }

    // ------------
    // | Transfer |
    // ------------

    /// Validates the external transfer in the statement
    ///
    /// The transfer direction is enforced to be binary by its representation as
    /// a `BoolVar`
    ///
    /// Takes in a pre-computed wire indicating whether the transfer is zero, so
    /// that we may reuse this computation in other components
    pub fn validate_external_transfer(
        is_zero: BoolVar,
        transfer: &ExternalTransferVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Enforce that if the transfer mint is zero, the whole transfer struct must be
        // zero. We can enforce this by enforcing `mint_is_zero == transfer_is_zero`
        let mint_is_zero = EqZeroGadget::eq_zero(&transfer.mint, cs)?;
        cs.enforce_equal(mint_is_zero.into(), is_zero.into())?;

        // Check that the amount of transfer is a valid amount
        AmountGadget::constrain_valid_amount(transfer.amount, cs)
    }

    // ------------
    // | Balances |
    // ------------

    /// Validates the balance updates in the wallet
    fn validate_balance_updates(
        old_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS>,
        new_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS>,
        transfer_idx: Variable,
        transfer_is_zero: BoolVar,
        external_transfer: &ExternalTransferVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Check that if the balance mint is zero the whole balance must be zero
        // and that the balances have valid amounts in them after update
        for balance in new_wallet.balances.iter() {
            // If the mint is zero, the balance must be zero
            // This is equivalent to enforcing `mint_is_zero == balance_is_zero`
            let mint_is_zero = EqZeroGadget::eq_zero(&balance.mint, cs)?;
            let balance_is_zero = EqZeroGadget::eq_zero(balance, cs)?;
            cs.enforce_equal(mint_is_zero.into(), balance_is_zero.into())?;

            // Constrain the amount to be valid
            AmountGadget::constrain_valid_amount(balance.amount, cs)?;
        }

        // Ensure that all mints in the updated balances are unique
        Self::constrain_unique_balance_mints(new_wallet, cs)?;
        // Check that the fee balances did not change in the update
        Self::validate_fee_balances_unchanged(old_wallet, new_wallet, cs)?;
        // Validate that the external transfer has been correctly applied
        Self::validate_transfer_application(
            old_wallet,
            new_wallet,
            transfer_idx,
            transfer_is_zero,
            external_transfer,
            cs,
        )
    }

    /// Constrains all balance mints to be unique or zero
    fn constrain_unique_balance_mints(
        wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        for i in 0..wallet.balances.len() {
            let mint_is_zero = EqZeroGadget::eq_zero(&wallet.balances[i].mint, cs)?;

            for j in (i + 1)..wallet.balances.len() {
                // Check whether balance[i] != balance[j]
                let ij_unique = NotEqualGadget::not_equal(
                    wallet.balances[i].mint,
                    wallet.balances[j].mint,
                    cs,
                )?;

                // Either the mints do not equal one another or they are both zero
                let valid_mints = cs.logic_or(ij_unique, mint_is_zero)?;
                cs.enforce_true(valid_mints)?;
            }
        }

        Ok(())
    }

    /// Check that the fees on the balances are unchanged after update
    fn validate_fee_balances_unchanged(
        old_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS>,
        new_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        for (old_balance, new_balance) in old_wallet.balances.iter().zip(new_wallet.balances.iter())
        {
            cs.enforce_equal(old_balance.relayer_fee_balance, new_balance.relayer_fee_balance)?;
            cs.enforce_equal(old_balance.protocol_fee_balance, new_balance.protocol_fee_balance)?;
        }

        Ok(())
    }

    /// Validates the application of the external transfer to the balance state
    fn validate_transfer_application(
        old_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS>,
        new_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS>,
        transfer_idx: Variable,
        transfer_is_zero: BoolVar,
        external_transfer: &ExternalTransferVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let zero = ScalarField::zero();
        let one = ScalarField::one();
        let zero_var = cs.zero();
        let one_var = cs.one();

        // Negate out the external transfer amount if it is a withdrawal
        let transfer_amount = external_transfer.amount;
        let neg_amount = cs.mul_constant(transfer_amount, &-one)?;

        let is_withdrawal = external_transfer.direction;
        let is_deposit = cs.logic_neg(is_withdrawal)?;
        let transfer_not_zero = cs.logic_neg(transfer_is_zero)?;

        // The term added to the balance matching the external transfer mint
        let external_transfer_term =
            CondSelectGadget::select(&neg_amount, &transfer_amount, is_withdrawal, cs)?;

        let mut found = cs.false_var();
        let mut curr_idx = zero_var;

        // Check the balance state transition for each balance
        for (old_balance, new_balance) in old_wallet.balances.iter().zip(new_wallet.balances.iter())
        {
            // --- Conditional Masking --- //

            let is_transfer_idx = EqGadget::eq(&curr_idx, &transfer_idx, cs)?;
            found = cs.logic_or(found, is_transfer_idx)?;
            let transfer_applies = cs.logic_and(is_transfer_idx, transfer_not_zero)?;

            // --- Amount Updates --- //

            // Mask the transfer amount according to whether the the transfer applies to
            // this balance
            let external_transfer_term = cs.mul(transfer_applies.into(), external_transfer_term)?;

            // Constrain the updated balance to be correctly updated
            //  `new_balance.amount - old_balance.amount - external_transfer_term == 0`
            cs.lc_gate(
                &[
                    new_balance.amount,
                    old_balance.amount,
                    external_transfer_term,
                    cs.zero(),
                    cs.zero(), // output
                ],
                &[one, -one, -one, zero],
            )?;

            // --- Fee Violations --- //

            // To withdraw a balance, all fees in the wallet must be zero
            let fees_paid = EqVecGadget::eq_zero_vec(
                &[old_balance.relayer_fee_balance, old_balance.protocol_fee_balance],
                cs,
            )?;

            // Either no withdrawal (deposit/default) was applied or the fees were zero
            // pre-update
            let valid_fee_update = cs.logic_or(is_deposit, fees_paid)?;
            cs.enforce_true(valid_fee_update)?;

            // --- Mint Updates --- //

            // Valid mint pairs are:
            // 1. If the transfer does not apply to this balance, then two cases are valid:
            //   - The mint is unchanged
            //   - The balance was zero'd in the old wallet and the mint is now zero
            // 2. If the transfer does apply to this balance, then three cases are valid:
            //   - The mint is unchanged, and both mints equal the transfer mint
            //   - The transfer is a deposit, the mint in the old balance was zero (wallet
            //     invariant implies the whole balance was zero),  and the mint in the new
            //     balance is the transfer mint (new deposit)
            //   - The transfer is a withdrawal, the mint in the old balance was the
            //     transfer mint, and the new balance is zero'd (full withdrawal)
            let transfer_not_applied = cs.logic_neg(transfer_applies)?;
            let mints_equal = EqGadget::eq(&old_balance.mint, &new_balance.mint, cs)?;
            let old_mint_equals_transfer =
                EqGadget::eq(&old_balance.mint, &external_transfer.mint, cs)?;
            let new_mint_equals_transfer =
                EqGadget::eq(&new_balance.mint, &external_transfer.mint, cs)?;
            let new_balance_zerod = EqZeroGadget::eq_zero(new_balance, cs)?;
            let old_balance_zero_amounts = EqVecGadget::eq_zero_vec(
                &[
                    old_balance.amount,
                    old_balance.relayer_fee_balance,
                    old_balance.protocol_fee_balance,
                ],
                cs,
            )?;

            // Transfer not applied, no mint change
            let valid_mint1 = cs.logic_and(transfer_not_applied, mints_equal)?;

            // Transfer not applied, balance was zero'd and now the mint is zero
            let valid_mint2 = cs.logic_and_all(&[
                transfer_not_applied,
                old_balance_zero_amounts,
                new_balance_zerod,
            ])?;

            // Transfer applied, mint is unchanged and both mints equal the transfer mint
            let valid_mint3 = cs.logic_and_all(&[
                transfer_applies,
                old_mint_equals_transfer,
                new_mint_equals_transfer,
            ])?;

            // [New Deposit] Transfer applied, old balance was zero'd and the mint is now
            // the transfer mint
            let valid_mint4 = cs.logic_and_all(&[
                transfer_applies,
                is_deposit,
                old_balance_zero_amounts,
                new_mint_equals_transfer,
            ])?;

            // [Full Withdrawal] Transfer applied, old mint was the transfer mint and the
            // new balance is zero'd
            let valid_mint5 = cs.logic_and_all(&[
                transfer_applies,
                is_withdrawal,
                old_mint_equals_transfer,
                new_balance_zerod,
            ])?;

            // Constrain one of the four mint conditions to hold
            let valid_mint = cs.logic_or_all(&[
                valid_mint1,
                valid_mint2,
                valid_mint3,
                valid_mint4,
                valid_mint5,
            ])?;
            cs.enforce_true(valid_mint)?;

            curr_idx = cs.add(curr_idx, one_var)?;
        }

        // Either the transfer was zero, or it was successfully applied
        let transfer_applied_or_zero = cs.logic_or(found, transfer_is_zero)?;
        cs.enforce_true(transfer_applied_or_zero)
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for `VALID WALLET UPDATE`
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug)]
pub struct ValidWalletUpdateWitness<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MERKLE_HEIGHT: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// The private secret shares of the existing wallet
    pub old_wallet_private_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The public secret shares of the existing wallet
    pub old_wallet_public_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The opening of the old wallet's shares to the global Merkle root
    pub old_shares_opening: MerkleOpening<MERKLE_HEIGHT>,
    /// The new wallet's private secret shares
    pub new_wallet_private_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The index in the wallet balances that the external transfer applies to
    pub transfer_index: usize,
}
/// A `VALID WALLET UPDATE` witness with default const generic sizing parameters
pub type SizedValidWalletUpdateWitness =
    ValidWalletUpdateWitness<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>;

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for `VALID WALLET UPDATE`
#[circuit_type(singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidWalletUpdateStatement<const MAX_BALANCES: usize, const MAX_ORDERS: usize>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// The nullifier of the old wallet's secret shares
    pub old_shares_nullifier: Nullifier,
    /// A commitment to the new wallet's secret shares
    pub new_wallet_commitment: WalletShareStateCommitment,
    /// The public secret shares of the new wallet
    pub new_public_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The global Merkle root that the wallet share proofs open to
    pub merkle_root: MerkleRoot,
    /// The external transfer tuple
    pub external_transfer: ExternalTransfer,
    /// The public root key of the old wallet, rotated out after update
    pub old_pk_root: PublicSigningKey,
}
/// A `VALID WALLET UPDATE` statement with default const generic sizing
/// parameters
pub type SizedValidWalletUpdateStatement = ValidWalletUpdateStatement<MAX_BALANCES, MAX_ORDERS>;

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MERKLE_HEIGHT: usize>
    SingleProverCircuit for ValidWalletUpdate<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    type Witness = ValidWalletUpdateWitness<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>;
    type Statement = ValidWalletUpdateStatement<MAX_BALANCES, MAX_ORDERS>;

    fn name() -> String {
        format!("Valid Wallet Update ({MAX_BALANCES}, {MAX_ORDERS}, {MERKLE_HEIGHT})")
    }

    fn apply_constraints(
        witness_var: ValidWalletUpdateWitnessVar<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>,
        statement_var: ValidWalletUpdateStatementVar<MAX_BALANCES, MAX_ORDERS>,
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
    use circuit_types::{
        native_helpers::{compute_wallet_share_commitment, compute_wallet_share_nullifier},
        transfers::ExternalTransfer,
        wallet::Wallet,
    };

    use crate::zk_circuits::test_helpers::{
        create_multi_opening, create_wallet_shares, create_wallet_shares_with_blinder_seed,
        MAX_BALANCES, MAX_ORDERS,
    };

    use super::{ValidWalletUpdateStatement, ValidWalletUpdateWitness};

    /// The witness type with default size parameters attached
    pub type SizedWitness = ValidWalletUpdateWitness<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>;
    /// The statement type with default size parameters attached
    pub type SizedStatement = ValidWalletUpdateStatement<MAX_BALANCES, MAX_ORDERS>;

    /// The height of the Merkle tree to test on
    pub(super) const MERKLE_HEIGHT: usize = 3;

    // -----------
    // | Helpers |
    // -----------

    /// Construct a witness and statement
    pub fn construct_witness_statement<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
        const MERKLE_HEIGHT: usize,
    >(
        old_wallet: &Wallet<MAX_BALANCES, MAX_ORDERS>,
        new_wallet: &Wallet<MAX_BALANCES, MAX_ORDERS>,
        transfer_index: usize,
        external_transfer: ExternalTransfer,
    ) -> (
        ValidWalletUpdateWitness<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>,
        ValidWalletUpdateStatement<MAX_BALANCES, MAX_ORDERS>,
    )
    where
        [(); MAX_BALANCES + MAX_ORDERS]: Sized,
    {
        // Construct secret shares of the wallets
        let mut new_wallet = new_wallet.clone();
        let (old_wallet_private_shares, old_wallet_public_shares) =
            create_wallet_shares(old_wallet);
        let new_wallet_seed = old_wallet_private_shares.blinder;
        let (new_wallet_private_shares, new_wallet_public_shares) =
            create_wallet_shares_with_blinder_seed(&mut new_wallet, new_wallet_seed);

        // Create dummy openings for the old shares
        let old_shares_commitment =
            compute_wallet_share_commitment(&old_wallet_public_shares, &old_wallet_private_shares);
        let (merkle_root, mut opening) =
            create_multi_opening::<MERKLE_HEIGHT>(&[old_shares_commitment]);
        let old_shares_opening = opening.pop().unwrap();

        // Compute nullifiers for the old state
        let old_shares_nullifier =
            compute_wallet_share_nullifier(old_shares_commitment, old_wallet.blinder);

        // Commit to the new wallet shares
        let new_wallet_commitment =
            compute_wallet_share_commitment(&new_wallet_public_shares, &new_wallet_private_shares);

        let witness = ValidWalletUpdateWitness {
            old_wallet_private_shares,
            old_wallet_public_shares,
            new_wallet_private_shares,
            old_shares_opening,
            transfer_index,
        };
        let statement = ValidWalletUpdateStatement {
            old_shares_nullifier,
            old_pk_root: old_wallet.keys.pk_root.clone(),
            new_wallet_commitment,
            new_public_shares: new_wallet_public_shares,
            merkle_root,
            external_transfer,
        };

        (witness, statement)
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod test {
    use circuit_types::{
        balance::Balance,
        elgamal::DecryptionKey,
        fixed_point::FixedPoint,
        keychain::PublicSigningKey,
        native_helpers::compute_wallet_share_commitment,
        order::Order,
        traits::{CircuitBaseType, SingleProverCircuit},
        transfers::{ExternalTransfer, ExternalTransferDirection},
        Address, AMOUNT_BITS, PRICE_BITS,
    };
    use constants::Scalar;
    use k256::ecdsa::SigningKey;
    use mpc_relation::{traits::Circuit, PlonkCircuit};
    use rand::{thread_rng, Rng, RngCore};
    use renegade_crypto::fields::scalar_to_u128;

    use crate::zk_circuits::{
        check_constraint_satisfaction,
        test_helpers::{SizedWallet, INITIAL_WALLET, MAX_BALANCES, MAX_ORDERS},
    };

    use super::{
        test_helpers::{construct_witness_statement, MERKLE_HEIGHT},
        ValidWalletUpdate,
    };

    /// A marker constant for no transfer on the index
    const NO_TRANSFER: usize = 0;

    /// Returns true if the circuit constraints are satisfied on the given
    /// parameters
    fn constraints_satisfied_on_wallets(
        old_wallet: &SizedWallet,
        new_wallet: &SizedWallet,
        transfer_index: usize,
        transfer: ExternalTransfer,
    ) -> bool {
        let (witness, statement) =
            construct_witness_statement(old_wallet, new_wallet, transfer_index, transfer);
        check_constraint_satisfaction::<ValidWalletUpdate<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>>(
            &witness, &statement,
        )
    }

    /// Get the scalar representation of the maximum allowable amount
    fn max_amount_scalar() -> Scalar {
        Scalar::from(2u8).pow(AMOUNT_BITS as u64) - Scalar::one()
    }

    /// Get the fixed point representation of the maximum allowable price
    fn max_price_fp() -> FixedPoint {
        let repr = Scalar::from(2u8).pow(PRICE_BITS as u64) - Scalar::one();
        FixedPoint { repr }
    }

    /// A helper to print the number of constraints in the circuit
    ///
    /// Useful when benchmarking the circuit
    #[test]
    #[ignore]
    fn test_n_constraints() {
        let layout = ValidWalletUpdate::<
            { constants::MAX_BALANCES },
            { constants::MAX_ORDERS },
            { constants::MERKLE_HEIGHT },
        >::get_circuit_layout()
        .unwrap();

        let n_gates = layout.n_gates;
        let circuit_size = layout.circuit_size();
        println!("Number of constraints: {n_gates}");
        println!("Next power of two: {circuit_size}");
    }

    // ---------------------
    // | Keychain Rotation |
    // ---------------------

    /// Tests a valid keychain rotation via a wallet update
    #[test]
    fn test_valid_keychain_rotation() {
        let old_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = INITIAL_WALLET.clone();

        // Rotate the root key
        let mut rng = thread_rng();
        let key = SigningKey::random(&mut rng);
        new_wallet.keys.pk_root = PublicSigningKey::from(key.verifying_key());
        new_wallet.keys.nonce += Scalar::one();

        assert!(constraints_satisfied_on_wallets(
            &old_wallet,
            &new_wallet,
            NO_TRANSFER,
            ExternalTransfer::default()
        ));
    }

    // ----------
    // | Orders |
    // ----------

    /// Tests a valid witness and statement for placing an order
    #[test]
    fn test_place_order__valid() {
        let mut old_wallet = INITIAL_WALLET.clone();
        let new_wallet = INITIAL_WALLET.clone();

        // Remove an order from the initial wallet
        old_wallet.orders[0] = Order::default();

        assert!(constraints_satisfied_on_wallets(
            &old_wallet,
            &new_wallet,
            NO_TRANSFER,
            ExternalTransfer::default()
        ));
    }

    /// Tests order cancellation
    #[test]
    fn test_order_cancellation() {
        let old_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = INITIAL_WALLET.clone();
        new_wallet.orders[0] = Order::default();

        assert!(constraints_satisfied_on_wallets(
            &old_wallet,
            &new_wallet,
            NO_TRANSFER,
            ExternalTransfer::default()
        ))
    }

    /// Tests multiple valid order updates at once
    ///
    /// Includes one cancellation and one placement
    #[test]
    fn test_multi_order_update() {
        let mut old_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = INITIAL_WALLET.clone();
        old_wallet.orders[0] = Order::default();
        new_wallet.orders[1] = Order::default();

        assert!(constraints_satisfied_on_wallets(
            &old_wallet,
            &new_wallet,
            NO_TRANSFER,
            ExternalTransfer::default()
        ))
    }

    /// Tests the case in which an order is placed with an amount that is too
    /// large
    #[test]
    fn test_invalid_order_amount() {
        let old_wallet = INITIAL_WALLET.clone();
        let new_wallet = INITIAL_WALLET.clone();

        // Construct a statement and witness then modify the order amount of the first
        // order to be too large
        let (mut witness, mut statement) = construct_witness_statement(
            &old_wallet,
            &new_wallet,
            NO_TRANSFER,
            ExternalTransfer::default(),
        );

        let blinder =
            statement.new_public_shares.blinder + witness.new_wallet_private_shares.blinder;

        statement.new_public_shares.orders[0].amount = max_amount_scalar() + Scalar::one();
        witness.new_wallet_private_shares.orders[0].amount = blinder; // Cancels out the blinding on the public shares

        // Recompute the wallet commitment
        statement.new_wallet_commitment = compute_wallet_share_commitment(
            &statement.new_public_shares,
            &witness.new_wallet_private_shares,
        );

        let res = check_constraint_satisfaction::<
            ValidWalletUpdate<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>,
        >(&witness, &statement);
        assert!(!res);
    }

    /// Tests an invalid order side
    #[test]
    fn test_invalid_order_side() {
        let old_wallet = INITIAL_WALLET.clone();
        let new_wallet = INITIAL_WALLET.clone();

        // Construct a statement and witness then modify the side of the first order
        let (mut witness, mut statement) = construct_witness_statement(
            &old_wallet,
            &new_wallet,
            NO_TRANSFER,
            ExternalTransfer::default(),
        );

        // Change the side of the first order, changing the shares directly will work
        witness.new_wallet_private_shares.orders[0].side += Scalar::from(2u8);

        // Recompute the wallet commitment
        statement.new_wallet_commitment = compute_wallet_share_commitment(
            &statement.new_public_shares,
            &witness.new_wallet_private_shares,
        );

        let res = check_constraint_satisfaction::<
            ValidWalletUpdate<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>,
        >(&witness, &statement);
        assert!(!res);
    }

    /// Tests an invalid order in which the zero mint is the quote or base mint
    #[test]
    fn test_invalid_order__zero_mint() {
        let mut old_wallet = INITIAL_WALLET.clone();
        let new_wallet = INITIAL_WALLET.clone();
        old_wallet.orders[0] = Order::default();

        // Quote mint is zero in new order
        let mut new_wallet = new_wallet.clone();
        new_wallet.orders[0].quote_mint = Address::from(0u8);

        assert!(!constraints_satisfied_on_wallets(
            &old_wallet,
            &new_wallet,
            NO_TRANSFER,
            ExternalTransfer::default()
        ));

        // Base mint is zero in new order
        let mut new_wallet = new_wallet.clone();
        new_wallet.orders[0].base_mint = Address::from(0u8);

        assert!(!constraints_satisfied_on_wallets(
            &old_wallet,
            &new_wallet,
            NO_TRANSFER,
            ExternalTransfer::default()
        ));
    }

    /// Test the case in which an order is given with an invalid worst case
    /// price
    #[test]
    fn test_invalid_worst_case_price() {
        let mut rng = thread_rng();
        let old_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = INITIAL_WALLET.clone();

        let idx = rng.gen_range(0..MAX_ORDERS);
        let mut price = max_price_fp();
        price.repr += Scalar::one();
        new_wallet.orders[idx].worst_case_price = price;

        // Construct a statement and witness then modify the worst case price of the
        // first order to be too large
        let (witness, statement) = construct_witness_statement(
            &old_wallet,
            &new_wallet,
            NO_TRANSFER,
            ExternalTransfer::default(),
        );

        let res = check_constraint_satisfaction::<
            ValidWalletUpdate<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>,
        >(&witness, &statement);
        assert!(!res);
    }

    // -------------
    // | Transfers |
    // -------------

    /// Tests the case in which the mint is zero but the amount is not
    #[test]
    fn test_zero_mint_transfer() {
        let mut cs = PlonkCircuit::new_turbo_plonk();

        let transfer = ExternalTransfer {
            account_addr: Address::from(0u8),
            mint: Address::from(0u8),
            amount: 1u128,
            direction: ExternalTransferDirection::Deposit,
        };
        let transfer_var = transfer.create_witness(&mut cs);

        let is_zero = cs.false_var();
        ValidWalletUpdate::<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>::validate_external_transfer(
            is_zero,
            &transfer_var,
            &mut cs,
        )
        .unwrap();
        assert!(cs.check_circuit_satisfiability(&[]).is_err());
    }

    /// Tests the case in which the transfer amount is too large
    #[test]
    fn test_invalid_transfer__large_amount() {
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let transfer = ExternalTransfer {
            account_addr: Address::from(0u8),
            mint: Address::from(1u8),
            amount: 0, // replaced
            direction: ExternalTransferDirection::Deposit,
        };

        // Allocate the transfer then replace its amount with a large one
        let large_amt = max_amount_scalar() + Scalar::one();
        let large_amt_var = large_amt.create_witness(&mut cs);

        let mut transfer_var = transfer.create_witness(&mut cs);
        transfer_var.amount = large_amt_var;

        let is_zero = cs.false_var();
        ValidWalletUpdate::<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>::validate_external_transfer(
            is_zero,
            &transfer_var,
            &mut cs,
        )
        .unwrap();
        assert!(cs.check_circuit_satisfiability(&[]).is_err());
    }

    // ------------
    // | Balances |
    // ------------

    /// Tests a non-zero balance for the zero mint -- invalid
    #[test]
    fn test_invalid_balance__non_zero_zero_mint() {
        // To ablate any other constraints, make the zero mint present in both
        let mut old_wallet = INITIAL_WALLET.clone();
        old_wallet.balances[0].mint = Address::from(0u8);
        let new_wallet = old_wallet.clone();

        assert!(!constraints_satisfied_on_wallets(
            &old_wallet,
            &new_wallet,
            NO_TRANSFER,
            ExternalTransfer::default()
        ));
    }

    /// Tests an invalid balance amount
    #[test]
    fn test_invalid_balance__large_amount() {
        // Transfer in an amount that pushes the balance over the maximum
        let mut old_wallet = INITIAL_WALLET.clone();
        let amt = max_amount_scalar() - Scalar::one();
        old_wallet.balances[0].amount = scalar_to_u128(&amt);
        let new_wallet = old_wallet.clone();

        // Construct a statement and witness then modify the order amount of the first
        // order to be too large
        let transfer_amt = 2;
        let (witness, mut statement) = construct_witness_statement(
            &old_wallet,
            &new_wallet,
            0, // transfer index
            ExternalTransfer {
                mint: old_wallet.balances[0].mint.clone(),
                amount: transfer_amt,
                direction: ExternalTransferDirection::Deposit,
                account_addr: Address::from(0u8),
            },
        );

        statement.new_public_shares.balances[0].amount += Scalar::from(transfer_amt);
        let res = check_constraint_satisfaction::<
            ValidWalletUpdate<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>,
        >(&witness, &statement);
        assert!(!res);
    }

    /// Tests the case in which a protocol fee balance is modified in the update
    #[test]
    fn test_invalid_balance__protocol_fee_modified() {
        let old_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = INITIAL_WALLET.clone();
        new_wallet.balances[0].protocol_fee_balance += 1u128;

        assert!(!constraints_satisfied_on_wallets(
            &old_wallet,
            &new_wallet,
            NO_TRANSFER,
            ExternalTransfer::default()
        ));
    }

    /// Tests the case in which a relayer fee balance is modified in the update
    #[test]
    fn test_invalid_balance__relayer_fee_modified() {
        let old_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = INITIAL_WALLET.clone();
        new_wallet.balances[0].relayer_fee_balance += 1u128;

        assert!(!constraints_satisfied_on_wallets(
            &old_wallet,
            &new_wallet,
            NO_TRANSFER,
            ExternalTransfer::default()
        ));
    }

    /// Tests the case in which a duplicate balance is given
    #[test]
    #[allow(clippy::assigning_clones)]
    fn test_duplicate_balance() {
        // No update to the orders, but the timestamp is incorrect
        // To ablate any other constraints, make the duplicate balance present in both
        // wallets
        let mut old_wallet = INITIAL_WALLET.clone();
        old_wallet.balances[1].mint = old_wallet.balances[0].mint.clone();
        let new_wallet = old_wallet.clone();

        assert!(!constraints_satisfied_on_wallets(
            &old_wallet,
            &new_wallet,
            NO_TRANSFER,
            ExternalTransfer::default()
        ));
    }

    // --- Withdrawals --- //

    /// Tests a valid external transfer that withdraws a balance
    #[test]
    fn test_external_transfer__valid_withdrawal() {
        let old_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = INITIAL_WALLET.clone();

        // Withdraw all of the first balance from the new wallet
        let idx = 0;
        new_wallet.balances[idx] = Balance::default();
        let transfer = ExternalTransfer {
            mint: old_wallet.balances[idx].mint.clone(),
            amount: old_wallet.balances[idx].amount,
            direction: ExternalTransferDirection::Withdrawal,
            account_addr: Address::from(0u8),
        };

        assert!(constraints_satisfied_on_wallets(&old_wallet, &new_wallet, idx, transfer));
    }

    /// Tests a valid external transfer that withdraws a partial balance
    #[test]
    fn test_external_transfer__valid_partial_withdrawal() {
        let old_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = INITIAL_WALLET.clone();

        // Withdraw part of the second balance from the original wallet
        let idx = 1;
        let withdrawn_mint = old_wallet.balances[idx].mint.clone();
        let withdrawn_amount = old_wallet.balances[idx].amount - 1; // all but one

        new_wallet.balances[idx] = Balance::new_from_mint_and_amount(withdrawn_mint.clone(), 1);

        // Build a valid transfer
        let transfer = ExternalTransfer {
            mint: withdrawn_mint,
            amount: withdrawn_amount,
            direction: ExternalTransferDirection::Withdrawal,
            account_addr: Address::from(0u8),
        };

        assert!(constraints_satisfied_on_wallets(&old_wallet, &new_wallet, idx, transfer));
    }

    /// Tests an invalid withdrawal in which a balance is incorrectly updated
    #[test]
    fn test_external_transfer__invalid_balance_update() {
        let old_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = INITIAL_WALLET.clone();

        // Withdraw part of the second balance from the original wallet
        let idx = 1;
        let withdrawn_mint = old_wallet.balances[idx].mint.clone();
        let withdrawn_amount = old_wallet.balances[idx].amount - 1; // all but one

        // Add an extra unit of the balance
        new_wallet.balances[idx] = Balance::new_from_mint_and_amount(withdrawn_mint.clone(), 2);

        // Build a valid transfer
        let transfer = ExternalTransfer {
            mint: withdrawn_mint,
            amount: withdrawn_amount,
            direction: ExternalTransferDirection::Withdrawal,
            account_addr: Address::from(0u8),
        };

        assert!(!constraints_satisfied_on_wallets(&old_wallet, &new_wallet, idx, transfer));
    }

    /// Tests an invalid external transfer in which the prover attempts to
    /// withdraw more than their wallet's balance
    #[test]
    fn test_external_transfer__overdraft_withdrawal() {
        let old_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = INITIAL_WALLET.clone();

        // Overdraft the second balance
        let idx = 1;
        let withdrawn_mint = old_wallet.balances[idx].mint.clone();
        let withdrawn_amount = old_wallet.balances[idx].amount + 1; // one more than is present

        new_wallet.balances[idx] = Balance::default();

        // Build a valid transfer
        let transfer = ExternalTransfer {
            mint: withdrawn_mint,
            amount: withdrawn_amount,
            direction: ExternalTransferDirection::Withdrawal,
            account_addr: Address::from(0u8),
        };

        assert!(!constraints_satisfied_on_wallets(&old_wallet, &new_wallet, idx, transfer));
    }

    /// Tests an invalid withdrawal in which the prover attempts to withdraw a
    /// balance that their wallet does not hold
    #[test]
    fn test_external_transfer__withdraw_no_balance() {
        let old_wallet = INITIAL_WALLET.clone();
        let new_wallet = INITIAL_WALLET.clone();

        // Withdraw a random balance
        let mut rng = thread_rng();
        let withdrawn_mint = Address::from(rng.next_u32());
        let withdrawn_amount = 1u128;

        // Build a valid transfer
        let idx = 0;
        let transfer = ExternalTransfer {
            mint: withdrawn_mint,
            amount: withdrawn_amount,
            direction: ExternalTransferDirection::Withdrawal,
            account_addr: Address::from(0u8),
        };

        assert!(!constraints_satisfied_on_wallets(&old_wallet, &new_wallet, idx, transfer));
    }

    /// Tests an invalid withdrawal in which the prover adds an unrelated
    /// balance as well as decrementing the updated balance
    #[test]
    fn test_external_transfer__invalid_withdrawal_extra_update() {
        let old_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = INITIAL_WALLET.clone();
        let idx = 1;
        new_wallet.balances[idx] = Balance::default();

        // Transfer units of an existing mint into the wallet
        let withdrawal_mint = old_wallet.balances[idx].mint.clone();
        let withdrawal_amount = old_wallet.balances[idx].amount;

        // Prover also tries to increment the non-updated balance
        new_wallet.balances[0].amount += 1;

        let transfer = ExternalTransfer {
            mint: withdrawal_mint,
            amount: withdrawal_amount,
            direction: ExternalTransferDirection::Withdrawal,
            account_addr: Address::from(0u8),
        };

        assert!(!constraints_satisfied_on_wallets(&old_wallet, &new_wallet, idx, transfer));
    }

    /// Try withdrawing when the wallet has a non-zero protocol fee -- this is
    /// invalid
    #[test]
    fn test_invalid_withdrawal__non_zero_protocol_fee() {
        // Setup a wallet with outstanding fees
        let mut rng = thread_rng();
        let fee_idx = rng.gen_range(0..MAX_BALANCES);

        let mut old_wallet = INITIAL_WALLET.clone();
        old_wallet.balances[fee_idx].protocol_fee_balance = 1;

        // Withdraw from the balance
        let mut new_wallet = old_wallet.clone();
        let idx = 0;
        new_wallet.balances[idx].amount -= 1;

        let transfer = ExternalTransfer {
            mint: old_wallet.balances[idx].mint.clone(),
            amount: 1,
            direction: ExternalTransferDirection::Withdrawal,
            account_addr: Address::from(0u8),
        };

        assert!(!constraints_satisfied_on_wallets(&old_wallet, &new_wallet, idx, transfer));
    }

    /// Try withdrawing from a balance with non-zero relayer fee -- this is
    /// invalid
    #[test]
    fn test_invalid_withdrawal__non_zero_relayer_fee() {
        // Setup a wallet with outstanding fees
        let mut rng = thread_rng();
        let fee_idx = rng.gen_range(0..MAX_BALANCES);

        let mut old_wallet = INITIAL_WALLET.clone();
        old_wallet.balances[fee_idx].relayer_fee_balance = 1;

        // Withdraw from the wallet
        let mut new_wallet = old_wallet.clone();
        let idx = 0;
        new_wallet.balances[idx].amount -= 1;

        let transfer = ExternalTransfer {
            mint: old_wallet.balances[idx].mint.clone(),
            amount: 1,
            direction: ExternalTransferDirection::Withdrawal,
            account_addr: Address::from(0u8),
        };

        assert!(!constraints_satisfied_on_wallets(&old_wallet, &new_wallet, idx, transfer));
    }

    // --- Deposits --- //

    /// Tests a valid deposit into the wallet that adds a new balance
    #[test]
    fn test_external_transfer__valid_deposit_new_balance() {
        let mut old_wallet = INITIAL_WALLET.clone();
        let new_wallet = INITIAL_WALLET.clone();

        // Remove the first balance from the old wallet
        let idx = 0;
        old_wallet.balances[idx] = Balance::default();

        // Transfer a brand new mint into the new wallet
        let deposit_mint = new_wallet.balances[idx].mint.clone();
        let deposit_amount = new_wallet.balances[idx].amount;

        let transfer = ExternalTransfer {
            mint: deposit_mint,
            amount: deposit_amount,
            direction: ExternalTransferDirection::Deposit,
            account_addr: Address::from(0u8),
        };

        assert!(constraints_satisfied_on_wallets(&old_wallet, &new_wallet, idx, transfer));
    }

    /// Tests a valid deposit into the wallet that adds to an existing balance
    #[test]
    fn test_external_transfer__valid_deposit_existing_balance() {
        let old_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = INITIAL_WALLET.clone();

        // Transfer units of an existing mint into the wallet
        let idx = 1;
        let deposit_mint = new_wallet.balances[idx].mint.clone();
        let deposit_amount = 10;

        new_wallet.balances[idx].amount += deposit_amount;

        let transfer = ExternalTransfer {
            mint: deposit_mint,
            amount: deposit_amount,
            direction: ExternalTransferDirection::Deposit,
            account_addr: Address::from(0u8),
        };

        assert!(constraints_satisfied_on_wallets(&old_wallet, &new_wallet, idx, transfer));
    }

    /// Tests an invalid deposit in which the balance is updated incorrectly
    #[test]
    fn test_external_transfer__invalid_deposit_balance_update() {
        let old_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = INITIAL_WALLET.clone();

        // Transfer units of an existing mint into the wallet
        let idx = 1;
        let deposit_mint = new_wallet.balances[idx].mint.clone();
        let deposit_amount = 10;

        // Prover adds one more unit than the transfer is for
        new_wallet.balances[idx].amount += deposit_amount + 1;

        let transfer = ExternalTransfer {
            mint: deposit_mint,
            amount: deposit_amount,
            direction: ExternalTransferDirection::Deposit,
            account_addr: Address::from(0u8),
        };

        assert!(!constraints_satisfied_on_wallets(&old_wallet, &new_wallet, idx, transfer));
    }

    /// Tests an invalid deposit in which the prover adds an unrelated balance
    /// as well as the updated balance
    #[test]
    fn test_external_transfer__invalid_deposit_extra_update() {
        let old_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = INITIAL_WALLET.clone();

        // Transfer units of an existing mint into the wallet
        let idx = 1;
        let deposit_mint = new_wallet.balances[idx].mint.clone();
        let deposit_amount = new_wallet.balances[idx].amount;

        new_wallet.balances[idx].amount += deposit_amount;

        // Prover also tries to increment the non-updated balance
        new_wallet.balances[0].amount += 1;

        let transfer = ExternalTransfer {
            mint: deposit_mint,
            amount: deposit_amount,
            direction: ExternalTransferDirection::Deposit,
            account_addr: Address::from(0u8),
        };

        assert!(!constraints_satisfied_on_wallets(&old_wallet, &new_wallet, idx, transfer));
    }

    /// Top up a balance with non-zero fees -- this is valid
    #[test]
    fn test_deposit_with_nonzero_fee() {
        // Old wallet with outstanding fees
        let mut old_wallet = INITIAL_WALLET.clone();
        let idx = 0;
        old_wallet.balances[idx].protocol_fee_balance = 1;

        // Deposit additional balance into it
        let mut new_wallet = old_wallet.clone();
        new_wallet.balances[idx].amount += 1;

        let transfer = ExternalTransfer {
            mint: old_wallet.balances[idx].mint.clone(),
            amount: 1,
            direction: ExternalTransferDirection::Deposit,
            account_addr: Address::from(0u8),
        };

        assert!(constraints_satisfied_on_wallets(&old_wallet, &new_wallet, idx, transfer));
    }

    // --- Mint Updates --- //

    /// Tests the case in which a zero'd balance with non-zero mint is replaced
    /// in a withdrawal
    #[test]
    fn test_replace_zero_balance() {
        let mut rng = thread_rng();

        // Setup the old wallet with a balance of zero amount and fees
        let mut old_wallet = INITIAL_WALLET.clone();
        let idx = 0;
        old_wallet.balances[idx] = Balance::new_from_mint(old_wallet.balances[idx].mint.clone());

        // Replace that balance with a new deposit
        let new_mint = Address::from(rng.next_u64());
        let new_amt = 1;
        let mut new_wallet = old_wallet.clone();
        new_wallet.balances[idx] = Balance::new_from_mint_and_amount(new_mint.clone(), new_amt);

        let transfer = ExternalTransfer {
            mint: new_mint,
            amount: new_amt,
            direction: ExternalTransferDirection::Deposit,
            account_addr: Address::from(0u8),
        };

        assert!(constraints_satisfied_on_wallets(&old_wallet, &new_wallet, idx, transfer));
    }

    /// Tests the case in which a zero'd balance is replaced by a zero mint
    #[test]
    fn test_replace_zero_balance_with_zero_mint() {
        let mut old_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = INITIAL_WALLET.clone();

        // Set the first balance to have zero amount and fees
        old_wallet.balances[0] = Balance::new_from_mint(Address::from(1u8));

        // Replace it with an entirely zero'd balance
        new_wallet.balances[0] = Balance::default();

        assert!(constraints_satisfied_on_wallets(
            &old_wallet,
            &new_wallet,
            NO_TRANSFER,
            ExternalTransfer::default()
        ));
    }

    // -------------------------------
    // | Malicious Prover Test Cases |
    // -------------------------------

    /// Tests the case in which a prover zeros a balance without any external
    /// transfer corresponding to the update
    #[test]
    fn test_malicious_prover__spuriously_zerod_balance() {
        let old_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = INITIAL_WALLET.clone();

        // Prover spuriously zeros a balance without transfer
        new_wallet.balances[0] = Balance::default();

        assert!(!constraints_satisfied_on_wallets(
            &old_wallet,
            &new_wallet,
            NO_TRANSFER,
            ExternalTransfer::default()
        ));
    }

    /// Tests the case in which the prover attempts to change the match fee of
    /// the wallet
    ///
    /// This is invalid for now, we may allow the _user_ to do so in the future
    #[test]
    fn test_malicious_prover__increase_match_fee() {
        let old_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = INITIAL_WALLET.clone();

        new_wallet.max_match_fee = new_wallet.max_match_fee + Scalar::one();

        assert!(!constraints_satisfied_on_wallets(
            &old_wallet,
            &new_wallet,
            NO_TRANSFER,
            ExternalTransfer::default()
        ));
    }

    /// Tests the case in which the prover attempts to change the managing
    /// cluster of the wallet
    ///
    /// This is invalid for now, we may allow the _user_ to do so in the future
    #[test]
    fn test_malicious_prover__change_cluster() {
        let mut rng = thread_rng();
        let old_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = INITIAL_WALLET.clone();

        let (_, new_key) = DecryptionKey::random_pair(&mut rng);
        new_wallet.managing_cluster = new_key;

        assert!(!constraints_satisfied_on_wallets(
            &old_wallet,
            &new_wallet,
            NO_TRANSFER,
            ExternalTransfer::default()
        ));
    }

    // --- Misc Invalid Cases --- //

    /// Tests the case in which the new wallet's public blinder share is not
    /// properly derived from the blinder stream
    #[test]
    fn test_incorrect_blinder_share() {
        let mut rng = thread_rng();
        let old_wallet = INITIAL_WALLET.clone();
        let new_wallet = INITIAL_WALLET.clone();
        let (mut witness, mut statement) =
            construct_witness_statement::<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>(
                &old_wallet,
                &new_wallet,
                NO_TRANSFER,
                ExternalTransfer::default(),
            );

        // Incorrectly blind the new wallet
        let offset = Scalar::random(&mut rng);
        witness.new_wallet_private_shares.blinder += offset;
        statement.new_public_shares.blinder -= offset;
        statement.new_wallet_commitment = compute_wallet_share_commitment(
            &statement.new_public_shares,
            &witness.new_wallet_private_shares,
        );

        // Check that the constraints are not satisfied
        let res = check_constraint_satisfaction::<
            ValidWalletUpdate<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>,
        >(&witness, &statement);
        assert!(!res);
    }
}
