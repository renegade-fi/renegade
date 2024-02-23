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
        wallet_operations::{AmountGadget, WalletGadget},
    },
    SingleProverCircuit,
};

// ----------------------
// | Circuit Definition |
// ----------------------

/// A type alias for the `ValidWalletUpdate` circuit with default size
/// parameters attached
pub type SizedValidWalletUpdate = ValidWalletUpdate<MAX_ORDERS, MAX_BALANCES, MERKLE_HEIGHT>;

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

        // Validate the commitment to the new wallet private shares
        let new_wallet_private_commitment =
            WalletGadget::compute_private_commitment(&witness.new_wallet_private_shares, cs)?;
        cs.enforce_equal(new_wallet_private_commitment, statement.new_private_shares_commitment)?;

        // Recover the old wallet from shares
        let old_wallet = WalletGadget::wallet_from_shares(
            &witness.old_wallet_public_shares,
            &witness.old_wallet_private_shares,
            cs,
        )?;

        // -- Authorization -- //

        // Check pk_root in the statement corresponds to pk_root in the wallet
        EqGadget::constrain_eq(&statement.old_pk_root, &old_wallet.keys.pk_root, cs)?;

        // -- State transition validity -- //

        // Reconstruct the new wallet from shares
        let new_wallet = WalletGadget::wallet_from_shares(
            &statement.new_public_shares,
            &witness.new_wallet_private_shares,
            cs,
        )?;
        Self::verify_wallet_transition(&old_wallet, &new_wallet, &statement.external_transfer, cs)
    }

    /// Verify a state transition between two wallets
    fn verify_wallet_transition(
        old_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS>,
        new_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS>,
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
            transfer_is_zero,
            external_transfer,
            cs,
        )?;

        // The match_fee and managing_cluster should remain unchanged
        //
        // Note that the keys are allowed to change to enable key rotation. The actual
        // wallet transition is authorized by a signature from the old root key
        // (checked on-chain) so rotation is protected outside of the circuit
        EqGadget::constrain_eq(&old_wallet.match_fee, &new_wallet.match_fee, cs)?;
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
        // zero This is equivalent to enforcing `mint_is_zero ==
        // transfer_is_zero`
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
            let balance_is_zero = EqZeroGadget::eq_zero(&balance.amount, cs)?;
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
        let one = ScalarField::one();

        for i in 0..wallet.balances.len() {
            for j in (i + 1)..wallet.balances.len() {
                // Check whether balance[i] != balance[j]
                let ij_unique = NotEqualGadget::not_equal(
                    wallet.balances[i].mint,
                    wallet.balances[j].mint,
                    cs,
                )?;

                // Evaluate the polynomial mint * (1 - ij_unique) which is 0 iff
                // the mint is zero, or balance[i] != balance[j]
                let mint = wallet.balances[i].mint;
                cs.mul_add_gate(
                    &[mint, cs.one(), mint, ij_unique.into(), cs.zero()],
                    &[one, -one],
                )?;
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
        transfer_is_zero: BoolVar,
        external_transfer: &ExternalTransferVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let zero = ScalarField::zero();
        let one = ScalarField::one();

        // Negate out the external transfer amount if it is a withdrawal
        let transfer_amount = external_transfer.amount;
        let neg_amount = cs.mul_constant(transfer_amount, &-one)?;

        // The term added to the balance matching the external transfer mint
        let external_transfer_term =
            cs.mux(external_transfer.direction, neg_amount, transfer_amount)?;

        // Stores a counter indicating whether the external transfer appeared in the new
        // balances; it must be applied to at least one balance
        let mut external_transfer_applied = cs.zero();

        // Check the balance state transition for each balance
        for (old_balance, new_balance) in old_wallet.balances.iter().zip(new_wallet.balances.iter())
        {
            // --- Conditional Masking --- //

            // Whether or not the transfer applies to this balance -- this is true if the
            // transfer mint is equal to either the old or new balance mint
            let equals_old_mint = EqGadget::eq(&old_balance.mint, &external_transfer.mint, cs)?;
            let equals_new_mint = EqGadget::eq(&new_balance.mint, &external_transfer.mint, cs)?;
            let transfer_applies = cs.logic_or(equals_old_mint, equals_new_mint)?;

            // Mask the transfer amount according to whether the the transfer applies to
            // this balance
            let external_transfer_term = cs.mul(transfer_applies.into(), external_transfer_term)?;

            // Mark the transfer as applied
            external_transfer_applied =
                cs.add(external_transfer_applied, transfer_applies.into())?;

            // --- Amount Updates --- //

            // Constrain the updated balance to be correctly updated
            //  `new_balance.amount - old_balance.amount - external_transfer_term == 0`
            cs.lc_gate(
                &[
                    new_balance.amount,
                    old_balance.amount,
                    external_transfer_term,
                    cs.one(),
                    cs.zero(), // output
                ],
                &[one, -one, -one, zero],
            )?;

            // --- Fee Violations --- //

            // If the transfer is a withdrawal, the fees must be zero for the balance
            let old_fees_are_zero = EqVecGadget::eq_zero_vec(
                &[old_balance.relayer_fee_balance, old_balance.protocol_fee_balance],
                cs,
            )?;
            let withdrawal_applied_to_balance =
                cs.logic_and(transfer_applies, external_transfer.direction)?;
            let withdrawal_not_applied = cs.logic_neg(withdrawal_applied_to_balance)?;

            // Either no withdrawal was applied or the fees were zero pre-update
            let valid_fee_update = cs.logic_or(withdrawal_not_applied, old_fees_are_zero)?;
            cs.enforce_true(valid_fee_update)?;

            // --- Mint Updates --- //

            // Constrain the mints to be set correctly. A valid mint is one of:
            //  1. The same mint as in the old wallet
            //  2. The old mint was zero and the new mint is the transfer mint
            //  3. The old mint was the transfer mint and the new mint is zero
            //  4. The transfer or zero mint, if it replaces a balance that had zero amount
            //     & fees
            let mints_equal = EqGadget::eq(&old_balance.mint, &new_balance.mint, cs)?;
            let old_mint_equals_transfer_mint =
                EqGadget::eq(&old_balance.mint, &external_transfer.mint, cs)?;
            let new_mint_equals_transfer_mint =
                EqGadget::eq(&new_balance.mint, &external_transfer.mint, cs)?;
            let old_mint_is_zero = EqZeroGadget::eq_zero(&old_balance.mint, cs)?;
            let new_mint_is_zero = EqZeroGadget::eq_zero(&new_balance.mint, cs)?;
            let old_amount_zero = EqZeroGadget::eq_zero(&old_balance.amount, cs)?;
            let prev_balance_was_zerod = cs.logic_and(old_amount_zero, old_fees_are_zero)?;

            // Condition 1 -- same mint as old wallet
            let valid_mint1 = mints_equal;

            // Condition 2 -- new mint added to wallet
            let valid_mint2 = cs.logic_and(new_mint_equals_transfer_mint, old_mint_is_zero)?;

            // Condition 3 -- withdrawal of entire balance, mint is now zero
            let valid_mint3 = cs.logic_and(old_mint_equals_transfer_mint, new_mint_is_zero)?;

            // Condition 4 -- A zero'd balance with non-zero mint was replaced either by a
            // zero mint or the transfer mint
            let new_mint_transfer_or_zero =
                cs.logic_or(new_mint_equals_transfer_mint, new_mint_is_zero)?;
            let valid_mint4 = cs.logic_and(new_mint_transfer_or_zero, prev_balance_was_zerod)?;

            // Constrain one of the four mint conditions to hold
            let valid_mint =
                cs.logic_or_all(&[valid_mint1, valid_mint2, valid_mint3, valid_mint4])?;
            cs.enforce_true(valid_mint)?;
        }

        // Validate that the external transfer's mint did show up in exactly one of the
        // balances
        let single_transfer_applied = EqGadget::eq(&external_transfer_applied, &cs.one(), cs)?;
        let transfer_applied_or_zero = cs.logic_or(single_transfer_applied, transfer_is_zero)?;
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
    /// A commitment to the new wallet's private secret shares
    pub new_private_shares_commitment: WalletShareStateCommitment,
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
        native_helpers::{
            compute_wallet_private_share_commitment, compute_wallet_share_commitment,
            compute_wallet_share_nullifier,
        },
        transfers::ExternalTransfer,
        wallet::Wallet,
    };

    use crate::zk_circuits::test_helpers::{
        create_multi_opening, create_wallet_shares, MAX_BALANCES, MAX_ORDERS,
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
        external_transfer: ExternalTransfer,
    ) -> (
        ValidWalletUpdateWitness<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>,
        ValidWalletUpdateStatement<MAX_BALANCES, MAX_ORDERS>,
    )
    where
        [(); MAX_BALANCES + MAX_ORDERS]: Sized,
    {
        // Construct secret shares of the wallets
        let (old_wallet_private_shares, old_wallet_public_shares) =
            create_wallet_shares(old_wallet);
        let (new_wallet_private_shares, new_wallet_public_shares) =
            create_wallet_shares(new_wallet);

        // Create dummy openings for the old shares
        let old_shares_commitment =
            compute_wallet_share_commitment(&old_wallet_public_shares, &old_wallet_private_shares);
        let (merkle_root, mut opening) =
            create_multi_opening::<MERKLE_HEIGHT>(&[old_shares_commitment]);
        let old_shares_opening = opening.pop().unwrap();

        // Compute nullifiers for the old state
        let old_shares_nullifier =
            compute_wallet_share_nullifier(old_shares_commitment, old_wallet.blinder);

        // Commit to the new private shares
        let new_private_shares_commitment =
            compute_wallet_private_share_commitment(&new_wallet_private_shares);

        let witness = ValidWalletUpdateWitness {
            old_wallet_private_shares,
            old_wallet_public_shares,
            new_wallet_private_shares,
            old_shares_opening,
        };
        let statement = ValidWalletUpdateStatement {
            old_shares_nullifier,
            old_pk_root: old_wallet.keys.pk_root.clone(),
            new_private_shares_commitment,
            new_public_shares: new_wallet_public_shares,
            merkle_root,
            external_transfer,
        };

        (witness, statement)
    }
}

#[cfg(test)]
mod test {
    #![allow(non_snake_case)]

    use circuit_types::{
        balance::Balance,
        native_helpers::compute_wallet_private_share_commitment,
        order::Order,
        traits::CircuitBaseType,
        transfers::{ExternalTransfer, ExternalTransferDirection},
        AMOUNT_BITS,
    };
    use constants::Scalar;
    use mpc_relation::{traits::Circuit, PlonkCircuit};
    use num_bigint::BigUint;
    use rand::{thread_rng, RngCore};
    use renegade_crypto::fields::scalar_to_u128;

    use crate::zk_circuits::{
        check_constraint_satisfaction,
        test_helpers::{SizedWallet, INITIAL_WALLET, MAX_BALANCES, MAX_ORDERS},
    };

    use super::{
        test_helpers::{construct_witness_statement, MERKLE_HEIGHT},
        ValidWalletUpdate,
    };

    /// Returns true if the circuit constraints are satisfied on the given
    /// parameters
    fn constraints_satisfied_on_wallets(
        old_wallet: &SizedWallet,
        new_wallet: &SizedWallet,
        transfer: ExternalTransfer,
    ) -> bool {
        let (witness, statement) = construct_witness_statement(old_wallet, new_wallet, transfer);
        check_constraint_satisfaction::<ValidWalletUpdate<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>>(
            &witness, &statement,
        )
    }

    /// Get the scalar representation of the maximum allowable amount
    fn max_amount_scalar() -> Scalar {
        Scalar::from(2u8).pow(AMOUNT_BITS as u64) - Scalar::from(1u8)
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
        let (mut witness, mut statement) =
            construct_witness_statement(&old_wallet, &new_wallet, ExternalTransfer::default());

        let blinder =
            statement.new_public_shares.blinder + witness.new_wallet_private_shares.blinder;

        statement.new_public_shares.orders[0].amount = max_amount_scalar() + Scalar::one();
        witness.new_wallet_private_shares.orders[0].amount = blinder; // Cancels out the blinding on the public shares

        // Recompute the wallet commitment
        statement.new_private_shares_commitment =
            compute_wallet_private_share_commitment(&witness.new_wallet_private_shares);

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
        let (mut witness, mut statement) =
            construct_witness_statement(&old_wallet, &new_wallet, ExternalTransfer::default());

        // Change the side of the first order, changing the shares directly will work
        witness.new_wallet_private_shares.orders[0].side += Scalar::from(2u8);

        // Recompute the wallet commitment
        statement.new_private_shares_commitment =
            compute_wallet_private_share_commitment(&witness.new_wallet_private_shares);

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
        new_wallet.orders[0].quote_mint = BigUint::from(0u8);

        assert!(!constraints_satisfied_on_wallets(
            &old_wallet,
            &new_wallet,
            ExternalTransfer::default()
        ));

        // Base mint is zero in new order
        let mut new_wallet = new_wallet.clone();
        new_wallet.orders[0].base_mint = BigUint::from(0u8);

        assert!(!constraints_satisfied_on_wallets(
            &old_wallet,
            &new_wallet,
            ExternalTransfer::default()
        ));
    }

    // -------------
    // | Transfers |
    // -------------

    /// Tests the case in which the mint is zero but the amount is not
    #[test]
    fn test_zero_mint_transfer() {
        let mut cs = PlonkCircuit::new_turbo_plonk();

        let transfer = ExternalTransfer {
            account_addr: BigUint::from(0u8),
            mint: BigUint::from(0u8),
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
            account_addr: BigUint::from(0u8),
            mint: BigUint::from(1u8),
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
        old_wallet.balances[0].mint = BigUint::from(0u8);
        let new_wallet = old_wallet.clone();

        assert!(!constraints_satisfied_on_wallets(
            &old_wallet,
            &new_wallet,
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
            ExternalTransfer {
                mint: old_wallet.balances[0].mint.clone(),
                amount: transfer_amt,
                direction: ExternalTransferDirection::Deposit,
                account_addr: BigUint::from(0u8),
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
            ExternalTransfer::default()
        ));
    }

    /// Tests the case in which a duplicate balance is given
    #[test]
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
        new_wallet.balances[0] = Balance::default();
        let transfer = ExternalTransfer {
            mint: old_wallet.balances[0].mint.clone(),
            amount: old_wallet.balances[0].amount,
            direction: ExternalTransferDirection::Withdrawal,
            account_addr: BigUint::from(0u8),
        };

        assert!(constraints_satisfied_on_wallets(&old_wallet, &new_wallet, transfer));
    }

    /// Tests a valid external transfer that withdraws a partial balance
    #[test]
    fn test_external_transfer__valid_partial_withdrawal() {
        let old_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = INITIAL_WALLET.clone();

        // Withdraw part of the second balance from the original wallet
        let withdrawn_mint = old_wallet.balances[1].mint.clone();
        let withdrawn_amount = old_wallet.balances[1].amount - 1; // all but one

        new_wallet.balances[1] = Balance::new_from_mint_and_amount(withdrawn_mint.clone(), 1);

        // Build a valid transfer
        let transfer = ExternalTransfer {
            mint: withdrawn_mint,
            amount: withdrawn_amount,
            direction: ExternalTransferDirection::Withdrawal,
            account_addr: BigUint::from(0u8),
        };

        assert!(constraints_satisfied_on_wallets(&old_wallet, &new_wallet, transfer));
    }

    /// Tests an invalid withdrawal in which a balance is incorrectly updated
    #[test]
    fn test_external_transfer__invalid_balance_update() {
        let old_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = INITIAL_WALLET.clone();

        // Withdraw part of the second balance from the original wallet
        let withdrawn_mint = old_wallet.balances[1].mint.clone();
        let withdrawn_amount = old_wallet.balances[1].amount - 1; // all but one

        // Add an extra unit of the balance
        new_wallet.balances[1] = Balance::new_from_mint_and_amount(withdrawn_mint.clone(), 2);

        // Build a valid transfer
        let transfer = ExternalTransfer {
            mint: withdrawn_mint,
            amount: withdrawn_amount,
            direction: ExternalTransferDirection::Withdrawal,
            account_addr: BigUint::from(0u8),
        };

        assert!(!constraints_satisfied_on_wallets(&old_wallet, &new_wallet, transfer));
    }

    /// Tests an invalid external transfer in which the prover attempts to
    /// withdraw more than their wallet's balance
    #[test]
    fn test_external_transfer__overdraft_withdrawal() {
        let old_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = INITIAL_WALLET.clone();

        // Overdraft the second balance
        let withdrawn_mint = old_wallet.balances[1].mint.clone();
        let withdrawn_amount = old_wallet.balances[1].amount + 1; // one more than is present

        new_wallet.balances[1] = Balance::default();

        // Build a valid transfer
        let transfer = ExternalTransfer {
            mint: withdrawn_mint,
            amount: withdrawn_amount,
            direction: ExternalTransferDirection::Withdrawal,
            account_addr: BigUint::from(0u8),
        };

        assert!(!constraints_satisfied_on_wallets(&old_wallet, &new_wallet, transfer));
    }

    /// Tests an invalid withdrawal in which the prover attempts to withdraw a
    /// balance that their wallet does not hold
    #[test]
    fn test_external_transfer__withdraw_no_balance() {
        let old_wallet = INITIAL_WALLET.clone();
        let new_wallet = INITIAL_WALLET.clone();

        // Withdraw a random balance
        let mut rng = thread_rng();
        let withdrawn_mint = BigUint::from(rng.next_u32());
        let withdrawn_amount = 1u128;

        // Build a valid transfer
        let transfer = ExternalTransfer {
            mint: withdrawn_mint,
            amount: withdrawn_amount,
            direction: ExternalTransferDirection::Withdrawal,
            account_addr: BigUint::from(0u8),
        };

        assert!(!constraints_satisfied_on_wallets(&old_wallet, &new_wallet, transfer));
    }

    /// Tests an invalid withdrawal in which the prover adds an unrelated
    /// balance as well as decrementing the updated balance
    #[test]
    fn test_external_transfer__invalid_withdrawal_extra_update() {
        let old_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = INITIAL_WALLET.clone();
        new_wallet.balances[1] = Balance::default();

        // Transfer units of an existing mint into the wallet
        let withdrawal_mint = old_wallet.balances[1].mint.clone();
        let withdrawal_amount = old_wallet.balances[1].amount;

        // Prover also tries to increment the non-updated balance
        new_wallet.balances[0].amount += 1;

        let transfer = ExternalTransfer {
            mint: withdrawal_mint,
            amount: withdrawal_amount,
            direction: ExternalTransferDirection::Withdrawal,
            account_addr: BigUint::from(0u8),
        };

        assert!(!constraints_satisfied_on_wallets(&old_wallet, &new_wallet, transfer));
    }

    /// Try withdrawing from a balance with non-zero protocol fee -- this is
    /// invalid
    #[test]
    fn test_invalid_withdrawal__non_zero_protocol_fee() {
        // Setup a wallet with outstanding fees
        let mut old_wallet = INITIAL_WALLET.clone();
        old_wallet.balances[0].protocol_fee_balance = 1;

        // Withdraw from the balance
        let mut new_wallet = old_wallet.clone();
        new_wallet.balances[0].amount -= 1;

        let transfer = ExternalTransfer {
            mint: old_wallet.balances[0].mint.clone(),
            amount: 1,
            direction: ExternalTransferDirection::Withdrawal,
            account_addr: BigUint::from(0u8),
        };

        assert!(!constraints_satisfied_on_wallets(&old_wallet, &new_wallet, transfer));
    }

    /// Try withdrawing from a balance with non-zero relayer fee -- this is
    /// invalid
    #[test]
    fn test_invalid_withdrawal__non_zero_relayer_fee() {
        // Setup a wallet with outstanding fees
        let mut old_wallet = INITIAL_WALLET.clone();
        old_wallet.balances[0].relayer_fee_balance = 1;

        // Withdraw from the wallet
        let mut new_wallet = old_wallet.clone();
        new_wallet.balances[0].amount -= 1;

        let transfer = ExternalTransfer {
            mint: old_wallet.balances[0].mint.clone(),
            amount: 1,
            direction: ExternalTransferDirection::Withdrawal,
            account_addr: BigUint::from(0u8),
        };

        assert!(!constraints_satisfied_on_wallets(&old_wallet, &new_wallet, transfer));
    }

    // --- Deposits --- //

    /// Tests a valid deposit into the wallet that adds a new balance
    #[test]
    fn test_external_transfer__valid_deposit_new_balance() {
        let mut old_wallet = INITIAL_WALLET.clone();
        let new_wallet = INITIAL_WALLET.clone();

        // Remove the first balance from the old wallet
        old_wallet.balances[0] = Balance::default();

        // Transfer a brand new mint into the new wallet
        let deposit_mint = new_wallet.balances[0].mint.clone();
        let deposit_amount = new_wallet.balances[0].amount;

        let transfer = ExternalTransfer {
            mint: deposit_mint,
            amount: deposit_amount,
            direction: ExternalTransferDirection::Deposit,
            account_addr: BigUint::from(0u8),
        };

        assert!(constraints_satisfied_on_wallets(&old_wallet, &new_wallet, transfer));
    }

    /// Tests a valid deposit into the wallet that adds to an existing balance
    #[test]
    fn test_external_transfer__valid_deposit_existing_balance() {
        let old_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = INITIAL_WALLET.clone();

        // Transfer units of an existing mint into the wallet
        let deposit_mint = new_wallet.balances[1].mint.clone();
        let deposit_amount = new_wallet.balances[1].amount;

        new_wallet.balances[1].amount += deposit_amount;

        let transfer = ExternalTransfer {
            mint: deposit_mint,
            amount: deposit_amount,
            direction: ExternalTransferDirection::Deposit,
            account_addr: BigUint::from(0u8),
        };

        assert!(constraints_satisfied_on_wallets(&old_wallet, &new_wallet, transfer));
    }

    /// Tests an invalid deposit in which the balance is updated incorrectly
    #[test]
    fn test_external_transfer__invalid_deposit_balance_update() {
        let old_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = INITIAL_WALLET.clone();

        // Transfer units of an existing mint into the wallet
        let deposit_mint = new_wallet.balances[1].mint.clone();
        let deposit_amount = new_wallet.balances[1].amount;

        // Prover adds one more unit than the transfer is for
        new_wallet.balances[1].amount += deposit_amount + 1;

        let transfer = ExternalTransfer {
            mint: deposit_mint,
            amount: deposit_amount,
            direction: ExternalTransferDirection::Deposit,
            account_addr: BigUint::from(0u8),
        };

        assert!(!constraints_satisfied_on_wallets(&old_wallet, &new_wallet, transfer));
    }

    /// Tests an invalid deposit in which the prover adds an unrelated balance
    /// as well as the updated balance
    #[test]
    fn test_external_transfer__invalid_deposit_extra_update() {
        let old_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = INITIAL_WALLET.clone();

        // Transfer units of an existing mint into the wallet
        let deposit_mint = new_wallet.balances[1].mint.clone();
        let deposit_amount = new_wallet.balances[1].amount;

        new_wallet.balances[1].amount += deposit_amount;

        // Prover also tries to increment the non-updated balance
        new_wallet.balances[0].amount += 1;

        let transfer = ExternalTransfer {
            mint: deposit_mint,
            amount: deposit_amount,
            direction: ExternalTransferDirection::Deposit,
            account_addr: BigUint::from(0u8),
        };

        assert!(!constraints_satisfied_on_wallets(&old_wallet, &new_wallet, transfer));
    }

    /// Top up a balance with non-zero fees -- this is valid
    #[test]
    fn test_deposit_with_nonzero_fee() {
        // Old wallet with outstanding fees
        let mut old_wallet = INITIAL_WALLET.clone();
        old_wallet.balances[0].protocol_fee_balance = 1;

        // Deposit additional balance into it
        let mut new_wallet = old_wallet.clone();
        new_wallet.balances[0].amount += 1;

        let transfer = ExternalTransfer {
            mint: old_wallet.balances[0].mint.clone(),
            amount: 1,
            direction: ExternalTransferDirection::Deposit,
            account_addr: BigUint::from(0u8),
        };

        assert!(constraints_satisfied_on_wallets(&old_wallet, &new_wallet, transfer));
    }

    // --- Mint Updates --- //

    /// Tests the case in which a zero'd balance with non-zero mint is replaced
    /// in a withdrawal
    #[test]
    fn test_replace_zero_balance() {
        let mut rng = thread_rng();

        // Setup the old wallet with a balance of zero amount and fees
        let mut old_wallet = INITIAL_WALLET.clone();
        old_wallet.balances[0] = Balance::new_from_mint(old_wallet.balances[0].mint.clone());

        // Replace that balance with a new deposit
        let new_mint = BigUint::from(rng.next_u64());
        let new_amt = 1;
        let mut new_wallet = old_wallet.clone();
        new_wallet.balances[0] = Balance::new_from_mint_and_amount(new_mint.clone(), new_amt);

        let transfer = ExternalTransfer {
            mint: new_mint,
            amount: new_amt,
            direction: ExternalTransferDirection::Deposit,
            account_addr: BigUint::from(0u8),
        };

        assert!(constraints_satisfied_on_wallets(&old_wallet, &new_wallet, transfer,));
    }

    /// Tests the case in which a zero'd balance is replaced by a zero mint
    #[test]
    fn test_replace_zero_balance_with_zero_mint() {
        let mut old_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = INITIAL_WALLET.clone();

        // Set the first balance to have zero amount and fees
        old_wallet.balances[0] = Balance::new_from_mint(BigUint::from(1u8));

        // Replace it with an entirely zero'd balance
        new_wallet.balances[0] = Balance::default();

        assert!(constraints_satisfied_on_wallets(
            &old_wallet,
            &new_wallet,
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

        new_wallet.match_fee = new_wallet.match_fee + Scalar::one();

        assert!(!constraints_satisfied_on_wallets(
            &old_wallet,
            &new_wallet,
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

        new_wallet.managing_cluster = BigUint::from(rng.next_u64());

        assert!(!constraints_satisfied_on_wallets(
            &old_wallet,
            &new_wallet,
            ExternalTransfer::default()
        ));
    }
}
