//! Defines the `VALID WITHDRAWAL` circuit
//!
//! This circuit proves an update to a committed balance which withdraws funds
//! from the balance.

use circuit_macros::circuit_type;
use circuit_types::balance::{
    BalanceShare, BalanceShareVar, BalanceVar, DarkpoolStateBalance, DarkpoolStateBalanceVar,
};
use circuit_types::merkle::{MerkleOpening, MerkleRoot};
use circuit_types::traits::{BaseType, CircuitBaseType, CircuitVarType};
use circuit_types::withdrawal::Withdrawal;
use circuit_types::{AMOUNT_BITS, Commitment, Nullifier, PlonkCircuit};
use constants::{MERKLE_HEIGHT, Scalar, ScalarField};
use mpc_plonk::errors::PlonkError;
use mpc_relation::{Variable, errors::CircuitError, traits::Circuit};
use serde::{Deserialize, Serialize};

use crate::SingleProverCircuit;
use crate::zk_gadgets::bitlength::AmountGadget;
use crate::zk_gadgets::comparators::{EqGadget, EqZeroGadget, GreaterThanEqGadget};
use crate::zk_gadgets::shares::ShareGadget;
use crate::zk_gadgets::stream_cipher::StreamCipherGadget;
use crate::zk_gadgets::v2::state_rotation::{StateElementRotationArgs, StateElementRotationGadget};

// ----------------------
// | Circuit Definition |
// ----------------------

/// A type alias for the `ValidWithdrawal` circuit with default size
/// parameters attached
pub type SizedValidWithdrawal = ValidWithdrawal<MERKLE_HEIGHT>;

/// The `VALID WITHDRAWAL` circuit
pub struct ValidWithdrawal<const MERKLE_HEIGHT: usize>;

impl<const MERKLE_HEIGHT: usize> ValidWithdrawal<MERKLE_HEIGHT> {
    /// Apply the circuit constraints to a given constraint system
    pub fn circuit(
        statement: &ValidWithdrawalStatementVar,
        witness: &ValidWithdrawalWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // 1. Validate the withdrawal
        Self::validate_withdrawal(statement, witness, cs)?;

        // 2. Verify that the balance has no outstanding fees
        Self::verify_no_outstanding_fees(&witness.old_balance.inner, cs)?;

        // 3. Build and verify the new balance
        // Recover the old balance public shares
        let old_public = &witness.old_balance_public_shares;
        let old_private =
            ShareGadget::compute_complementary_shares(old_public, &witness.old_balance.inner, cs)?;
        let (new_balance, new_private_share, new_public_share) =
            Self::build_and_verify_new_balance(&old_private, statement, witness, cs)?;

        // 3. Verify wallet rotation
        let mut rotation_args = StateElementRotationArgs {
            old_version: witness.old_balance.clone(),
            old_private_share: old_private,
            old_public_share: old_public.clone(),
            old_opening: witness.old_balance_opening.clone(),
            merkle_root: statement.merkle_root,
            nullifier: statement.old_balance_nullifier,
            new_version: new_balance,
            new_private_share,
            new_public_share,
            new_commitment: statement.new_balance_commitment,
            recovery_id: statement.recovery_id,
        };
        StateElementRotationGadget::rotate_version(&mut rotation_args, cs)?;

        Ok(())
    }

    /// Validate the withdrawal
    pub(crate) fn validate_withdrawal(
        statement: &ValidWithdrawalStatementVar,
        witness: &ValidWithdrawalWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let withdrawal = &statement.withdrawal;
        let old_balance = &witness.old_balance.inner;

        // 1. Verify the withdrawal amount is valid
        AmountGadget::constrain_valid_amount(withdrawal.amount, cs)?;
        let eq_zero = EqZeroGadget::eq_zero(&withdrawal.amount, cs)?;
        cs.enforce_false(eq_zero)?;

        // 2. The token must match the balance mint, and the withdrawal address must
        //    match the balance owner
        EqGadget::constrain_eq(&withdrawal.token, &witness.old_balance.inner.mint, cs)?;
        EqGadget::constrain_eq(&withdrawal.to, &witness.old_balance.inner.owner, cs)?;

        // 3. The withdrawal amount must be less than or equal to the balance amount
        GreaterThanEqGadget::constrain_greater_than_eq(
            old_balance.amount,
            withdrawal.amount,
            AMOUNT_BITS,
            cs,
        )
    }

    /// Verify that the balance has no outstanding fees
    ///
    /// We require that all fees be paid before a withdrawal is executed
    fn verify_no_outstanding_fees(
        old_balance: &BalanceVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let zero = cs.zero();
        EqGadget::constrain_eq(&old_balance.relayer_fee_balance, &zero, cs)?;
        EqGadget::constrain_eq(&old_balance.protocol_fee_balance, &zero, cs)
    }

    /// Build and verify the new balance
    ///
    /// Returns the new balance, private shares, and public shares
    fn build_and_verify_new_balance(
        old_balance_private_shares: &BalanceShareVar,
        statement: &ValidWithdrawalStatementVar,
        witness: &ValidWithdrawalWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(DarkpoolStateBalanceVar, BalanceShareVar, BalanceShareVar), CircuitError> {
        let old_balance = &witness.old_balance;
        let mut new_balance = old_balance.clone();

        // Apply the withdrawal to the amount in the balance
        let mut new_balance_private_shares = old_balance_private_shares.clone();
        let mut new_balance_public_shares = witness.old_balance_public_shares.clone();
        new_balance.inner.amount = cs.sub(old_balance.inner.amount, statement.withdrawal.amount)?;

        // Re-encrypt the amount field as it's changed
        let (new_amount_private_share, new_amount_public_share) =
            StreamCipherGadget::encrypt::<Variable>(
                &new_balance.inner.amount,
                &mut new_balance.share_stream,
                cs,
            )?;
        new_balance_private_shares.amount = new_amount_private_share;
        new_balance_public_shares.amount = new_amount_public_share;
        EqGadget::constrain_eq(&new_amount_public_share, &statement.new_amount_share, cs)?;

        Ok((new_balance, new_balance_private_shares, new_balance_public_shares))
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for `VALID WITHDRAWAL`
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidWithdrawalWitness<const MERKLE_HEIGHT: usize> {
    /// The old balance
    pub old_balance: DarkpoolStateBalance,
    /// The old public shares of the balance
    pub old_balance_public_shares: BalanceShare,
    /// The opening of the old balance to the Merkle root
    pub old_balance_opening: MerkleOpening<MERKLE_HEIGHT>,
}

/// A `VALID WITHDRAWAL` witness with default const generic sizing parameters
pub type SizedValidWithdrawalWitness = ValidWithdrawalWitness<MERKLE_HEIGHT>;

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for `VALID WITHDRAWAL`
#[circuit_type(singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidWithdrawalStatement {
    /// The withdrawal
    pub withdrawal: Withdrawal,
    /// The Merkle root to which the balance opens
    pub merkle_root: MerkleRoot,
    /// The nullifier of the previous balance
    pub old_balance_nullifier: Nullifier,
    /// The commitment to the new balance
    pub new_balance_commitment: Commitment,
    /// The new recovery identifier of the balance
    pub recovery_id: Scalar,
    /// The new encrypted amount (public share) of the balance
    pub new_amount_share: Scalar,
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl<const MERKLE_HEIGHT: usize> SingleProverCircuit for ValidWithdrawal<MERKLE_HEIGHT> {
    type Witness = ValidWithdrawalWitness<MERKLE_HEIGHT>;
    type Statement = ValidWithdrawalStatement;

    fn name() -> String {
        format!("Valid Withdrawal ({MERKLE_HEIGHT})")
    }

    fn apply_constraints(
        witness_var: ValidWithdrawalWitnessVar<MERKLE_HEIGHT>,
        statement_var: ValidWithdrawalStatementVar,
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
        balance::{Balance, BalanceShare, DarkpoolStateBalance},
        withdrawal::Withdrawal,
    };
    use constants::Scalar;

    use crate::{
        test_helpers::{check_constraints_satisfied, random_address, random_amount},
        zk_circuits::v2::valid_withdrawal::{SizedValidWithdrawal, SizedValidWithdrawalWitness},
        zk_gadgets::test_helpers::{
            create_merkle_opening, create_random_shares, create_state_wrapper,
        },
    };

    use super::{ValidWithdrawalStatement, ValidWithdrawalWitness};

    /// The height of the Merkle tree to test on
    const MERKLE_HEIGHT: usize = 10;

    // -----------
    // | Helpers |
    // -----------

    /// Check that the constraints are satisfied on the given witness and
    /// statement
    pub fn check_constraints(
        witness: &SizedValidWithdrawalWitness,
        statement: &ValidWithdrawalStatement,
    ) -> bool {
        check_constraints_satisfied::<SizedValidWithdrawal>(witness, statement)
    }

    /// Construct a witness and statement with valid data
    pub fn create_witness_statement() -> (SizedValidWithdrawalWitness, ValidWithdrawalStatement) {
        // Create a withdrawal that matches the balance's mint and owner
        let withdrawal = create_random_withdrawal();
        create_witness_statement_with_withdrawal(withdrawal)
    }

    /// Create a witness and statement with a given withdrawal
    pub fn create_witness_statement_with_withdrawal(
        withdrawal: Withdrawal,
    ) -> (SizedValidWithdrawalWitness, ValidWithdrawalStatement) {
        // Create an old balance matching the withdrawal's token and owner
        // Ensure the balance amount is at least as large as the withdrawal amount
        let old_balance = create_state_wrapper(Balance {
            mint: withdrawal.token,
            owner: withdrawal.to,
            fee_recipient: random_address(),
            one_time_authority: random_address(),
            relayer_fee_balance: 0,
            protocol_fee_balance: 0,
            amount: withdrawal.amount + random_amount(), // Ensure balance >= withdrawal
        });

        create_witness_statement_with_withdrawal_and_balance(withdrawal, &old_balance)
    }

    /// Create a witness and statement with the given withdrawal and balance
    pub fn create_witness_statement_with_withdrawal_and_balance(
        withdrawal: Withdrawal,
        old_balance: &DarkpoolStateBalance,
    ) -> (SizedValidWithdrawalWitness, ValidWithdrawalStatement) {
        // Create valid complementary shares for the old balance
        let (old_balance_private_shares, old_balance_public_shares) =
            create_random_shares::<BalanceShare>(&old_balance.inner);

        // Compute commitment, nullifier, and Merkle opening for the old balance
        let old_balance_commitment =
            old_balance.compute_commitment(&old_balance_private_shares, &old_balance_public_shares);
        let old_balance_nullifier = old_balance.compute_nullifier();
        let (merkle_root, old_balance_opening) =
            create_merkle_opening::<MERKLE_HEIGHT>(old_balance_commitment);

        // Create the new balance by subtracting the withdrawal amount
        let mut new_balance = old_balance.clone();
        new_balance.inner.amount -= withdrawal.amount;

        // To compute the new amount share, we need to simulate the stream cipher
        // encryption.
        let new_amount_scalar = Scalar::from(new_balance.inner.amount);
        let (new_amount_private_share, new_amount_public_share) =
            new_balance.stream_cipher_encrypt(&new_amount_scalar);

        // Compute a commitment to the new balance
        let mut new_private_shares = old_balance_private_shares.clone();
        let mut new_public_shares = old_balance_public_shares.clone();
        new_public_shares.amount = new_amount_public_share;
        new_private_shares.amount = new_amount_private_share;

        // Compute recovery_id, which will advance the recovery stream
        let recovery_id = new_balance.compute_recovery_id();
        let new_balance_commitment =
            new_balance.compute_commitment(&new_private_shares, &new_public_shares);

        // Build the witness and statement
        let witness = ValidWithdrawalWitness {
            old_balance: old_balance.clone(),
            old_balance_public_shares,
            old_balance_opening,
        };

        let statement = ValidWithdrawalStatement {
            withdrawal,
            merkle_root,
            old_balance_nullifier,
            new_balance_commitment,
            recovery_id,
            new_amount_share: new_amount_public_share,
        };
        (witness, statement)
    }

    /// Build a random withdrawal
    pub fn create_random_withdrawal() -> Withdrawal {
        Withdrawal { to: random_address(), token: random_address(), amount: random_amount() }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        test_helpers::{random_address, random_amount, random_scalar},
        zk_gadgets::test_helpers::create_state_wrapper,
    };

    use super::*;
    use circuit_types::{balance::Balance, max_amount, traits::SingleProverCircuit};
    use constants::MERKLE_HEIGHT;
    use itertools::Itertools;
    use rand::{Rng, thread_rng};

    /// A helper to print the number of constraints in the circuit
    ///
    /// Useful when benchmarking the circuit
    #[test]
    fn test_n_constraints() {
        let layout = ValidWithdrawal::<10>::get_circuit_layout().unwrap();

        let n_gates = layout.n_gates;
        let circuit_size = layout.circuit_size();
        println!("Number of constraints: {n_gates}");
        println!("Next power of two: {circuit_size}");
    }

    /// Test that constraints are satisfied on a valid witness and statement
    #[test]
    fn test_valid_withdrawal_constraints() {
        let (witness, statement) = test_helpers::create_witness_statement();
        assert!(test_helpers::check_constraints(&witness, &statement));
    }

    /// Test that a full withdrawal (where withdrawal amount equals balance
    /// amount) is valid
    #[test]
    fn test_valid_full_withdrawal() {
        // Create a balance with the exact withdrawal amount
        let withdrawal = test_helpers::create_random_withdrawal();
        let balance = create_state_wrapper(Balance {
            mint: withdrawal.token,
            owner: withdrawal.to,
            fee_recipient: random_address(),
            one_time_authority: random_address(),
            relayer_fee_balance: 0,
            protocol_fee_balance: 0,
            amount: withdrawal.amount,
        });

        let (witness, statement) =
            test_helpers::create_witness_statement_with_withdrawal_and_balance(
                withdrawal, &balance,
            );
        assert!(test_helpers::check_constraints(&witness, &statement));
    }

    // --- Withdrawal Validation Tests --- //

    /// Test the case in which the withdrawal amount is zero
    #[test]
    fn test_invalid_withdrawal_amount() {
        let mut withdrawal = test_helpers::create_random_withdrawal();
        withdrawal.amount = 0;
        let (witness, statement) =
            test_helpers::create_witness_statement_with_withdrawal(withdrawal);

        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the withdrawal amount exceeds the maximum allowed
    /// amount
    #[test]
    fn test_invalid_withdrawal_amount_too_large() {
        let mut withdrawal = test_helpers::create_random_withdrawal();
        withdrawal.amount = max_amount() + 1;
        let (witness, statement) =
            test_helpers::create_witness_statement_with_withdrawal(withdrawal);

        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the withdrawal exceeds the balance amount
    #[test]
    fn test_invalid_withdrawal_exceeds_balance() {
        let (witness, mut statement) = test_helpers::create_witness_statement();
        statement.withdrawal.amount = witness.old_balance.inner.amount + 1;

        // Apply only the withdrawal validation constraints to isolate the failure
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let witness_var = witness.create_witness(&mut cs);
        let statement_var = statement.create_public_var(&mut cs);
        ValidWithdrawal::<MERKLE_HEIGHT>::validate_withdrawal(
            &statement_var,
            &witness_var,
            &mut cs,
        )
        .unwrap();

        let statement_scalars = statement.to_scalars().iter().map(|s| s.inner()).collect_vec();
        let satisfied = cs.check_circuit_satisfiability(&statement_scalars).is_ok();
        assert!(!satisfied);
    }

    /// Test the case in which the withdrawal token does not match the balance
    /// mint
    #[test]
    fn test_invalid_withdrawal_token_mismatch() {
        let (witness, mut statement) = test_helpers::create_witness_statement();
        statement.withdrawal.token = random_address();
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the withdrawal to does not match the balance
    /// owner
    #[test]
    fn test_invalid_withdrawal_to_mismatch() {
        let (witness, mut statement) = test_helpers::create_witness_statement();
        statement.withdrawal.to = random_address();
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    // --- Outstanding Fees Tests --- //

    /// Test the case in which the balance has outstanding fees
    #[test]
    fn test_invalid_withdrawal_outstanding_fees() {
        let mut rng = thread_rng();
        let withdrawal = test_helpers::create_random_withdrawal();
        let mut balance = create_state_wrapper(Balance {
            mint: withdrawal.token,
            owner: withdrawal.to,
            fee_recipient: random_address(),
            one_time_authority: random_address(),
            relayer_fee_balance: 0,
            protocol_fee_balance: 0,
            amount: withdrawal.amount,
        });

        // Randomly set one of the fees to a non-zero value
        if rng.gen_bool(0.5) {
            balance.inner.relayer_fee_balance = random_amount();
        } else {
            balance.inner.protocol_fee_balance = random_amount();
        }

        // Generate a witness and statement with the modified balance
        let (witness, statement) =
            test_helpers::create_witness_statement_with_withdrawal_and_balance(
                withdrawal, &balance,
            );
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    // --- State Rotation Tests --- //
    // The majority of these tests are covered by the state rotation gadgets in
    // the `StateElementRotationGadget` test suite

    /// Test an invalid encryption of the amount field on the new balance
    #[test]
    fn test_invalid_new_balance_amount_encryption() {
        let (witness, mut statement) = test_helpers::create_witness_statement();
        statement.new_amount_share = random_scalar();
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }
}
