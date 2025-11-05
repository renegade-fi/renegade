//! Defines the `VALID DEPOSIT` circuit
//!
//! This circuit proves that a deposit into an _existing_ balance is valid.

use circuit_macros::circuit_type;
use circuit_types::{
    PlonkCircuit,
    balance::{BalanceShare, BalanceShareVar, DarkpoolStateBalance, DarkpoolStateBalanceVar},
    deposit::Deposit,
    merkle::{MerkleOpening, MerkleRoot},
    traits::{BaseType, CircuitBaseType, CircuitVarType},
    v2::{Commitment, Nullifier},
};
use constants::{MERKLE_HEIGHT, Scalar, ScalarField};
use mpc_plonk::errors::PlonkError;
use mpc_relation::{Variable, errors::CircuitError, traits::Circuit};
use serde::{Deserialize, Serialize};

use crate::{
    SingleProverCircuit,
    zk_gadgets::{
        bitlength::AmountGadget,
        shares::ShareGadget,
        stream_cipher::StreamCipherGadget,
        v2::state_rotation::{StateElementRotationArgs, StateElementRotationGadget},
    },
};

// ----------------------
// | Circuit Definition |
// ----------------------

/// A type alias for the `ValidDeposit` circuit with default size
/// parameters attached
pub type SizedValidDeposit = ValidDeposit<MERKLE_HEIGHT>;

/// The `VALID DEPOSIT` circuit
pub struct ValidDeposit<const MERKLE_HEIGHT: usize>;

impl<const MERKLE_HEIGHT: usize> ValidDeposit<MERKLE_HEIGHT> {
    /// Apply the circuit constraints to a given constraint system
    pub fn circuit(
        statement: &ValidDepositStatementVar,
        witness: &ValidDepositWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Validate the deposit
        Self::validate_deposit(statement, witness, cs)?;

        // Recover the implied private shares from the base type
        let old_balance_private_shares = ShareGadget::compute_complementary_shares(
            &witness.old_balance_public_shares,
            &witness.old_balance.inner,
            cs,
        )?;

        // Update the balance
        let (new_balance, new_private_share, new_public_share) =
            Self::create_new_balance(&old_balance_private_shares, statement, witness, cs)?;

        // Use the rotation gadget to verify the old balance and compute the new
        // commitment
        let mut rotation_args = StateElementRotationArgs {
            old_version: witness.old_balance.clone(),
            old_private_share: old_balance_private_shares,
            old_public_share: witness.old_balance_public_shares.clone(),
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

    /// Validate the deposit
    fn validate_deposit(
        statement: &ValidDepositStatementVar,
        witness: &ValidDepositWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let deposit = &statement.deposit;

        // 1. The deposit amount must not exceed the amount bitlength
        AmountGadget::constrain_valid_amount(deposit.amount, cs)?;

        // 2. The mint of the deposit must be the same as that of the balance
        // and the `from` of the deposit must match the owner of the balance
        cs.enforce_equal(deposit.token, witness.old_balance.inner.mint)?;
        cs.enforce_equal(deposit.from, witness.old_balance.inner.owner)?;
        Ok(())
    }

    /// Create a new balance from the deposit
    fn create_new_balance(
        old_balance_private_shares: &BalanceShareVar,
        statement: &ValidDepositStatementVar,
        witness: &ValidDepositWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(DarkpoolStateBalanceVar, BalanceShareVar, BalanceShareVar), CircuitError> {
        // Update the balance
        let mut new_balance = witness.old_balance.clone();
        let mut new_balance_private_share = old_balance_private_shares.clone();
        let mut new_balance_public_share = witness.old_balance_public_shares.clone();

        // Add the deposit amount to the balance and validate that it is not too large
        new_balance.inner.amount = cs.add(new_balance.inner.amount, statement.deposit.amount)?;
        AmountGadget::constrain_valid_amount(new_balance.inner.amount, cs)?;

        // Re-encrypt the amount field as it's changed
        // We leak the public share of this new encryption for recovery, so constrain
        // the new encryption to equal the amount share in the statement
        let (new_amount_private_share, new_amount_public_share) =
            StreamCipherGadget::encrypt::<Variable>(
                &new_balance.inner.amount,
                &mut new_balance.share_stream,
                cs,
            )?;
        new_balance_private_share.amount = new_amount_private_share;
        new_balance_public_share.amount = new_amount_public_share;
        cs.enforce_equal(new_amount_public_share, statement.new_amount_share)?;

        Ok((new_balance, new_balance_private_share, new_balance_public_share))
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for `VALID DEPOSIT`
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidDepositWitness<const MERKLE_HEIGHT: usize> {
    /// The old balance
    pub old_balance: DarkpoolStateBalance,
    /// The old public shares of the balance
    pub old_balance_public_shares: BalanceShare,
    /// The opening of the old balance to the Merkle root
    pub old_balance_opening: MerkleOpening<MERKLE_HEIGHT>,
}

/// A `VALID DEPOSIT` witness with default const generic sizing parameters
pub type SizedValidDepositWitness = ValidDepositWitness<MERKLE_HEIGHT>;

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for `VALID DEPOSIT`
#[circuit_type(singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidDepositStatement {
    /// The deposit
    pub deposit: Deposit,
    /// The Merkle root to which the old balance opens
    pub merkle_root: MerkleRoot,
    /// The nullifier of the previous balance
    pub old_balance_nullifier: Nullifier,
    /// The commitment to the new balance
    /// TODO: Decide whether this is a full or partial commitment
    pub new_balance_commitment: Commitment,
    /// The new recovery identifier of the balance
    ///
    /// This value is emitted as an event for chain indexers to track the
    /// balance's update
    pub recovery_id: Scalar,
    /// The new public share of the amount field on the balance
    ///
    /// We only leak the public shares of the updated fields in each state
    /// transition
    pub new_amount_share: Scalar,
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl<const MERKLE_HEIGHT: usize> SingleProverCircuit for ValidDeposit<MERKLE_HEIGHT> {
    type Witness = ValidDepositWitness<MERKLE_HEIGHT>;
    type Statement = ValidDepositStatement;

    fn name() -> String {
        format!("Valid Deposit ({MERKLE_HEIGHT})")
    }

    fn apply_constraints(
        witness_var: ValidDepositWitnessVar<MERKLE_HEIGHT>,
        statement_var: ValidDepositStatementVar,
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
        balance::{Balance, BalanceShare},
        deposit::Deposit,
    };
    use constants::Scalar;

    use crate::{
        test_helpers::{check_constraints_satisfied, random_address, random_amount},
        zk_circuits::valid_deposit::{SizedValidDeposit, SizedValidDepositWitness},
        zk_gadgets::test_helpers::{
            create_merkle_opening, create_random_shares, create_state_wrapper,
        },
    };

    use super::{ValidDepositStatement, ValidDepositWitness};

    /// The height of the Merkle tree to test on
    const MERKLE_HEIGHT: usize = 10;

    // -----------
    // | Helpers |
    // -----------

    /// Check that the constraints are satisfied on the given witness and
    /// statement
    pub fn check_constraints(
        witness: &SizedValidDepositWitness,
        statement: &ValidDepositStatement,
    ) -> bool {
        check_constraints_satisfied::<SizedValidDeposit>(witness, statement)
    }

    /// Construct a witness and statement with valid data
    pub fn create_dummy_witness_statement() -> (SizedValidDepositWitness, ValidDepositStatement) {
        // Create a deposit that matches the balance's mint and owner
        let deposit = create_random_deposit();
        create_dummy_witness_statement_with_deposit(deposit)
    }

    /// Create a dummy witness and statement with a given deposit
    pub fn create_dummy_witness_statement_with_deposit(
        deposit: Deposit,
    ) -> (SizedValidDepositWitness, ValidDepositStatement) {
        let old_balance = create_state_wrapper(Balance {
            mint: deposit.token,
            relayer_fee_recipient: Address::ZERO,
            owner: deposit.from,
            one_time_authority: Address::ZERO,
            relayer_fee_balance: random_amount(),
            protocol_fee_balance: random_amount(),
            amount: random_amount(),
        });

        // Create valid complementary shares for the old balance
        let (old_balance_private_shares, old_balance_public_shares) =
            create_random_shares::<BalanceShare>(&old_balance.inner);

        // Compute commitment, nullifier, and Merkle opening for the old balance
        let old_balance_commitment =
            old_balance.compute_commitment(&old_balance_private_shares, &old_balance_public_shares);
        let old_balance_nullifier = old_balance.compute_nullifier();
        let (merkle_root, old_balance_opening) =
            create_merkle_opening::<MERKLE_HEIGHT>(old_balance_commitment);

        // Create the new balance by adding the deposit amount
        let mut new_balance = old_balance.clone();
        new_balance.inner.amount += deposit.amount;

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
        let witness =
            ValidDepositWitness { old_balance, old_balance_public_shares, old_balance_opening };

        let statement = ValidDepositStatement {
            deposit,
            merkle_root,
            old_balance_nullifier,
            new_balance_commitment,
            recovery_id,
            new_amount_share: new_amount_public_share,
        };

        (witness, statement)
    }

    /// Build a random deposit
    pub fn create_random_deposit() -> Deposit {
        Deposit { from: random_address(), token: random_address(), amount: random_amount() }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        test_helpers::{random_address, random_scalar},
        zk_circuits::{
            v2::valid_deposit::test_helpers::create_dummy_witness_statement,
            valid_deposit::test_helpers::{
                create_dummy_witness_statement_with_deposit, create_random_deposit,
            },
        },
    };
    use circuit_types::{max_amount, traits::SingleProverCircuit};
    use itertools::Itertools;

    /// A helper to print the number of constraints in the circuit
    ///
    /// Useful when benchmarking the circuit
    #[test]
    fn test_n_constraints() {
        let layout = ValidDeposit::<10>::get_circuit_layout().unwrap();

        let n_gates = layout.n_gates;
        let circuit_size = layout.circuit_size();
        println!("Number of constraints: {n_gates}");
        println!("Next power of two: {circuit_size}");
    }

    /// Test that constraints are satisfied on a valid witness and statement
    #[test]
    fn test_valid_deposit_constraints() {
        let (witness, statement) = create_dummy_witness_statement();

        // Allocate in the constraint system
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let witness_var = witness.create_witness(&mut cs);
        let statement_var = statement.create_public_var(&mut cs);

        // Apply circuit constraints
        ValidDeposit::<10>::apply_constraints(witness_var, statement_var, &mut cs)
            .expect("Circuit constraints should be satisfied");

        // Verify satisfiability with public inputs
        let statement_scalars = statement.to_scalars().iter().map(|s| s.inner()).collect_vec();
        cs.check_circuit_satisfiability(&statement_scalars).expect("Circuit should be satisfiable");
    }

    // --- Deposit Validation Tests --- //

    /// Test the case in which the deposit amount is too large
    #[test]
    fn test_invalid_deposit_amount() {
        let mut deposit = create_random_deposit();
        deposit.amount = max_amount() + 1;
        let (witness, statement) = create_dummy_witness_statement_with_deposit(deposit);

        // Apply circuit constraints
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the deposit mint does not match the balance's
    /// mint
    #[test]
    fn test_invalid_deposit_mint() {
        let (witness, mut statement) = create_dummy_witness_statement();
        statement.deposit.token = random_address();

        // Apply circuit constraints
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the deposit from does not match the balance's
    /// owner
    #[test]
    fn test_invalid_deposit_from() {
        let (witness, mut statement) = create_dummy_witness_statement();
        statement.deposit.from = random_address();

        // Apply circuit constraints
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    // --- Balance Update Tests --- //

    /// Test the case in which the deposit overflows the balance's amount
    #[test]
    fn test_invalid_deposit_overflow() {
        let mut deposit = create_random_deposit();
        deposit.amount = max_amount() - 1; // Valid amount, but will overflow
        let (witness, statement) = create_dummy_witness_statement_with_deposit(deposit);

        // Apply circuit constraints
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the new amount share is not correctly encrypted
    #[test]
    fn test_invalid_new_amount_share() {
        let (witness, mut statement) = create_dummy_witness_statement();
        statement.new_amount_share = random_scalar();

        // Apply circuit constraints
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    // --- State Rotation Tests --- //
    // Most of these tests are covered by the state rotation gadgets in
    // the `StateElementRotationGadget` test suite

    /// Test the case in which the old balance's public shares are invalid
    #[test]
    fn test_invalid_old_balance_public_shares() {
        let (mut witness, statement) = create_dummy_witness_statement();
        witness.old_balance_public_shares.amount = random_scalar();

        // Apply circuit constraints
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the new balance's commitment is modified
    #[test]
    fn test_invalid_new_balance_commitment() {
        let (witness, mut statement) = create_dummy_witness_statement();
        statement.new_balance_commitment = random_scalar();

        // Apply circuit constraints
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }
}
