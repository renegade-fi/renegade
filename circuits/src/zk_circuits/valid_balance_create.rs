//! Defines the `VALID BALANCE CREATE` circuit
//!
//! This circuit proves that a given commitment represents a newly initialized
//! balance. This balance may be zero'd out or reflect a deposit in the same
//! transaction.

use circuit_macros::circuit_type;
use circuit_types::{
    Commitment, PlonkCircuit,
    balance::{Balance, BalanceShare, BalanceShareVar, BalanceVar, DarkpoolStateBalanceVar},
    csprng::PoseidonCSPRNG,
    deposit::{Deposit, DepositVar},
    traits::{BaseType, CircuitBaseType, CircuitVarType},
};
use constants::{Scalar, ScalarField};
use mpc_plonk::errors::PlonkError;
use mpc_relation::{Variable, errors::CircuitError, traits::Circuit};
use serde::{Deserialize, Serialize};

use crate::{
    SingleProverCircuit,
    zk_gadgets::{
        StreamCipherGadget,
        comparators::EqGadget,
        primitives::bitlength::AmountGadget,
        state_primitives::{CommitmentGadget, RecoveryIdGadget},
    },
};

// ----------------------
// | Circuit Definition |
// ----------------------

/// The `VALID BALANCE CREATE` circuit
pub struct ValidBalanceCreate;

impl ValidBalanceCreate {
    /// Apply the circuit constraints to a given constraint system
    pub fn circuit(
        statement: &ValidBalanceCreateStatementVar,
        witness: &mut ValidBalanceCreateWitnessVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // 1. Validate the deposit and the new balance
        Self::validate_deposit(statement, witness, cs)?;
        Self::validate_new_balance(&witness.balance, &statement.deposit, cs)?;

        // 2. Encrypt the new balance using the state element's allocated stream cipher
        let (mut new_balance, private_share) =
            Self::verify_balance_encryption(witness, statement, cs)?;

        // 3. Compute the recovery identifier for the new balance
        let recovery_id = RecoveryIdGadget::compute_recovery_id(&mut new_balance, cs)?;
        EqGadget::constrain_eq(&recovery_id, &statement.recovery_id, cs)?;

        // 4. Compute the commitment to the new balance
        // This must be done after encrypting and computing the recovery identifier so
        // that we commit to the updated stream states for the CSPRNGs
        let commitment = CommitmentGadget::compute_commitment(&new_balance, &private_share, cs)?;
        EqGadget::constrain_eq(&commitment, &statement.balance_commitment, cs)?;

        Ok(())
    }

    /// Validate the deposit
    fn validate_deposit(
        statement: &ValidBalanceCreateStatementVar,
        witness: &ValidBalanceCreateWitnessVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let deposit = &statement.deposit;
        let balance = &witness.balance;

        // 1. The deposit amount must not exceed the amount bitlength
        AmountGadget::constrain_valid_amount(deposit.amount, cs)?;

        // 2. The mint of the deposit must be the same as that of the balance
        // and the `from` of the deposit must match the owner of the balance
        EqGadget::constrain_eq(&deposit.token, &balance.mint, cs)?;
        EqGadget::constrain_eq(&deposit.from, &balance.owner, cs)?;
        Ok(())
    }

    /// Validate the new balance
    fn validate_new_balance(
        balance: &BalanceVar,
        deposit: &DepositVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let zero = cs.zero();

        // 1. The balance amount should equal the deposit amount for new balances
        EqGadget::constrain_eq(&balance.amount, &deposit.amount, cs)?;

        // 2. The balance fees should be zero for new balances
        EqGadget::constrain_eq(&balance.relayer_fee_balance, &zero, cs)?;
        EqGadget::constrain_eq(&balance.protocol_fee_balance, &zero, cs)?;
        Ok(())
    }

    /// Encrypt the new balance and verify that it matches the statement
    ///
    /// Creates a `DarkpoolStateBalanceVar` from the witness balance and returns
    /// it along with the private share of the balance
    fn verify_balance_encryption(
        witness: &mut ValidBalanceCreateWitnessVar,
        statement: &ValidBalanceCreateStatementVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(DarkpoolStateBalanceVar, BalanceShareVar), CircuitError> {
        // 1. Encrypt the balance with the stream cipher
        let balance = &witness.balance;
        let (private_share, public_share) =
            StreamCipherGadget::encrypt(balance, &mut witness.initial_share_stream, cs)?;

        // 2. Verify that the encrypted balance matches the statement
        EqGadget::constrain_eq(&public_share, &statement.new_balance_share, cs)?;

        // 3. Create the balance state element
        // The share stream has been mutated by the stream cipher gadget as expected, so
        // this balance contains the updated share stream state
        let balance = DarkpoolStateBalanceVar {
            recovery_stream: witness.initial_recovery_stream.clone(),
            share_stream: witness.initial_share_stream.clone(),
            inner: balance.clone(),
            public_share,
        };
        Ok((balance, private_share))
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for `VALID BALANCE CREATE`
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidBalanceCreateWitness {
    /// The initial balance share CSPRNG
    pub initial_share_stream: PoseidonCSPRNG,
    /// The initial recovery identifier CSPRNG
    pub initial_recovery_stream: PoseidonCSPRNG,
    /// The balance being created
    pub balance: Balance,
}

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for `VALID BALANCE CREATE`
#[circuit_type(singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidBalanceCreateStatement {
    /// The deposit which initializes the balance
    ///
    /// This may be zero'd out to reflect a zero'd out new balance
    pub deposit: Deposit,
    /// A commitment to the new balance
    pub balance_commitment: Commitment,
    /// The recovery identifier of the balance
    pub recovery_id: Scalar,
    /// The encrypted balance; i.e. the public shares of the balance
    pub new_balance_share: BalanceShare,
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl SingleProverCircuit for ValidBalanceCreate {
    type Witness = ValidBalanceCreateWitness;
    type Statement = ValidBalanceCreateStatement;

    fn name() -> String {
        "Valid Balance Create".to_string()
    }

    fn apply_constraints(
        mut witness_var: ValidBalanceCreateWitnessVar,
        statement_var: ValidBalanceCreateStatementVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), PlonkError> {
        Self::circuit(&statement_var, &mut witness_var, cs).map_err(PlonkError::CircuitError)
    }
}

// ---------
// | Tests |
// ---------

#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    use circuit_types::{balance::Balance, deposit::Deposit};

    use crate::{
        test_helpers::{
            check_constraints_satisfied, create_random_state_wrapper, random_address,
            random_deposit,
        },
        zk_circuits::valid_balance_create::{
            ValidBalanceCreate, ValidBalanceCreateStatement, ValidBalanceCreateWitness,
        },
    };

    // -----------
    // | Helpers |
    // -----------

    /// Check that the constraints are satisfied on the given witness and
    /// statement
    pub fn check_constraints(
        witness: &ValidBalanceCreateWitness,
        statement: &ValidBalanceCreateStatement,
    ) -> bool {
        check_constraints_satisfied::<ValidBalanceCreate>(witness, statement)
    }

    /// Construct a witness and statement with valid data
    pub fn create_witness_statement() -> (ValidBalanceCreateWitness, ValidBalanceCreateStatement) {
        // Create a deposit that matches the balance's mint and owner
        let deposit = random_deposit();
        create_witness_statement_with_deposit(deposit)
    }

    /// Create a dummy witness and statement with a given deposit
    pub fn create_witness_statement_with_deposit(
        deposit: Deposit,
    ) -> (ValidBalanceCreateWitness, ValidBalanceCreateStatement) {
        // Create a new balance matching the deposit
        let balance_inner = Balance {
            mint: deposit.token,
            owner: deposit.from,
            relayer_fee_recipient: random_address(),
            one_time_authority: random_address(),
            relayer_fee_balance: 0,
            protocol_fee_balance: 0,
            amount: deposit.amount,
        };

        create_witness_statement_with_deposit_and_balance(deposit, &balance_inner)
    }

    /// Create a witness and statement with the given deposit and balance
    pub fn create_witness_statement_with_deposit_and_balance(
        deposit: Deposit,
        balance_inner: &Balance,
    ) -> (ValidBalanceCreateWitness, ValidBalanceCreateStatement) {
        // Create the witness balance with initial stream states
        let balance = create_random_state_wrapper(balance_inner.clone());
        let mut new_balance = balance.clone();

        // Encrypt the entire balance using the stream cipher
        let balance_public_shares = new_balance.stream_cipher_encrypt::<Balance>(balance_inner);
        new_balance.public_share = balance_public_shares;
        let recovery_id = new_balance.compute_recovery_id();

        // Compute commitment to the balance
        let balance_commitment = new_balance.compute_commitment();

        // Build the witness and statement using the pre-update balance
        let new_balance_share = new_balance.public_share();
        let witness = ValidBalanceCreateWitness {
            initial_share_stream: balance.share_stream,
            initial_recovery_stream: balance.recovery_stream,
            balance: balance.inner,
        };

        let statement = ValidBalanceCreateStatement {
            deposit,
            balance_commitment,
            recovery_id,
            new_balance_share,
        };

        (witness, statement)
    }
}

#[cfg(test)]
mod test {
    use crate::test_helpers::{random_address, random_amount, random_deposit, random_scalar};

    use super::*;
    use circuit_types::{balance::Balance, traits::SingleProverCircuit};
    use rand::{Rng, thread_rng};

    /// A helper to print the number of constraints in the circuit
    ///
    /// Useful when benchmarking the circuit
    #[test]
    fn test_n_constraints() {
        let layout = ValidBalanceCreate::get_circuit_layout().unwrap();

        let n_gates = layout.n_gates;
        let circuit_size = layout.circuit_size();
        println!("Number of constraints: {n_gates}");
        println!("Next power of two: {circuit_size}");
    }

    /// Test that constraints are satisfied on a valid witness and statement
    #[test]
    fn test_valid_balance_create_constraints() {
        let (witness, statement) = test_helpers::create_witness_statement();
        assert!(test_helpers::check_constraints(&witness, &statement));
    }

    /// Test a valid balance creation with a zero'd out deposit
    #[test]
    fn test_valid_balance_create_with_zeroed_out_deposit() {
        let mut deposit = random_deposit();
        deposit.amount = 0;
        let (witness, statement) = test_helpers::create_witness_statement_with_deposit(deposit);
        assert!(test_helpers::check_constraints(&witness, &statement));
    }

    // --- Balance Validation Tests --- //

    /// Test the case in which the balance amount is not equal to the deposit
    /// amount
    #[test]
    fn test_invalid_balance_amount() {
        let (witness, mut statement) = test_helpers::create_witness_statement();
        statement.deposit.amount = random_amount();
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which a balance fee is non-zero
    #[test]
    fn test_invalid_balance_fees() {
        let mut rng = thread_rng();
        let deposit = random_deposit();
        let mut balance = Balance {
            mint: deposit.token,
            owner: deposit.from,
            relayer_fee_recipient: random_address(),
            one_time_authority: random_address(),
            relayer_fee_balance: 0,
            protocol_fee_balance: 0,
            amount: deposit.amount,
        };

        // Modify one of the fees
        if rng.gen_bool(0.5) {
            balance.relayer_fee_balance = random_amount();
        } else {
            balance.protocol_fee_balance = random_amount();
        }

        // Verify that the constraints are not satisfied
        let (witness, statement) =
            test_helpers::create_witness_statement_with_deposit_and_balance(deposit, &balance);
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the balance owner is not the same as the deposit
    /// from field
    #[test]
    fn test_invalid_balance_owner() {
        let (witness, mut statement) = test_helpers::create_witness_statement();
        statement.deposit.from = random_address();
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the balance mint is not the same as the deposit
    /// token
    #[test]
    fn test_invalid_balance_mint() {
        let (witness, mut statement) = test_helpers::create_witness_statement();
        statement.deposit.token = random_address();
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    // --- Encryption Validation Tests --- //

    /// Test the case in which the new balance share is not correctly encrypted
    #[test]
    fn test_invalid_new_balance_share() {
        let mut rng = thread_rng();
        let (witness, mut statement) = test_helpers::create_witness_statement();

        // Modify a share in the new balance public shares
        let mut shares = statement.new_balance_share.to_scalars();
        let random_index = rng.gen_range(0..shares.len());
        shares[random_index] = random_scalar();
        statement.new_balance_share = BalanceShare::from_scalars(&mut shares.into_iter());
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    // --- State Rotation Tests --- //

    /// Test the case in which the recovery ID is computed incorrectly
    #[test]
    fn test_invalid_recovery_id() {
        let (witness, mut statement) = test_helpers::create_witness_statement();
        statement.recovery_id = random_scalar();
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the balance commitment is computed incorrectly
    #[test]
    fn test_invalid_balance_commitment() {
        let (witness, mut statement) = test_helpers::create_witness_statement();
        statement.balance_commitment = random_scalar();
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }
}
