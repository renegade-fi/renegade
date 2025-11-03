//! Defines the `VALID BALANCE CREATE` circuit
//!
//! This circuit proves that a given commitment represents a newly initialized
//! balance. This balance may be zero'd out or reflect a deposit in the same
//! transaction.

use circuit_macros::circuit_type;
use circuit_types::{
    Commitment, PlonkCircuit,
    balance::{BalanceShare, BalanceShareVar, BalanceVar, DarkpoolStateBalance},
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
        bitlength::AmountGadget, comparators::EqGadget, state_elements::StateElementGadget,
        stream_cipher::StreamCipherGadget,
    },
};

// ----------------------
// | Circuit Definition |
// ----------------------

/// A type alias for the `ValidBalanceCreate` circuit with default size
/// parameters attached
pub type SizedValidBalanceCreate = ValidBalanceCreate;

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
        Self::validate_new_balance(&witness.balance.inner, &statement.deposit, cs)?;

        // 2. Encrypt the new balance using the state element's allocated stream cipher
        let (private_share, public_share) =
            Self::verify_balance_encryption(witness, statement, cs)?;

        // 3. Compute the recovery identifier for the new balance
        let recovery_id = StateElementGadget::compute_recovery_id(&mut witness.balance, cs)?;
        EqGadget::constrain_eq(&recovery_id, &statement.recovery_id, cs)?;

        // 4. Compute the commitment to the new balance
        // This must be done after encrypting and computing the recovery identifier so
        // that we commit to the updated stream states for the CSPRNGs
        let commitment = StateElementGadget::compute_commitment(
            &private_share,
            &public_share,
            &witness.balance,
            cs,
        )?;
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
        let balance = &witness.balance.inner;

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
    /// Returns the public and private shares of the balance
    fn verify_balance_encryption(
        witness: &mut ValidBalanceCreateWitnessVar,
        statement: &ValidBalanceCreateStatementVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(BalanceShareVar, BalanceShareVar), CircuitError> {
        // 1. Encrypt the balance with the stream cipher
        let balance = &mut witness.balance;
        let (private_share, public_share) =
            StreamCipherGadget::encrypt(&balance.inner, &mut balance.share_stream, cs)?;

        // 2. Verify that the encrypted balance matches the statement
        EqGadget::constrain_eq(&public_share, &statement.new_balance_share, cs)?;
        Ok((private_share, public_share))
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for `VALID BALANCE CREATE`
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidBalanceCreateWitness {
    /// The balance being created
    pub balance: DarkpoolStateBalance,
}

/// A `VALID BALANCE CREATE` witness with default const generic sizing
/// parameters
pub type SizedValidBalanceCreateWitness = ValidBalanceCreateWitness;

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

/// A `VALID BALANCE CREATE` statement with default const generic sizing
/// parameters
pub type SizedValidBalanceCreateStatement = ValidBalanceCreateStatement;

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
