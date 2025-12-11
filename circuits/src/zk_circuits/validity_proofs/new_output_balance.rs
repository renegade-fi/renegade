//! Helpers for proving and validating proofs of NEW OUTPUT BALANCE VALIDITY
//!
//! This circuit proves the construction of a new balance to receive the output
//! of a match into.

use circuit_macros::circuit_type;
use circuit_types::{
    Commitment, PlonkCircuit,
    balance::{
        Balance, BalanceShareVar, BalanceVar, DarkpoolStateBalanceVar, PostMatchBalanceShare,
    },
    csprng::PoseidonCSPRNG,
    state_wrapper::PartialCommitment,
    traits::{BaseType, CircuitBaseType, CircuitVarType},
};
use constants::{Scalar, ScalarField};
use mpc_plonk::errors::PlonkError;
use mpc_relation::{
    Variable,
    errors::CircuitError,
    proof_linking::{GroupLayout, LinkableCircuit},
    traits::Circuit,
};
use serde::{Deserialize, Serialize};

use crate::{
    SingleProverCircuit,
    zk_circuits::settlement::{
        OUTPUT_BALANCE_SETTLEMENT_PARTY0_LINK, OUTPUT_BALANCE_SETTLEMENT_PARTY1_LINK,
        intent_and_balance_private_settlement::IntentAndBalancePrivateSettlementCircuit,
    },
    zk_gadgets::{
        comparators::EqGadget,
        shares::ShareGadget,
        state_primitives::{CommitmentGadget, RecoveryIdGadget},
        stream_cipher::StreamCipherGadget,
    },
};

/// The number of public shares to include in the partial commitment to the
/// updated balance
///
/// This is the set of shares that will not change after the match.
const NEW_BALANCE_PARTIAL_COMMITMENT_SIZE: usize =
    Balance::NUM_SCALARS - PostMatchBalanceShare::NUM_SCALARS;

// ----------------------
// | Circuit Definition |
// ----------------------

/// The `NEW OUTPUT BALANCE VALIDITY` circuit
pub struct NewOutputBalanceValidityCircuit;

impl NewOutputBalanceValidityCircuit {
    /// Apply the circuit constraints to a given constraint system
    pub fn circuit(
        statement: &NewOutputBalanceValidityStatementVar,
        witness: &mut NewOutputBalanceValidityWitnessVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // 1. Validate the newly created balance's fields
        Self::validate_new_balance(&witness.balance, cs)?;

        // 2. Build the state wrapper for the balance
        let (mut balance, private_shares) = Self::build_balance_state(witness, cs)?;

        // 3. Compute a commitment to the original balance
        let original_balance_commitment =
            CommitmentGadget::compute_commitment(&balance, &private_shares, cs)?;
        // TODO: Check signature here

        // 4. Compute the recovery identifier for the new balance
        let recovery_id = RecoveryIdGadget::compute_recovery_id(&mut balance, cs)?;
        EqGadget::constrain_eq(&recovery_id, &statement.recovery_id, cs)?;

        // 5. Compute a partial commitment to the updated balance
        // This is done after computing the recovery identifier so that we commit to the
        // progressed recovery stream state
        let new_balance_partial_commitment = CommitmentGadget::compute_partial_commitment(
            NEW_BALANCE_PARTIAL_COMMITMENT_SIZE,
            &private_shares,
            &balance,
            cs,
        )?;
        EqGadget::constrain_eq(
            &new_balance_partial_commitment,
            &statement.new_balance_partial_commitment,
            cs,
        )?;

        Ok(())
    }

    /// Build the balance state wrapper
    ///
    /// Returns the state element and the private shares
    fn build_balance_state(
        witness: &mut NewOutputBalanceValidityWitnessVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(DarkpoolStateBalanceVar, BalanceShareVar), CircuitError> {
        let balance = &witness.balance;
        let share_stream = &mut witness.initial_share_stream;
        let recovery_stream = &mut witness.initial_recovery_stream;

        // Sample public and private shares for the balance
        let (private_shares, public_share) =
            StreamCipherGadget::encrypt(balance, share_stream, cs)?;

        // Build the post-match balance shares
        let post_match_balance_shares = ShareGadget::build_post_match_balance_share(&public_share);
        EqGadget::constrain_eq(&post_match_balance_shares, &witness.post_match_balance_shares, cs)?;

        // Build the balance state wrapper
        // This value has the updated share stream state
        let state_wrapper = DarkpoolStateBalanceVar {
            recovery_stream: recovery_stream.clone(),
            share_stream: share_stream.clone(),
            inner: balance.clone(),
            public_share,
        };

        Ok((state_wrapper, private_shares))
    }

    /// Validate the newly created balance's fields
    fn validate_new_balance(
        balance: &BalanceVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let zero = cs.zero();
        // 1. The balance amount should be zero
        EqGadget::constrain_eq(&balance.amount, &zero, cs)?;

        // 2. The balance fees should be zero
        EqGadget::constrain_eq(&balance.relayer_fee_balance, &zero, cs)?;
        EqGadget::constrain_eq(&balance.protocol_fee_balance, &zero, cs)?;
        Ok(())
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for `NEW OUTPUT BALANCE VALIDITY`
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewOutputBalanceValidityWitness {
    /// The balance
    #[link_groups = "output_balance_settlement_party0,output_balance_settlement_party1"]
    pub balance: Balance,
    /// The balance public shares which are updated in the settlement circuit
    ///
    /// These values are proof-linked into the settlement circuit
    #[link_groups = "output_balance_settlement_party0,output_balance_settlement_party1"]
    pub post_match_balance_shares: PostMatchBalanceShare,
    /// The initial share stream of the balance
    pub initial_share_stream: PoseidonCSPRNG,
    /// The initial recovery stream of the balance
    pub initial_recovery_stream: PoseidonCSPRNG,
}

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for `NEW OUTPUT BALANCE VALIDITY`
#[circuit_type(singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewOutputBalanceValidityStatement {
    /// A partial commitment to the new output balance
    pub new_balance_partial_commitment: PartialCommitment,
    /// The recovery identifier of the new output balance
    pub recovery_id: Scalar,
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl SingleProverCircuit for NewOutputBalanceValidityCircuit {
    type Witness = NewOutputBalanceValidityWitness;
    type Statement = NewOutputBalanceValidityStatement;

    fn name() -> String {
        "New Output Balance Validity".to_string()
    }

    /// NEW OUTPUT BALANCE VALIDITY has one proof linking group:
    /// - output_balance_settlement: The linking group between NEW OUTPUT
    ///   BALANCE VALIDITY and the settlement circuits.
    ///
    /// The layout for this group is inherited from the settlement circuit.
    fn proof_linking_groups() -> Result<Vec<(String, Option<GroupLayout>)>, PlonkError> {
        let circuit_layout = IntentAndBalancePrivateSettlementCircuit::get_circuit_layout()?;
        let group_layout0 = circuit_layout.get_group_layout(OUTPUT_BALANCE_SETTLEMENT_PARTY0_LINK);
        let group_layout1 = circuit_layout.get_group_layout(OUTPUT_BALANCE_SETTLEMENT_PARTY1_LINK);

        Ok(vec![
            (OUTPUT_BALANCE_SETTLEMENT_PARTY0_LINK.to_string(), Some(group_layout0)),
            (OUTPUT_BALANCE_SETTLEMENT_PARTY1_LINK.to_string(), Some(group_layout1)),
        ])
    }

    fn apply_constraints(
        mut witness_var: NewOutputBalanceValidityWitnessVar,
        statement_var: NewOutputBalanceValidityStatementVar,
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
    use crate::test_helpers::{
        check_constraints_satisfied, create_state_wrapper, random_zeroed_balance,
    };

    use super::*;

    // -----------
    // | Helpers |
    // -----------

    /// Check that the constraints are satisfied on the given witness and
    /// statement
    pub fn check_constraints(
        witness: &NewOutputBalanceValidityWitness,
        statement: &NewOutputBalanceValidityStatement,
    ) -> bool {
        check_constraints_satisfied::<NewOutputBalanceValidityCircuit>(witness, statement)
    }

    /// Construct a witness and statement with valid data
    pub fn create_witness_statement()
    -> (NewOutputBalanceValidityWitness, NewOutputBalanceValidityStatement) {
        // Create a random balance
        let balance_inner = random_zeroed_balance();
        create_witness_statement_with_balance(balance_inner)
    }

    /// Construct a witness and statement with the given balance
    ///
    /// The balance must be zeroed (amount = 0, fees = 0) to satisfy the circuit
    /// constraints
    pub fn create_witness_statement_with_balance(
        mut balance_inner: Balance,
    ) -> (NewOutputBalanceValidityWitness, NewOutputBalanceValidityStatement) {
        balance_inner.amount = 0;
        balance_inner.relayer_fee_balance = 0;
        balance_inner.protocol_fee_balance = 0;
        let mut balance = create_state_wrapper(balance_inner);

        // Compute the recovery identifier (mutates recovery_stream)
        let recovery_id = balance.compute_recovery_id();
        let new_balance_partial_commitment =
            balance.compute_partial_commitment(NEW_BALANCE_PARTIAL_COMMITMENT_SIZE);

        // Build the witness with the initial streams (before mutations)
        let mut initial_share_stream = balance.share_stream;
        let mut initial_recovery_stream = balance.recovery_stream;
        initial_share_stream.index = 0;
        initial_recovery_stream.index = 0;
        let post_match_balance_shares = PostMatchBalanceShare::from(balance.public_share);
        let witness = NewOutputBalanceValidityWitness {
            balance: balance.inner,
            initial_share_stream,
            initial_recovery_stream,
            post_match_balance_shares,
        };

        // Build the statement
        let statement =
            NewOutputBalanceValidityStatement { new_balance_partial_commitment, recovery_id };

        (witness, statement)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use circuit_types::traits::SingleProverCircuit;

    /// A helper to print the number of constraints in the circuit
    ///
    /// Useful when benchmarking the circuit
    #[test]
    fn test_n_constraints() {
        let layout = NewOutputBalanceValidityCircuit::get_circuit_layout().unwrap();

        let n_gates = layout.n_gates;
        let circuit_size = layout.circuit_size();
        println!("Number of constraints: {n_gates}");
        println!("Next power of two: {circuit_size}");
    }

    /// Test that constraints are satisfied on a valid witness and statement
    #[test]
    fn test_valid_new_output_balance_constraints() {
        let (witness, statement) = test_helpers::create_witness_statement();
        assert!(test_helpers::check_constraints(&witness, &statement));
    }
}
