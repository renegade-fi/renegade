//! The settlement circuit for a private intent with a public, bounded
//! settlement
//!
//! A bounded settlement is one where the trade size is determined at runtime
//! by an external party. This circuit verifies that the intent's constraints
//! are satisfied by the bounded match result.

use alloy_primitives::Address;
use circuit_macros::circuit_type;
use circuit_types::{
    PlonkCircuit,
    bounded_match_result::BoundedMatchResult,
    fixed_point::FixedPoint,
    intent::Intent,
    traits::{BaseType, CircuitBaseType, CircuitVarType},
};
use constants::{Scalar, ScalarField};
use mpc_plonk::errors::PlonkError;
use mpc_relation::{Variable, errors::CircuitError, traits::Circuit};
use serde::{Deserialize, Serialize};

use crate::{SingleProverCircuit, zk_circuits::settlement::settlement_lib::SettlementGadget};

// ----------------------
// | Circuit Definition |
// ----------------------

/// The `INTENT ONLY BOUNDED SETTLEMENT` circuit
pub struct IntentOnlyBoundedSettlementCircuit;

impl IntentOnlyBoundedSettlementCircuit {
    /// Apply the circuit constraints to a given constraint system
    ///
    /// Note that, since the trade size is determined at runtime, the intent's
    /// amount public share is updated by the contracts using the homomorphic
    /// property of our stream cipher. So we need not validate any state updates
    /// here.
    ///
    /// All that must be validated here is that the intent's constraints are
    /// satisfied by the bounded match result.
    ///
    /// As well, price and amount bitlengths are validated by the contracts.
    pub fn circuit(
        statement: &IntentOnlyBoundedSettlementStatementVar,
        witness: &mut IntentOnlyBoundedSettlementWitnessVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Verify that the constraints which the intent places on the bounded
        // match result are satisfied
        SettlementGadget::verify_intent_bounded_match_result_constraints(
            &witness.intent,
            &statement.bounded_match_result,
            cs,
        )?;

        Ok(())
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for `INTENT ONLY BOUNDED SETTLEMENT`
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntentOnlyBoundedSettlementWitness {
    /// The intent which this circuit is settling a match for
    pub intent: Intent,
}

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for `INTENT ONLY BOUNDED SETTLEMENT`
#[circuit_type(singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntentOnlyBoundedSettlementStatement {
    /// The bounded match result which this circuit is settling a match for
    pub bounded_match_result: BoundedMatchResult,
    /// The relayer fee which is charged to the internal party for the
    /// settlement
    ///
    /// We place this field in the statement so that it is included in the
    /// Fiat-Shamir transcript and therefore is not malleable transaction
    /// calldata. This allows the relayer to set the fee and be sure it cannot
    /// be modified by mempool observers.
    pub internal_relayer_fee: FixedPoint,
    /// The relayer fee which is charged to the external party for the
    /// settlement
    pub external_relayer_fee: FixedPoint,
    /// The recipient of the relayer fee
    ///
    /// Similar to above, we place this in the statement to make it
    /// non-malleable; though it is otherwise unconstrained. This allows us to
    /// be sure the prover alone set this value.
    pub relayer_fee_recipient: Address,
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl SingleProverCircuit for IntentOnlyBoundedSettlementCircuit {
    type Witness = IntentOnlyBoundedSettlementWitness;
    type Statement = IntentOnlyBoundedSettlementStatement;

    fn name() -> String {
        "Intent Only Bounded Settlement".to_string()
    }

    fn apply_constraints(
        mut witness_var: IntentOnlyBoundedSettlementWitnessVar,
        statement_var: IntentOnlyBoundedSettlementStatementVar,
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
    use crate::{
        test_helpers::{
            check_constraints_satisfied, create_bounded_match_result, random_address, random_fee,
            random_intent,
        },
        zk_circuits::settlement::intent_only_bounded_settlement::{
            IntentOnlyBoundedSettlementCircuit, IntentOnlyBoundedSettlementStatement,
            IntentOnlyBoundedSettlementWitness,
        },
    };
    use circuit_types::{bounded_match_result::BoundedMatchResult, intent::Intent};

    // -----------
    // | Helpers |
    // -----------

    /// Check that the constraints are satisfied on the given witness and
    /// statement
    pub fn check_constraints(
        witness: &IntentOnlyBoundedSettlementWitness,
        statement: &IntentOnlyBoundedSettlementStatement,
    ) -> bool {
        check_constraints_satisfied::<IntentOnlyBoundedSettlementCircuit>(witness, statement)
    }

    /// Construct a witness and statement with valid data
    pub fn create_witness_statement()
    -> (IntentOnlyBoundedSettlementWitness, IntentOnlyBoundedSettlementStatement) {
        let intent = random_intent();
        create_witness_statement_with_intent(&intent)
    }

    /// Create a witness and statement with the given intent
    pub fn create_witness_statement_with_intent(
        intent: &Intent,
    ) -> (IntentOnlyBoundedSettlementWitness, IntentOnlyBoundedSettlementStatement) {
        let bounded_match_result = create_bounded_match_result(intent);
        create_witness_statement_with_intent_and_bounded_match_result(intent, &bounded_match_result)
    }

    /// Create a witness and statement with the given intent and obligation
    pub fn create_witness_statement_with_intent_and_bounded_match_result(
        intent: &Intent,
        bounded_match_result: &BoundedMatchResult,
    ) -> (IntentOnlyBoundedSettlementWitness, IntentOnlyBoundedSettlementStatement) {
        let witness = IntentOnlyBoundedSettlementWitness { intent: intent.clone() };
        let statement = IntentOnlyBoundedSettlementStatement {
            bounded_match_result: bounded_match_result.clone(),
            internal_relayer_fee: random_fee(),
            external_relayer_fee: random_fee(),
            relayer_fee_recipient: random_address(),
        };

        (witness, statement)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::zk_circuits::settlement::intent_only_bounded_settlement::test_helpers;

    /// A helper to print the number of constraints in the circuit
    ///
    /// Useful when benchmarking the circuit
    #[test]
    fn test_n_constraints() {
        let layout = IntentOnlyBoundedSettlementCircuit::get_circuit_layout().unwrap();
        let n_gates = layout.n_gates;
        let circuit_size = layout.circuit_size();
        println!("Number of constraints: {n_gates}");
        println!("Next power of two: {circuit_size}");
    }

    /// Test that constraints are satisfied on a valid witness and statement
    #[test]
    fn test_valid_intent_only_bounded_settlement_constraints() {
        let (witness, statement) = test_helpers::create_witness_statement();
        assert!(test_helpers::check_constraints(&witness, &statement));
    }
}
