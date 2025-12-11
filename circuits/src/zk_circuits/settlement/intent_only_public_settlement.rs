//! The settlement circuit for a private intent with a public settlement
//! obligation
//!
//! This circuit verifies that an intent has been correctly updated after a
//! match is settled. The settlement obligation (match result) is public,
//! meaning the verifier can see the match details.

use alloy_primitives::Address;
use circuit_macros::circuit_type;
use circuit_types::{
    PlonkCircuit,
    fixed_point::FixedPoint,
    intent::Intent,
    settlement_obligation::SettlementObligation,
    traits::{BaseType, CircuitBaseType, CircuitVarType},
};
use constants::{MERKLE_HEIGHT, Scalar, ScalarField};
use mpc_plonk::errors::PlonkError;
use mpc_relation::{
    Variable,
    errors::CircuitError,
    proof_linking::{GroupLayout, LinkableCircuit},
    traits::Circuit,
};
use serde::{Deserialize, Serialize};

use super::INTENT_ONLY_PUBLIC_SETTLEMENT_LINK;
use crate::{SingleProverCircuit, zk_circuits::settlement::settlement_lib::SettlementGadget};

// ----------------------
// | Circuit Definition |
// ----------------------

/// The `INTENT ONLY PUBLIC SETTLEMENT` circuit with default const generic
/// sizing parameters
pub type SizedIntentOnlyPublicSettlementCircuit = IntentOnlyPublicSettlementCircuit<MERKLE_HEIGHT>;
/// The `INTENT ONLY PUBLIC SETTLEMENT` circuit
pub struct IntentOnlyPublicSettlementCircuit<const MERKLE_HEIGHT: usize>;

impl<const MERKLE_HEIGHT: usize> IntentOnlyPublicSettlementCircuit<MERKLE_HEIGHT> {
    /// Apply the circuit constraints to a given constraint system
    ///
    /// Note that the intent's amount public share is updated by the contracts
    /// using the homomorphic property of our stream cipher. So we need not
    /// validate any state updates here.
    ///
    /// All that must be validated here is that the intent's constraints are
    /// satisfied by the settlement obligation.
    pub fn circuit(
        statement: &IntentOnlyPublicSettlementStatementVar,
        witness: &mut IntentOnlyPublicSettlementWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Verify that the constraints which the intent places on the settlement
        // obligation are satisfied
        SettlementGadget::verify_intent_constraints(
            &witness.intent,
            &statement.settlement_obligation,
            cs,
        )?;

        Ok(())
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for `INTENT ONLY PUBLIC SETTLEMENT`
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntentOnlyPublicSettlementWitness<const MERKLE_HEIGHT: usize> {
    /// The intent which this circuit is settling a match for
    #[link_groups = "intent_only_settlement"]
    pub intent: Intent,
}

/// A `INTENT ONLY PUBLIC SETTLEMENT` witness with default const generic sizing
/// parameters
pub type SizedIntentOnlyPublicSettlementWitness = IntentOnlyPublicSettlementWitness<MERKLE_HEIGHT>;

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for `INTENT ONLY PUBLIC SETTLEMENT`
#[circuit_type(singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntentOnlyPublicSettlementStatement {
    /// The settlement obligation for the party
    ///
    /// Note that the contract is responsible for validating the constraints
    /// which require only the obligation. For example, bitlengths on the
    /// obligation's in and out amounts
    pub settlement_obligation: SettlementObligation,
    /// The relayer fee which is charged for the settlement
    ///
    /// We place this field in the statement so that it is included in the
    /// Fiat-Shamir transcript and therefore is not malleable transaction
    /// calldata. This allows the relayer to set the fee and be sure it cannot
    /// be modified by mempool observers.
    pub relayer_fee: FixedPoint,
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

impl<const MERKLE_HEIGHT: usize> SingleProverCircuit
    for IntentOnlyPublicSettlementCircuit<MERKLE_HEIGHT>
{
    type Witness = IntentOnlyPublicSettlementWitness<MERKLE_HEIGHT>;
    type Statement = IntentOnlyPublicSettlementStatement;

    fn name() -> String {
        format!("Intent Only Public Settlement ({MERKLE_HEIGHT})")
    }

    /// INTENT ONLY PUBLIC SETTLEMENT has one proof linking group:
    /// - intent_only_public_settlement: The linking group between INTENT ONLY
    ///   VALIDITY and INTENT ONLY PUBLIC SETTLEMENT. This group is placed by
    ///   this circuit.
    fn proof_linking_groups() -> Result<Vec<(String, Option<GroupLayout>)>, PlonkError> {
        // Place the linking group (the intent validity circuit will inherit it)
        Ok(vec![(INTENT_ONLY_PUBLIC_SETTLEMENT_LINK.to_string(), None)])
    }

    fn apply_constraints(
        mut witness_var: IntentOnlyPublicSettlementWitnessVar<MERKLE_HEIGHT>,
        statement_var: IntentOnlyPublicSettlementStatementVar,
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
    use circuit_types::{intent::Intent, settlement_obligation::SettlementObligation};

    use crate::{
        test_helpers::{
            check_constraints_satisfied, create_settlement_obligation, random_address, random_fee,
            random_intent,
        },
        zk_circuits::settlement::intent_only_public_settlement::{
            IntentOnlyPublicSettlementCircuit, IntentOnlyPublicSettlementStatement,
            IntentOnlyPublicSettlementWitness,
        },
    };

    // -----------
    // | Helpers |
    // -----------

    /// Check that the constraints are satisfied on the given witness and
    /// statement
    pub fn check_constraints<const MERKLE_HEIGHT: usize>(
        witness: &IntentOnlyPublicSettlementWitness<MERKLE_HEIGHT>,
        statement: &IntentOnlyPublicSettlementStatement,
    ) -> bool {
        check_constraints_satisfied::<IntentOnlyPublicSettlementCircuit<MERKLE_HEIGHT>>(
            witness, statement,
        )
    }

    /// Construct a witness and statement with valid data
    pub fn create_witness_statement<const MERKLE_HEIGHT: usize>()
    -> (IntentOnlyPublicSettlementWitness<MERKLE_HEIGHT>, IntentOnlyPublicSettlementStatement) {
        let intent = random_intent();
        create_witness_statement_with_intent::<MERKLE_HEIGHT>(&intent)
    }

    /// Create a witness and statement with the given intent
    pub fn create_witness_statement_with_intent<const MERKLE_HEIGHT: usize>(
        intent: &Intent,
    ) -> (IntentOnlyPublicSettlementWitness<MERKLE_HEIGHT>, IntentOnlyPublicSettlementStatement)
    {
        let settlement_obligation = create_settlement_obligation(intent);
        create_witness_statement_with_intent_and_obligation::<MERKLE_HEIGHT>(
            intent,
            &settlement_obligation,
        )
    }

    /// Create a witness and statement with the given intent and obligation
    pub fn create_witness_statement_with_intent_and_obligation<const MERKLE_HEIGHT: usize>(
        intent: &Intent,
        obligation: &SettlementObligation,
    ) -> (IntentOnlyPublicSettlementWitness<MERKLE_HEIGHT>, IntentOnlyPublicSettlementStatement)
    {
        let witness = IntentOnlyPublicSettlementWitness { intent: intent.clone() };
        let statement = IntentOnlyPublicSettlementStatement {
            settlement_obligation: obligation.clone(),
            relayer_fee: random_fee(),
            relayer_fee_recipient: random_address(),
        };

        (witness, statement)
    }
}

#[cfg(test)]
mod test {
    use crate::test_helpers::{compute_min_amount_out, random_address, random_intent};

    use super::*;
    use circuit_types::{AMOUNT_BITS, max_amount, traits::SingleProverCircuit};
    use constants::MERKLE_HEIGHT;
    use rand::{Rng, thread_rng};

    /// A helper to print the number of constraints in the circuit
    ///
    /// Useful when benchmarking the circuit
    #[test]
    fn test_n_constraints() {
        let layout =
            IntentOnlyPublicSettlementCircuit::<MERKLE_HEIGHT>::get_circuit_layout().unwrap();

        let n_gates = layout.n_gates;
        let circuit_size = layout.circuit_size();
        println!("Number of constraints: {n_gates}");
        println!("Next power of two: {circuit_size}");
    }

    /// Test that constraints are satisfied on a valid witness and statement
    #[test]
    fn test_valid_intent_only_public_settlement_constraints() {
        let (witness, statement) = test_helpers::create_witness_statement::<MERKLE_HEIGHT>();
        assert!(test_helpers::check_constraints::<MERKLE_HEIGHT>(&witness, &statement));
    }

    /// Test the case in which the entire intent is settled
    #[test]
    fn test_full_fill() {
        // Sample an intent and leave room to actually settle the max amount
        let mut rng = thread_rng();
        let mut intent = random_intent();
        let max_amount_in = 1u128 << (AMOUNT_BITS / 2);
        intent.amount_in = rng.gen_range(0..max_amount_in);
        let (witness, mut statement) =
            test_helpers::create_witness_statement_with_intent::<MERKLE_HEIGHT>(&intent);

        // Modify the obligation to settle the max amount
        statement.settlement_obligation.amount_in = witness.intent.amount_in;
        let min_out = compute_min_amount_out(&witness.intent, witness.intent.amount_in);
        let amt_out = rng.gen_range(min_out..=max_amount());
        statement.settlement_obligation.amount_out = amt_out;
        assert!(test_helpers::check_constraints::<MERKLE_HEIGHT>(&witness, &statement));
    }

    /// Test the case in which the obligation settles exactly the minimum output
    /// amount
    #[test]
    fn test_exact_min_amount_out() {
        let (witness, mut statement) = test_helpers::create_witness_statement::<MERKLE_HEIGHT>();

        let amount_in = statement.settlement_obligation.amount_in;
        let min_out = compute_min_amount_out(&witness.intent, amount_in);
        statement.settlement_obligation.amount_out = min_out;
        assert!(test_helpers::check_constraints::<MERKLE_HEIGHT>(&witness, &statement));
    }

    // --- Invalid Test Cases --- //

    /// Test the case in which the pair in the obligation does not match the
    /// pair in the intent
    #[test]
    fn test_invalid_pair_in_obligation() {
        let mut rng = thread_rng();
        let (witness, mut statement) = test_helpers::create_witness_statement::<MERKLE_HEIGHT>();

        if rng.gen_bool(0.5) {
            statement.settlement_obligation.input_token = random_address();
        } else {
            statement.settlement_obligation.output_token = random_address();
        }
        assert!(!test_helpers::check_constraints::<MERKLE_HEIGHT>(&witness, &statement));
    }

    /// Test the case in which the obligation attempts to settle more than the
    /// intent's size
    #[test]
    fn test_invalid_amount_in_exceeds_intent_size() {
        // Leave room to exceed the max amount
        let mut rng = thread_rng();
        let mut intent = random_intent();
        let max_amount_in = 1u128 << (AMOUNT_BITS / 2);
        intent.amount_in = rng.gen_range(0..max_amount_in);

        let (witness, mut statement) =
            test_helpers::create_witness_statement_with_intent::<MERKLE_HEIGHT>(&intent);

        // Modify the amount in
        let new_amount_in = witness.intent.amount_in + 1;
        statement.settlement_obligation.amount_in = new_amount_in;

        // Update other fields to isolate the constraint
        let amount_out = compute_min_amount_out(&witness.intent, new_amount_in);
        statement.settlement_obligation.amount_out = amount_out;

        // Check that the constraints are not satisfied
        assert!(!test_helpers::check_constraints::<MERKLE_HEIGHT>(&witness, &statement));
    }

    /// Test the case in which the obligation violates the intent's min price
    #[test]
    fn test_invalid_amount_out_violates_min_price() {
        let (witness, mut statement) = test_helpers::create_witness_statement::<MERKLE_HEIGHT>();

        let min_amount_out = compute_min_amount_out(&witness.intent, witness.intent.amount_in);
        let amount_out = min_amount_out - 1;
        statement.settlement_obligation.amount_out = amount_out;
        assert!(!test_helpers::check_constraints::<MERKLE_HEIGHT>(&witness, &statement));
    }
}
