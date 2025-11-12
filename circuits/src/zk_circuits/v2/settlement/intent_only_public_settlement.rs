//! The settlement circuit for a private intent with a public settlement
//! obligation
//!
//! This circuit verifies that an intent has been correctly updated after a
//! match is settled. The settlement obligation (match result) is public,
//! meaning the verifier can see the match details.

use circuit_macros::circuit_type;
use circuit_types::{
    AMOUNT_BITS, PlonkCircuit,
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
use crate::{
    SingleProverCircuit,
    zk_gadgets::{
        comparators::{EqGadget, GreaterThanEqGadget},
        fixed_point::FixedPointGadget,
    },
};

// ----------------------
// | Circuit Definition |
// ----------------------

/// The `INTENT ONLY PUBLIC SETTLEMENT` circuit
pub struct IntentOnlyPublicSettlementCircuit<const MERKLE_HEIGHT: usize>;

impl<const MERKLE_HEIGHT: usize> IntentOnlyPublicSettlementCircuit<MERKLE_HEIGHT> {
    /// Apply the circuit constraints to a given constraint system
    pub fn circuit(
        statement: &IntentOnlyPublicSettlementStatementVar,
        witness: &mut IntentOnlyPublicSettlementWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // 1. Verify that the constraints which the intent places on the settlement
        //    obligation are satisfied
        Self::verify_intent_constraints(statement, witness, cs)?;

        // 2. Verify the update to the intent's amount public share
        // The remaining amount in the intent should decrease by the amount paid in the
        // obligation. We can rely on the additive homomorphic property of our stream
        // cipher and simply subtract the executed amount from the pre-settlement public
        // share.
        let expected_public_share = cs.sub(
            witness.pre_settlement_amount_public_share,
            statement.settlement_obligation.amount_in,
        )?;
        EqGadget::constrain_eq(&expected_public_share, &statement.new_amount_public_share, cs)?;

        Ok(())
    }

    /// Verify the constraints which the intent places on the settlement
    /// obligation
    fn verify_intent_constraints(
        statement: &IntentOnlyPublicSettlementStatementVar,
        witness: &IntentOnlyPublicSettlementWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let intent = &witness.intent;
        let obligation = &statement.settlement_obligation;

        // The settlement obligation's token pair must match that of the intent
        EqGadget::constrain_eq(&obligation.input_token, &intent.in_token, cs)?;
        EqGadget::constrain_eq(&obligation.output_token, &intent.out_token, cs)?;

        // The input amount of the obligation must not exceed the intent's amount
        GreaterThanEqGadget::constrain_greater_than_eq(
            intent.amount_in,
            obligation.amount_in,
            AMOUNT_BITS,
            cs,
        )?;

        // The settlement obligation must exceed the intent's worst case price
        // `intent.min_price` is in units of `out_token/in_token` so we need only clear
        // the denominator
        let min_output_fp =
            FixedPointGadget::mul_integer(intent.min_price, obligation.amount_in, cs)?;
        let min_output = FixedPointGadget::floor(min_output_fp, cs)?;
        GreaterThanEqGadget::constrain_greater_than_eq(
            obligation.amount_out,
            min_output,
            AMOUNT_BITS,
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
    /// The pre-update public share of the intent's amount
    ///
    /// This should match the `new_amount_public_share` from the intent validity
    /// proof that authorized this settlement
    #[link_groups = "intent_only_settlement"]
    pub pre_settlement_amount_public_share: Scalar,
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
    /// The updated amount public share of the intent
    pub new_amount_public_share: Scalar,
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
    use circuit_types::intent::Intent;
    use constants::Scalar;

    use crate::{
        test_helpers::{
            check_constraints_satisfied, create_settlement_obligation, random_intent, random_scalar,
        },
        zk_circuits::v2::settlement::intent_only_public_settlement::{
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

        let pre_settlement_amount_public_share = random_scalar();
        let new_amount_public_share =
            pre_settlement_amount_public_share - Scalar::from(settlement_obligation.amount_in);

        let witness = IntentOnlyPublicSettlementWitness {
            intent: intent.clone(),
            pre_settlement_amount_public_share,
        };
        let statement =
            IntentOnlyPublicSettlementStatement { settlement_obligation, new_amount_public_share };

        (witness, statement)
    }
}

#[cfg(test)]
mod test {
    use crate::test_helpers::{
        compute_min_amount_out, random_address, random_intent, random_scalar,
    };

    use super::*;
    use circuit_types::{max_amount, traits::SingleProverCircuit};
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
        statement.new_amount_public_share =
            witness.pre_settlement_amount_public_share - Scalar::from(witness.intent.amount_in);
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

    /// Test the case in which the `amount_in` public share is updated
    /// incorrectly
    #[test]
    fn test_invalid_amount_in_public_share() {
        let (witness, mut statement) = test_helpers::create_witness_statement::<MERKLE_HEIGHT>();
        statement.new_amount_public_share = random_scalar();
        assert!(!test_helpers::check_constraints::<MERKLE_HEIGHT>(&witness, &statement));
    }

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
        statement.new_amount_public_share =
            witness.pre_settlement_amount_public_share - Scalar::from(new_amount_in);

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
