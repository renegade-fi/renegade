//! Defines the circuitry for a bounded settlement of an intent and balance
//!
//! A bounded settlement is one where the trade size is determined at runtime
//! by an external party. This circuit verifies that the intent's constraints
//! are satisfied by the bounded match result.

use crate::{
    SingleProverCircuit, zk_circuits::settlement::settlement_lib::SettlementGadget,
    zk_gadgets::comparators::EqGadget,
};
use alloy_primitives::Address;
use circuit_macros::circuit_type;
use circuit_types::{
    PlonkCircuit,
    balance::{Balance, PostMatchBalanceShare},
    bounded_match_result::BoundedMatchResult,
    fixed_point::FixedPoint,
    intent::Intent,
    traits::{BaseType, CircuitBaseType, CircuitVarType},
};
use constants::{Scalar, ScalarField};
use mpc_plonk::errors::PlonkError;
use mpc_relation::{Variable, errors::CircuitError, proof_linking::GroupLayout, traits::Circuit};
use serde::{Deserialize, Serialize};

// ----------------------
// | Circuit Definition |
// ----------------------

/// The `INTENT AND BALANCE BOUNDED SETTLEMENT` circuit
pub struct IntentAndBalanceBoundedSettlementCircuit;
impl IntentAndBalanceBoundedSettlementCircuit {
    /// Apply the circuit constraints to a given constraint system
    pub fn circuit(
        statement: &IntentAndBalanceBoundedSettlementStatementVar,
        witness: &mut IntentAndBalanceBoundedSettlementWitnessVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // 1. Verify the constraints imposed by both the intent and the balance
        SettlementGadget::verify_intent_and_balance_bounded_match_result_constraints(
            &witness.intent,
            &witness.in_balance,
            &witness.out_balance,
            &statement.bounded_match_result,
            cs,
        )?;

        // 2. Verify that the leaked pre-update public shares match those proof-linked
        //    into the witness
        EqGadget::constrain_eq(
            &witness.pre_settlement_amount_public_share,
            &statement.amount_public_share,
            cs,
        )?;
        EqGadget::constrain_eq(
            &witness.pre_settlement_in_balance_shares,
            &statement.in_balance_public_shares,
            cs,
        )?;
        EqGadget::constrain_eq(
            &witness.pre_settlement_out_balance_shares,
            &statement.out_balance_public_shares,
            cs,
        )?;

        // 3. Verify the leak of the relayer fee recipient
        EqGadget::constrain_eq(
            &witness.out_balance.relayer_fee_recipient,
            &statement.relayer_fee_recipient,
            cs,
        )
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for `INTENT AND BALANCE BOUNDED SETTLEMENT`
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntentAndBalanceBoundedSettlementWitness {
    /// The intent which this circuit is settling a match for
    ///
    /// This value is proof-linked from the `INTENT AND BALANCE VALIDITY`
    /// circuit
    pub intent: Intent,
    /// The pre-update public share of the intent's amount
    ///
    /// This should match the `new_amount_public_share` from the intent validity
    /// proof that authorized this settlement
    pub pre_settlement_amount_public_share: Scalar,
    /// The balance which capitalizes the intent
    ///
    /// This value is proof-linked from the `INTENT AND BALANCE VALIDITY`
    /// circuit
    pub in_balance: Balance,
    /// The balance public shares which are updated in the settlement circuit
    ///
    /// This value is proof-linked from the `INTENT AND BALANCE VALIDITY`
    /// circuit
    pub pre_settlement_in_balance_shares: PostMatchBalanceShare,
    /// The balance which receives the output tokens of the obligation
    ///
    /// This value is proof-linked from the `INTENT AND BALANCE VALIDITY`
    /// circuit
    pub out_balance: Balance,
    /// The balance public shares which are updated in the settlement circuit
    /// for the output balance
    ///
    /// This value is proof-linked from the `INTENT AND BALANCE VALIDITY`
    /// circuit
    pub pre_settlement_out_balance_shares: PostMatchBalanceShare,
}

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for `INTENT AND BALANCE BOUNDED SETTLEMENT`
#[circuit_type(singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntentAndBalanceBoundedSettlementStatement {
    /// The bounded match result which this circuit is settling a match for
    ///
    /// Note that the contract is responsible for validating the constraints
    /// which require only the bounded match result, including:
    /// - Bit lengths on price, min_internal_party_amount_in, and
    ///   max_internal_party_amount_in
    /// - min_internal_party_amount_in <= max_internal_party_amount_in
    pub bounded_match_result: BoundedMatchResult,
    /// The leaked pre-update amount public share of the intent
    ///
    /// Because this circuit represents a public settlement, we leak the public
    /// share and allow the contracts to update it on-chain.
    pub amount_public_share: Scalar,
    /// The updated public shares of the post-match balance fields for the input
    /// balance.
    ///
    /// This value is also leaked from the witness so that the contracts can
    /// update it directly on-chain.
    pub in_balance_public_shares: PostMatchBalanceShare,
    /// The updated public shares of the post-match balance fields for the
    /// output balance
    ///
    /// This value is also leaked from the witness so that the contracts can
    /// update it directly on-chain.
    pub out_balance_public_shares: PostMatchBalanceShare,
    /// The relayer fee which is charged for the settlement
    ///
    /// We place this field in the statement so that it is included in the
    /// Fiat-Shamir transcript and therefore is not malleable transaction
    /// calldata. This allows the relayer to set the fee and be sure it cannot
    /// be modified by mempool observers.
    pub relayer_fee: FixedPoint,
    /// The recipient of the relayer fee
    ///
    /// This must match the value on the output balance where the fee is
    /// accrued.
    pub relayer_fee_recipient: Address,
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl SingleProverCircuit for IntentAndBalanceBoundedSettlementCircuit {
    type Witness = IntentAndBalanceBoundedSettlementWitness;
    type Statement = IntentAndBalanceBoundedSettlementStatement;

    fn name() -> String {
        "Intent And Balance Bounded Settlement".to_string()
    }

    fn proof_linking_groups() -> Result<Vec<(String, Option<GroupLayout>)>, PlonkError> {
        // TODO: Implement
        Ok(vec![])
    }

    fn apply_constraints(
        mut witness_var: IntentAndBalanceBoundedSettlementWitnessVar,
        statement_var: IntentAndBalanceBoundedSettlementStatementVar,
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
    use alloy_primitives::Address;
    use circuit_types::{
        balance::Balance, bounded_match_result::BoundedMatchResult, intent::Intent, max_amount,
    };
    use rand::{Rng, thread_rng};

    use crate::{
        test_helpers::{
            create_bounded_match_result_with_balance, create_matching_balance_for_intent,
            random_address, random_amount, random_fee, random_intent,
            random_post_match_balance_share, random_scalar,
        },
        zk_circuits::settlement::intent_and_balance_bounded_settlement::{
            IntentAndBalanceBoundedSettlementCircuit, IntentAndBalanceBoundedSettlementStatement,
            IntentAndBalanceBoundedSettlementWitness,
        },
    };

    // -----------
    // | Helpers |
    // -----------

    /// Check that the constraints are satisfied on the given witness and
    /// statement
    pub fn check_constraints(
        witness: &IntentAndBalanceBoundedSettlementWitness,
        statement: &IntentAndBalanceBoundedSettlementStatement,
    ) -> bool {
        crate::test_helpers::check_constraints_satisfied::<IntentAndBalanceBoundedSettlementCircuit>(
            witness, statement,
        )
    }

    /// Construct a witness and statement with valid data
    pub fn create_witness_statement()
    -> (IntentAndBalanceBoundedSettlementWitness, IntentAndBalanceBoundedSettlementStatement) {
        let intent = random_intent();
        create_witness_statement_with_intent(&intent)
    }

    /// Create a witness and statement with the given intent
    pub fn create_witness_statement_with_intent(
        intent: &Intent,
    ) -> (IntentAndBalanceBoundedSettlementWitness, IntentAndBalanceBoundedSettlementStatement)
    {
        let balance = create_matching_balance_for_intent(intent);
        create_witness_statement_with_intent_and_balance(intent, &balance)
    }

    /// Create a witness and statement with the given intent and balance
    pub fn create_witness_statement_with_intent_and_balance(
        intent: &Intent,
        balance: &Balance,
    ) -> (IntentAndBalanceBoundedSettlementWitness, IntentAndBalanceBoundedSettlementStatement)
    {
        let bounded_match_result = create_bounded_match_result_with_balance(intent, balance.amount);

        create_witness_statement_with_intent_balance_and_bounded_match_result(
            intent,
            balance,
            bounded_match_result,
        )
    }

    /// Create a witness and statement for a given intent, balance, and bounded
    /// match result
    pub fn create_witness_statement_with_intent_balance_and_bounded_match_result(
        intent: &Intent,
        balance: &Balance,
        bounded_match_result: BoundedMatchResult,
    ) -> (IntentAndBalanceBoundedSettlementWitness, IntentAndBalanceBoundedSettlementStatement)
    {
        // Create the intent amount public shares
        let receive_balance = create_receive_balance(intent.owner, &bounded_match_result);
        let pre_settlement_amount_public_share = random_scalar();

        // Create the balance post-match shares
        let pre_settlement_in_balance_shares = random_post_match_balance_share();
        let pre_settlement_out_balance_shares = random_post_match_balance_share();

        let relayer_fee_recipient = receive_balance.relayer_fee_recipient;
        let witness = IntentAndBalanceBoundedSettlementWitness {
            intent: intent.clone(),
            pre_settlement_amount_public_share,
            in_balance: balance.clone(),
            pre_settlement_in_balance_shares: pre_settlement_in_balance_shares.clone(),
            out_balance: receive_balance,
            pre_settlement_out_balance_shares: pre_settlement_out_balance_shares.clone(),
        };
        let statement = IntentAndBalanceBoundedSettlementStatement {
            bounded_match_result,
            amount_public_share: pre_settlement_amount_public_share,
            in_balance_public_shares: pre_settlement_in_balance_shares,
            out_balance_public_shares: pre_settlement_out_balance_shares,
            relayer_fee: random_fee(),
            relayer_fee_recipient,
        };

        (witness, statement)
    }

    pub fn create_receive_balance(
        owner: Address,
        bounded_match_result: &BoundedMatchResult,
    ) -> Balance {
        let mut rng = thread_rng();
        let max_existing_balance = max_amount() - bounded_match_result.max_internal_party_amount_in;
        let amount = rng.gen_range(0..=max_existing_balance);

        Balance {
            mint: bounded_match_result.internal_party_output_token,
            owner,
            relayer_fee_recipient: random_address(),
            one_time_authority: random_address(),
            relayer_fee_balance: random_amount(),
            protocol_fee_balance: random_amount(),
            amount,
        }
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
        let layout = IntentAndBalanceBoundedSettlementCircuit::get_circuit_layout().unwrap();

        let n_gates = layout.n_gates;
        let circuit_size = layout.circuit_size();
        println!("Number of constraints: {n_gates}");
        println!("Next power of two: {circuit_size}");
    }

    /// Test that constraints are satisfied on a valid witness and statement
    #[test]
    fn test_valid_intent_and_balance_bounded_settlement_constraints() {
        let (witness, statement) = test_helpers::create_witness_statement();
        assert!(test_helpers::check_constraints(&witness, &statement));
    }
}
