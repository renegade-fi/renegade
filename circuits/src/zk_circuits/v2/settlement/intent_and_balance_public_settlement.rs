//! Defines the circuitry for a public settlement of an intent and balance
//!
//! This settlement is performed by a relayer cluster, and is used to settle an
//! intent and balance pair

use circuit_macros::circuit_type;
use circuit_types::{
    AMOUNT_BITS, PlonkCircuit,
    balance::{Balance, PostMatchBalanceShare},
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

use super::INTENT_AND_BALANCE_PUBLIC_SETTLEMENT_LINK;
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

/// The `INTENT AND BALANCE PUBLIC SETTLEMENT` circuit
pub struct IntentAndBalancePublicSettlementCircuit<const MERKLE_HEIGHT: usize>;

/// The `INTENT AND BALANCE PUBLIC SETTLEMENT` circuit with default const
/// generic sizing parameters
pub type SizedIntentAndBalancePublicSettlementCircuit =
    IntentAndBalancePublicSettlementCircuit<MERKLE_HEIGHT>;

impl<const MERKLE_HEIGHT: usize> IntentAndBalancePublicSettlementCircuit<MERKLE_HEIGHT> {
    /// Apply the circuit constraints to a given constraint system
    pub fn circuit(
        statement: &IntentAndBalancePublicSettlementStatementVar,
        witness: &mut IntentAndBalancePublicSettlementWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // 1. Verify the constraints imposed by both the intent and the balance
        Self::verify_intent_constraints(statement, witness, cs)?;
        Self::verify_balance_constraints(statement, witness, cs)?;

        // 2. Verify the update to the intent and balance shares
        // - The intent's amount public share should decrease by obligation input
        // - The balance's amount should decrease by the obligation input
        // - TODO: Fees
        // We can rely on the additive homomorphic property of our stream cipher
        // for each of these updates.

        // Intent update
        let expected_amount_public_share = cs.sub(
            witness.pre_settlement_amount_public_share,
            statement.settlement_obligation.amount_in,
        )?;
        EqGadget::constrain_eq(
            &expected_amount_public_share,
            &statement.new_amount_public_share,
            cs,
        )?;

        // Balance update
        // TODO: Add fees
        let mut expected_shares = witness.pre_settlement_balance_shares.clone();
        expected_shares.amount = cs.sub(
            witness.pre_settlement_balance_shares.amount,
            statement.settlement_obligation.amount_in,
        )?;
        EqGadget::constrain_eq(&expected_shares, &statement.new_balance_public_shares, cs)
    }

    /// Verify that the intent's constraints are satisfied
    pub fn verify_intent_constraints(
        statement: &IntentAndBalancePublicSettlementStatementVar,
        witness: &IntentAndBalancePublicSettlementWitnessVar<MERKLE_HEIGHT>,
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

    /// Verify that the balance's constraints are satisfied
    ///
    /// We only need to verify that the balance adequately capitalizes the
    /// obligation. The pre-settlement validity proofs will verify that the mint
    /// of the balance matches the mint of the intent, and thereby the
    /// obligation.
    pub fn verify_balance_constraints(
        statement: &IntentAndBalancePublicSettlementStatementVar,
        witness: &IntentAndBalancePublicSettlementWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let balance = &witness.balance;
        let obligation = &statement.settlement_obligation;

        // The balance must exceed the obligation's input amount
        GreaterThanEqGadget::constrain_greater_than_eq(
            balance.amount,
            obligation.amount_in,
            AMOUNT_BITS,
            cs,
        )
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for `INTENT AND BALANCE PUBLIC SETTLEMENT`
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntentAndBalancePublicSettlementWitness<const MERKLE_HEIGHT: usize> {
    /// The intent which this circuit is settling a match for
    ///
    /// This value is proof-linked from the `INTENT AND BALANCE VALIDITY`
    /// circuit
    #[link_groups = "intent_and_balance_public_settlement"]
    pub intent: Intent,
    /// The pre-update public share of the intent's amount
    ///
    /// This should match the `new_amount_public_share` from the intent validity
    /// proof that authorized this settlement
    #[link_groups = "intent_and_balance_public_settlement"]
    pub pre_settlement_amount_public_share: Scalar,
    /// The balance which capitalizes the intent
    ///
    /// This value is proof-linked from the `INTENT AND BALANCE VALIDITY`
    /// circuit
    #[link_groups = "intent_and_balance_public_settlement"]
    pub balance: Balance,
    /// The updated public shares of the post-match balance
    ///
    /// This value is proof-linked from the `INTENT AND BALANCE VALIDITY`
    /// circuit
    #[link_groups = "intent_and_balance_public_settlement"]
    pub pre_settlement_balance_shares: PostMatchBalanceShare,
}

/// A `INTENT AND BALANCE PUBLIC SETTLEMENT` witness with default const generic
/// sizing parameters
pub type SizedIntentAndBalancePublicSettlementWitness =
    IntentAndBalancePublicSettlementWitness<MERKLE_HEIGHT>;

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for `INTENT AND BALANCE PUBLIC SETTLEMENT`
#[circuit_type(singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntentAndBalancePublicSettlementStatement {
    /// The settlement obligation for the party
    ///
    /// Note that the contract is responsible for validating the constraints
    /// which require only the obligation. For example, bitlengths on the
    /// obligation's in and out amounts
    pub settlement_obligation: SettlementObligation,
    /// The updated amount public share of the intent
    pub new_amount_public_share: Scalar,
    /// The updated public shares of the post-match balance fields
    pub new_balance_public_shares: PostMatchBalanceShare,
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl<const MERKLE_HEIGHT: usize> SingleProverCircuit
    for IntentAndBalancePublicSettlementCircuit<MERKLE_HEIGHT>
{
    type Witness = IntentAndBalancePublicSettlementWitness<MERKLE_HEIGHT>;
    type Statement = IntentAndBalancePublicSettlementStatement;

    fn name() -> String {
        format!("Intent And Balance Public Settlement ({MERKLE_HEIGHT})")
    }

    /// INTENT AND BALANCE PUBLIC SETTLEMENT has one proof linking group:
    /// - intent_and_balance_public_settlement: The linking group between INTENT
    ///   AND BALANCE VALIDITY and INTENT AND BALANCE PUBLIC SETTLEMENT. This
    ///   group is placed by this circuit.
    fn proof_linking_groups() -> Result<Vec<(String, Option<GroupLayout>)>, PlonkError> {
        // Place the linking group (the intent validity circuit will inherit it)
        Ok(vec![(INTENT_AND_BALANCE_PUBLIC_SETTLEMENT_LINK.to_string(), None)])
    }

    fn apply_constraints(
        mut witness_var: IntentAndBalancePublicSettlementWitnessVar<MERKLE_HEIGHT>,
        statement_var: IntentAndBalancePublicSettlementStatementVar,
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
    use circuit_types::{
        Amount,
        balance::{Balance, PostMatchBalance, PostMatchBalanceShare},
        intent::Intent,
    };
    use constants::Scalar;

    use crate::{
        test_helpers::{
            compute_min_amount_out as shared_compute_min_amount_out,
            create_settlement_obligation_with_balance, random_address, random_amount,
            random_intent, random_scalar,
        },
        zk_circuits::v2::settlement::intent_and_balance_public_settlement::{
            IntentAndBalancePublicSettlementCircuit, IntentAndBalancePublicSettlementStatement,
            IntentAndBalancePublicSettlementWitness,
        },
    };

    // -----------
    // | Helpers |
    // -----------

    /// Check that the constraints are satisfied on the given witness and
    /// statement
    pub fn check_constraints<const MERKLE_HEIGHT: usize>(
        witness: &IntentAndBalancePublicSettlementWitness<MERKLE_HEIGHT>,
        statement: &IntentAndBalancePublicSettlementStatement,
    ) -> bool {
        crate::test_helpers::check_constraints_satisfied::<
            IntentAndBalancePublicSettlementCircuit<MERKLE_HEIGHT>,
        >(witness, statement)
    }

    /// Create a balance that matches the given intent
    ///
    /// The balance will have the same owner and mint as the intent's in_token,
    /// with random values for other fields.
    pub fn create_matching_balance_for_intent(intent: &Intent) -> Balance {
        Balance {
            mint: intent.in_token,
            owner: intent.owner,
            relayer_fee_recipient: random_address(),
            one_time_authority: random_address(),
            relayer_fee_balance: random_amount(),
            protocol_fee_balance: random_amount(),
            amount: random_amount(),
        }
    }

    /// Construct a witness and statement with valid data
    pub fn create_witness_statement<const MERKLE_HEIGHT: usize>() -> (
        IntentAndBalancePublicSettlementWitness<MERKLE_HEIGHT>,
        IntentAndBalancePublicSettlementStatement,
    ) {
        let intent = random_intent();
        create_witness_statement_with_intent::<MERKLE_HEIGHT>(&intent)
    }

    /// Create a witness and statement with the given intent
    pub fn create_witness_statement_with_intent<const MERKLE_HEIGHT: usize>(
        intent: &Intent,
    ) -> (
        IntentAndBalancePublicSettlementWitness<MERKLE_HEIGHT>,
        IntentAndBalancePublicSettlementStatement,
    ) {
        let balance = create_matching_balance_for_intent(intent);
        create_witness_statement_with_intent_and_balance::<MERKLE_HEIGHT>(intent, &balance)
    }

    /// Create a witness and statement with the given intent and balance
    pub fn create_witness_statement_with_intent_and_balance<const MERKLE_HEIGHT: usize>(
        intent: &Intent,
        balance: &Balance,
    ) -> (
        IntentAndBalancePublicSettlementWitness<MERKLE_HEIGHT>,
        IntentAndBalancePublicSettlementStatement,
    ) {
        let settlement_obligation =
            create_settlement_obligation_with_balance(intent, balance.amount);

        // Create the intent amount public shares
        let pre_settlement_amount_public_share = random_scalar();
        let new_amount_public_share =
            pre_settlement_amount_public_share - Scalar::from(settlement_obligation.amount_in);

        // Create the balance post-match shares
        let pre_settlement_post_match = PostMatchBalance::from(balance.clone());
        let pre_settlement_balance_shares = PostMatchBalanceShare {
            amount: Scalar::from(pre_settlement_post_match.amount),
            relayer_fee_balance: Scalar::from(pre_settlement_post_match.relayer_fee_balance),
            protocol_fee_balance: Scalar::from(pre_settlement_post_match.protocol_fee_balance),
        };

        // Create the new balance shares after settlement
        let new_balance_amount = balance.amount - settlement_obligation.amount_in;
        let new_post_match = PostMatchBalance {
            amount: new_balance_amount,
            relayer_fee_balance: pre_settlement_post_match.relayer_fee_balance,
            protocol_fee_balance: pre_settlement_post_match.protocol_fee_balance,
        };
        let new_balance_public_shares = PostMatchBalanceShare {
            amount: Scalar::from(new_post_match.amount),
            relayer_fee_balance: Scalar::from(new_post_match.relayer_fee_balance),
            protocol_fee_balance: Scalar::from(new_post_match.protocol_fee_balance),
        };

        let witness = IntentAndBalancePublicSettlementWitness {
            intent: intent.clone(),
            pre_settlement_amount_public_share,
            balance: balance.clone(),
            pre_settlement_balance_shares,
        };
        let statement = IntentAndBalancePublicSettlementStatement {
            settlement_obligation,
            new_amount_public_share,
            new_balance_public_shares,
        };

        (witness, statement)
    }

    /// Compute the minimum amount out for a given intent and amount in
    pub fn compute_min_amount_out(intent: &Intent, amount_in: Amount) -> Amount {
        shared_compute_min_amount_out(intent, amount_in)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use circuit_types::traits::SingleProverCircuit;
    use constants::MERKLE_HEIGHT;

    /// A helper to print the number of constraints in the circuit
    ///
    /// Useful when benchmarking the circuit
    #[test]
    fn test_n_constraints() {
        let layout =
            IntentAndBalancePublicSettlementCircuit::<MERKLE_HEIGHT>::get_circuit_layout().unwrap();

        let n_gates = layout.n_gates;
        let circuit_size = layout.circuit_size();
        println!("Number of constraints: {n_gates}");
        println!("Next power of two: {circuit_size}");
    }

    /// Test that constraints are satisfied on a valid witness and statement
    #[test]
    fn test_valid_intent_and_balance_public_settlement_constraints() {
        let (witness, statement) = test_helpers::create_witness_statement::<MERKLE_HEIGHT>();
        assert!(test_helpers::check_constraints::<MERKLE_HEIGHT>(&witness, &statement));
    }
}
