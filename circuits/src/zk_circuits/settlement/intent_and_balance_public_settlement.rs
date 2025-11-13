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
    zk_circuits::settlement::OUTPUT_BALANCE_SETTLEMENT_LINK,
    zk_gadgets::{
        bitlength::AmountGadget,
        comparators::{EqGadget, GreaterThanEqGadget},
        fixed_point::FixedPointGadget,
    },
};

// ----------------------
// | Circuit Definition |
// ----------------------

/// The `INTENT AND BALANCE PUBLIC SETTLEMENT` circuit
pub struct IntentAndBalancePublicSettlementCircuit;
impl IntentAndBalancePublicSettlementCircuit {
    /// Apply the circuit constraints to a given constraint system
    pub fn circuit(
        statement: &IntentAndBalancePublicSettlementStatementVar,
        witness: &mut IntentAndBalancePublicSettlementWitnessVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // 1. Verify the constraints imposed by both the intent and the balance
        Self::verify_intent_constraints(statement, witness, cs)?;
        Self::verify_in_balance_constraints(statement, witness, cs)?;
        Self::verify_out_balance_constraints(statement, witness, cs)?;

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

        // Input balance update
        let mut expected_shares = witness.pre_settlement_in_balance_shares.clone();
        expected_shares.amount = cs.sub(
            witness.pre_settlement_in_balance_shares.amount,
            statement.settlement_obligation.amount_in,
        )?;
        EqGadget::constrain_eq(&expected_shares, &statement.new_in_balance_public_shares, cs)?;

        // Output balance update
        // TODO: Add fees
        let mut expected_shares = witness.pre_settlement_out_balance_shares.clone();
        expected_shares.amount = cs.add(
            witness.pre_settlement_out_balance_shares.amount,
            statement.settlement_obligation.amount_out,
        )?;
        EqGadget::constrain_eq(&expected_shares, &statement.new_out_balance_public_shares, cs)?;

        Ok(())
    }

    /// Verify that the intent's constraints are satisfied
    pub fn verify_intent_constraints(
        statement: &IntentAndBalancePublicSettlementStatementVar,
        witness: &IntentAndBalancePublicSettlementWitnessVar,
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
    pub fn verify_in_balance_constraints(
        statement: &IntentAndBalancePublicSettlementStatementVar,
        witness: &IntentAndBalancePublicSettlementWitnessVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let in_balance = &witness.in_balance;
        let obligation = &statement.settlement_obligation;

        // The balance must exceed the obligation's input amount
        GreaterThanEqGadget::constrain_greater_than_eq(
            in_balance.amount,
            obligation.amount_in,
            AMOUNT_BITS,
            cs,
        )
    }

    /// Verify receive balance constraints
    pub fn verify_out_balance_constraints(
        statement: &IntentAndBalancePublicSettlementStatementVar,
        witness: &IntentAndBalancePublicSettlementWitnessVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let intent = &witness.intent;
        let out_balance = &witness.out_balance;
        let obligation = &statement.settlement_obligation;

        // The output balance's mint must match the obligation's output token
        EqGadget::constrain_eq(&out_balance.mint, &obligation.output_token, cs)?;

        // The output amount must not overflow the receive balance
        let new_bal_amount = cs.add(out_balance.amount, obligation.amount_out)?;
        AmountGadget::constrain_valid_amount(new_bal_amount, cs)?;

        // The output balance must be owned by the intent's owner
        EqGadget::constrain_eq(&out_balance.owner, &intent.owner, cs)
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for `INTENT AND BALANCE PUBLIC SETTLEMENT`
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntentAndBalancePublicSettlementWitness {
    /// The intent which this circuit is settling a match for
    ///
    /// This value is proof-linked from the `INTENT AND BALANCE VALIDITY`
    /// circuit
    #[link_groups = "intent_and_balance_settlement"]
    pub intent: Intent,
    /// The pre-update public share of the intent's amount
    ///
    /// This should match the `new_amount_public_share` from the intent validity
    /// proof that authorized this settlement
    #[link_groups = "intent_and_balance_settlement"]
    pub pre_settlement_amount_public_share: Scalar,
    /// The balance which capitalizes the intent
    ///
    /// This value is proof-linked from the `INTENT AND BALANCE VALIDITY`
    /// circuit
    #[link_groups = "intent_and_balance_settlement"]
    pub in_balance: Balance,
    /// The balance public shares which are updated in the settlement circuit
    ///
    /// This value is proof-linked from the `INTENT AND BALANCE VALIDITY`
    /// circuit
    #[link_groups = "intent_and_balance_settlement"]
    pub pre_settlement_in_balance_shares: PostMatchBalanceShare,
    /// The balance which receives the output tokens of the obligation
    ///
    /// This value is proof-linked from the `INTENT AND BALANCE VALIDITY`
    /// circuit
    #[link_groups = "output_balance_settlement"]
    pub out_balance: Balance,
    /// The balance public shares which are updated in the settlement circuit
    /// for the output balance
    ///
    /// This value is proof-linked from the `INTENT AND BALANCE VALIDITY`
    /// circuit
    #[link_groups = "output_balance_settlement"]
    pub pre_settlement_out_balance_shares: PostMatchBalanceShare,
}

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
    /// The updated public shares of the post-match balance fields for the input
    /// balance
    pub new_in_balance_public_shares: PostMatchBalanceShare,
    /// The updated public shares of the post-match balance fields for the
    /// output balance
    pub new_out_balance_public_shares: PostMatchBalanceShare,
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl SingleProverCircuit for IntentAndBalancePublicSettlementCircuit {
    type Witness = IntentAndBalancePublicSettlementWitness;
    type Statement = IntentAndBalancePublicSettlementStatement;

    fn name() -> String {
        format!("Intent And Balance Public Settlement ({MERKLE_HEIGHT})")
    }

    /// INTENT AND BALANCE PUBLIC SETTLEMENT has two proof linking groups:
    /// - intent_and_balance_settlement: The linking group between INTENT AND
    ///   BALANCE VALIDITY and INTENT AND BALANCE PUBLIC SETTLEMENT. This group
    ///   is placed by this circuit.
    /// - out_balance_settlement: The linking group between INTENT AND BALANCE
    ///   PUBLIC SETTLEMENT and the output balance. This group is placed by this
    ///   circuit.
    fn proof_linking_groups() -> Result<Vec<(String, Option<GroupLayout>)>, PlonkError> {
        // Place the linking groups (the validity circuits will inherit them)
        Ok(vec![
            (INTENT_AND_BALANCE_PUBLIC_SETTLEMENT_LINK.to_string(), None),
            (OUTPUT_BALANCE_SETTLEMENT_LINK.to_string(), None),
        ])
    }

    fn apply_constraints(
        mut witness_var: IntentAndBalancePublicSettlementWitnessVar,
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
        balance::{Balance, PostMatchBalanceShare},
        intent::Intent,
        max_amount,
        settlement_obligation::SettlementObligation,
    };
    use constants::Scalar;
    use rand::{Rng, thread_rng};

    use crate::{
        test_helpers::{
            create_settlement_obligation_with_balance, random_address, random_amount,
            random_intent, random_scalar,
        },
        zk_circuits::settlement::intent_and_balance_public_settlement::{
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
        witness: &IntentAndBalancePublicSettlementWitness,
        statement: &IntentAndBalancePublicSettlementStatement,
    ) -> bool {
        crate::test_helpers::check_constraints_satisfied::<IntentAndBalancePublicSettlementCircuit>(
            witness, statement,
        )
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
    pub fn create_witness_statement<const MERKLE_HEIGHT: usize>()
    -> (IntentAndBalancePublicSettlementWitness, IntentAndBalancePublicSettlementStatement) {
        let intent = random_intent();
        create_witness_statement_with_intent::<MERKLE_HEIGHT>(&intent)
    }

    /// Create a witness and statement with the given intent
    pub fn create_witness_statement_with_intent<const MERKLE_HEIGHT: usize>(
        intent: &Intent,
    ) -> (IntentAndBalancePublicSettlementWitness, IntentAndBalancePublicSettlementStatement) {
        let balance = create_matching_balance_for_intent(intent);
        create_witness_statement_with_intent_and_balance::<MERKLE_HEIGHT>(intent, &balance)
    }

    /// Create a witness and statement with the given intent and balance
    pub fn create_witness_statement_with_intent_and_balance<const MERKLE_HEIGHT: usize>(
        intent: &Intent,
        balance: &Balance,
    ) -> (IntentAndBalancePublicSettlementWitness, IntentAndBalancePublicSettlementStatement) {
        let settlement_obligation =
            create_settlement_obligation_with_balance(intent, balance.amount);

        create_witness_statement_with_intent_balance_and_obligation::<MERKLE_HEIGHT>(
            intent,
            balance,
            settlement_obligation,
        )
    }

    /// Create a witness and statement for a given intent, balance, and
    /// settlement obligation
    pub fn create_witness_statement_with_intent_balance_and_obligation<
        const MERKLE_HEIGHT: usize,
    >(
        intent: &Intent,
        balance: &Balance,
        settlement_obligation: SettlementObligation,
    ) -> (IntentAndBalancePublicSettlementWitness, IntentAndBalancePublicSettlementStatement) {
        // Create the intent amount public shares
        let amount_in = Scalar::from(settlement_obligation.amount_in);
        let amount_out = Scalar::from(settlement_obligation.amount_out);
        let receive_balance = create_receive_balance(&settlement_obligation);
        let pre_settlement_amount_public_share = random_scalar();
        let new_amount_public_share = pre_settlement_amount_public_share - amount_in;

        // Create the balance post-match shares
        let pre_settlement_in_balance_shares = random_post_match_balance_share();
        let pre_settlement_out_balance_shares = random_post_match_balance_share();

        // Create the new balance shares after settlement
        let new_in_balance_public_shares = PostMatchBalanceShare {
            amount: pre_settlement_in_balance_shares.amount - amount_in,
            relayer_fee_balance: pre_settlement_in_balance_shares.relayer_fee_balance,
            protocol_fee_balance: pre_settlement_in_balance_shares.protocol_fee_balance,
        };

        let new_out_balance_public_shares = PostMatchBalanceShare {
            amount: pre_settlement_out_balance_shares.amount + amount_out,
            relayer_fee_balance: pre_settlement_out_balance_shares.relayer_fee_balance,
            protocol_fee_balance: pre_settlement_out_balance_shares.protocol_fee_balance,
        };

        let witness = IntentAndBalancePublicSettlementWitness {
            intent: intent.clone(),
            pre_settlement_amount_public_share,
            in_balance: balance.clone(),
            pre_settlement_in_balance_shares,
            out_balance: receive_balance,
            pre_settlement_out_balance_shares,
        };
        let statement = IntentAndBalancePublicSettlementStatement {
            settlement_obligation,
            new_amount_public_share,
            new_in_balance_public_shares,
            new_out_balance_public_shares,
        };

        (witness, statement)
    }

    /// Create a random post-match balance share
    pub fn random_post_match_balance_share() -> PostMatchBalanceShare {
        PostMatchBalanceShare {
            amount: random_scalar(),
            relayer_fee_balance: random_scalar(),
            protocol_fee_balance: random_scalar(),
        }
    }

    /// Create a receive balance for the given obligation
    pub fn create_receive_balance(obligation: &SettlementObligation) -> Balance {
        let mut rng = thread_rng();
        let max_existing_balance = max_amount() - obligation.amount_out;
        let amount = rng.gen_range(0..=max_existing_balance);

        Balance {
            mint: obligation.output_token,
            owner: random_address(),
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
    use crate::{
        test_helpers::{
            compute_min_amount_out, create_settlement_obligation_with_balance, random_address,
            random_bounded_intent, random_scalar,
        },
        zk_circuits::settlement::intent_and_balance_public_settlement::test_helpers::create_matching_balance_for_intent,
    };

    use super::*;
    use circuit_types::{Amount, max_amount, traits::SingleProverCircuit};
    use constants::MERKLE_HEIGHT;
    use rand::{Rng, thread_rng};

    /// The maximum input amount for intents; this leaves room for the whole
    /// intent to be executed at sampled prices; i.e. `amount_out` does not
    /// violate `AMOUNT_BITS` bounds.
    const MAX_AMOUNT_IN: Amount = 1u128 << (AMOUNT_BITS / 2);

    /// A helper to print the number of constraints in the circuit
    ///
    /// Useful when benchmarking the circuit
    #[test]
    fn test_n_constraints() {
        let layout = IntentAndBalancePublicSettlementCircuit::get_circuit_layout().unwrap();

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

    /// Test the case in which the intent is fully matched
    #[test]
    fn test_valid_intent_and_balance_public_settlement_constraints_full_match() {
        let intent = random_bounded_intent(MAX_AMOUNT_IN);
        let mut balance = create_matching_balance_for_intent(&intent);
        balance.amount = intent.amount_in;
        let mut obligation = create_settlement_obligation_with_balance(&intent, balance.amount);
        obligation.amount_out = compute_min_amount_out(&intent, obligation.amount_in);

        let (witness, statement) =
            test_helpers::create_witness_statement_with_intent_balance_and_obligation::<
                MERKLE_HEIGHT,
            >(&intent, &balance, obligation);
        assert!(test_helpers::check_constraints::<MERKLE_HEIGHT>(&witness, &statement));
    }

    /// Test the case in which the balance undercapitalizes the obligation
    #[test]
    fn test_valid_intent_and_balance_public_settlement_constraints_undercapitalized() {
        let intent = random_bounded_intent(MAX_AMOUNT_IN);
        let mut balance = create_matching_balance_for_intent(&intent);
        balance.amount = intent.amount_in / 2;
        let obligation = create_settlement_obligation_with_balance(&intent, balance.amount);

        let (witness, statement) =
            test_helpers::create_witness_statement_with_intent_balance_and_obligation::<
                MERKLE_HEIGHT,
            >(&intent, &balance, obligation);
        assert!(test_helpers::check_constraints::<MERKLE_HEIGHT>(&witness, &statement));
    }

    // --- Invalid Test Cases --- //

    /// Test the case in which the obligation pair doesn't match that of the
    /// intent
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_obligation__pair_mismatch() {
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
    #[allow(non_snake_case)]
    fn test_invalid_obligation__amount_in_exceeds_intent_size() {
        let intent = random_bounded_intent(MAX_AMOUNT_IN);
        let mut balance = create_matching_balance_for_intent(&intent);
        balance.amount = intent.amount_in + 1; // Fully capitalize the intent   
        let mut obligation = create_settlement_obligation_with_balance(&intent, balance.amount);
        obligation.amount_in = intent.amount_in + 1;
        obligation.amount_out = compute_min_amount_out(&intent, obligation.amount_in);

        // Check that the constraints are not satisfied
        let (witness, statement) =
            test_helpers::create_witness_statement_with_intent_balance_and_obligation::<
                MERKLE_HEIGHT,
            >(&intent, &balance, obligation);
        assert!(!test_helpers::check_constraints::<MERKLE_HEIGHT>(&witness, &statement));
    }

    /// Test the case in which the obligation attempts to settle at a worse
    /// price than the intent's min price
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_obligation__amount_out_violates_min_price() {
        let intent = random_bounded_intent(MAX_AMOUNT_IN);
        let mut balance = create_matching_balance_for_intent(&intent);
        balance.amount = intent.amount_in;
        let mut obligation = create_settlement_obligation_with_balance(&intent, balance.amount);
        obligation.amount_out = compute_min_amount_out(&intent, obligation.amount_in) - 1;

        // Check that the constraints are not satisfied
        let (witness, statement) =
            test_helpers::create_witness_statement_with_intent_balance_and_obligation::<
                MERKLE_HEIGHT,
            >(&intent, &balance, obligation);
        assert!(!test_helpers::check_constraints::<MERKLE_HEIGHT>(&witness, &statement));
    }

    /// Test an undercapitalized obligation
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_obligation__undercapitalized() {
        let intent = random_bounded_intent(MAX_AMOUNT_IN);
        let mut balance = create_matching_balance_for_intent(&intent);
        balance.amount = intent.amount_in - 1;
        let mut obligation = create_settlement_obligation_with_balance(&intent, balance.amount);
        obligation.amount_in = intent.amount_in;

        // Check that the constraints are not satisfied
        let (witness, statement) =
            test_helpers::create_witness_statement_with_intent_balance_and_obligation::<
                MERKLE_HEIGHT,
            >(&intent, &balance, obligation);
        assert!(!test_helpers::check_constraints::<MERKLE_HEIGHT>(&witness, &statement));
    }

    /// Test the case in which the output balance's owner does not match the
    /// intent's owner
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_obligation__output_balance_owner_mismatch() {
        let (mut witness, statement) = test_helpers::create_witness_statement::<MERKLE_HEIGHT>();
        witness.out_balance.owner = random_address();
        assert!(!test_helpers::check_constraints::<MERKLE_HEIGHT>(&witness, &statement));
    }

    /// Test the case in which the output balance's mint does not match the
    /// obligation's output token
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_obligation__output_balance_mint_mismatch() {
        let (mut witness, statement) = test_helpers::create_witness_statement::<MERKLE_HEIGHT>();
        witness.out_balance.mint = random_address();
        assert!(!test_helpers::check_constraints::<MERKLE_HEIGHT>(&witness, &statement));
    }

    /// Test the case in which the output balance overflows
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_obligation__output_balance_overflows() {
        let (mut witness, statement) = test_helpers::create_witness_statement::<MERKLE_HEIGHT>();

        let max_amount_out = max_amount() - statement.settlement_obligation.amount_out;
        witness.out_balance.amount = max_amount_out + 1;

        // Check that the constraints are not satisfied
        assert!(!test_helpers::check_constraints::<MERKLE_HEIGHT>(&witness, &statement));
    }

    // --- Invalid State Updates --- //

    /// Test the case in which the intent's amount public share is modified
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_update__intent_amount_public_share_modified() {
        let (witness, mut statement) = test_helpers::create_witness_statement::<MERKLE_HEIGHT>();
        statement.new_amount_public_share = random_scalar();
        assert!(!test_helpers::check_constraints::<MERKLE_HEIGHT>(&witness, &statement));
    }

    /// Test the case in which the balance's public shares are modified
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_update__balance_public_shares_modified() {
        let mut rng = thread_rng();
        let (witness, mut statement) = test_helpers::create_witness_statement::<MERKLE_HEIGHT>();

        let mut balance_scalars = statement.new_in_balance_public_shares.to_scalars();
        let idx = rng.gen_range(0..balance_scalars.len());
        balance_scalars[idx] = random_scalar();
        statement.new_in_balance_public_shares =
            PostMatchBalanceShare::from_scalars(&mut balance_scalars.into_iter());

        assert!(!test_helpers::check_constraints::<MERKLE_HEIGHT>(&witness, &statement));
    }

    /// Test the case in which the output balance's public shares are modified
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_update__out_balance_public_shares_modified() {
        let mut rng = thread_rng();
        let (witness, mut statement) = test_helpers::create_witness_statement::<MERKLE_HEIGHT>();

        let mut out_balance_scalars = statement.new_out_balance_public_shares.to_scalars();
        let idx = rng.gen_range(0..out_balance_scalars.len());
        out_balance_scalars[idx] = random_scalar();
        statement.new_out_balance_public_shares =
            PostMatchBalanceShare::from_scalars(&mut out_balance_scalars.into_iter());

        assert!(!test_helpers::check_constraints::<MERKLE_HEIGHT>(&witness, &statement));
    }
}
