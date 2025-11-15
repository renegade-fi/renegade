//! Defines the circuitry for a public settlement of an intent and balance
//!
//! This settlement is performed by a relayer cluster, and is used to settle an
//! intent and balance pair

use circuit_macros::circuit_type;
use circuit_types::{
    PlonkCircuit,
    balance::{Balance, PostMatchBalanceShare},
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

use crate::{
    SingleProverCircuit,
    zk_circuits::settlement::{
        INTENT_AND_BALANCE_SETTLEMENT_PARTY0_LINK, OUTPUT_BALANCE_SETTLEMENT_PARTY0_LINK,
        intent_and_balance_private_settlement::IntentAndBalancePrivateSettlementCircuit,
        settlement_lib::SettlementGadget,
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
        SettlementGadget::verify_intent_and_balance_obligation_constraints(
            &witness.intent,
            &witness.in_balance,
            &witness.out_balance,
            &statement.settlement_obligation,
            cs,
        )?;

        // 2. Verify the update to the intent and balance shares
        SettlementGadget::verify_state_updates(
            witness.pre_settlement_amount_public_share,
            statement.new_amount_public_share,
            &witness.pre_settlement_in_balance_shares,
            &statement.new_in_balance_public_shares,
            &witness.pre_settlement_out_balance_shares,
            &statement.new_out_balance_public_shares,
            &statement.settlement_obligation,
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
pub struct IntentAndBalancePublicSettlementWitness {
    /// The intent which this circuit is settling a match for
    ///
    /// This value is proof-linked from the `INTENT AND BALANCE VALIDITY`
    /// circuit
    #[link_groups = "intent_and_balance_settlement_party0"]
    pub intent: Intent,
    /// The pre-update public share of the intent's amount
    ///
    /// This should match the `new_amount_public_share` from the intent validity
    /// proof that authorized this settlement
    #[link_groups = "intent_and_balance_settlement_party0"]
    pub pre_settlement_amount_public_share: Scalar,
    /// The balance which capitalizes the intent
    ///
    /// This value is proof-linked from the `INTENT AND BALANCE VALIDITY`
    /// circuit
    #[link_groups = "intent_and_balance_settlement_party0"]
    pub in_balance: Balance,
    /// The balance public shares which are updated in the settlement circuit
    ///
    /// This value is proof-linked from the `INTENT AND BALANCE VALIDITY`
    /// circuit
    #[link_groups = "intent_and_balance_settlement_party0"]
    pub pre_settlement_in_balance_shares: PostMatchBalanceShare,
    /// The balance which receives the output tokens of the obligation
    ///
    /// This value is proof-linked from the `INTENT AND BALANCE VALIDITY`
    /// circuit
    #[link_groups = "output_balance_settlement_party0"]
    pub out_balance: Balance,
    /// The balance public shares which are updated in the settlement circuit
    /// for the output balance
    ///
    /// This value is proof-linked from the `INTENT AND BALANCE VALIDITY`
    /// circuit
    #[link_groups = "output_balance_settlement_party0"]
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
    /// The relayer fee which is charged for the settlement
    ///
    /// We place this field in the statement so that it is included in the
    /// Fiat-Shamir transcript and therefore is not malleable transaction
    /// calldata. This allows the relayer to set the fee and be sure it cannot
    /// be modified by mempool observers.
    pub relayer_fee: FixedPoint,
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
    ///
    /// Because this settlement circuit only settles one user's intent and
    /// balance, we use the party 0 link groups.
    fn proof_linking_groups() -> Result<Vec<(String, Option<GroupLayout>)>, PlonkError> {
        let layout = IntentAndBalancePrivateSettlementCircuit::get_circuit_layout()?;
        let intent_and_balance = layout.get_group_layout(INTENT_AND_BALANCE_SETTLEMENT_PARTY0_LINK);
        let output_balance = layout.get_group_layout(OUTPUT_BALANCE_SETTLEMENT_PARTY0_LINK);
        Ok(vec![
            (INTENT_AND_BALANCE_SETTLEMENT_PARTY0_LINK.to_string(), Some(intent_and_balance)),
            (OUTPUT_BALANCE_SETTLEMENT_PARTY0_LINK.to_string(), Some(output_balance)),
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
    use alloy_primitives::Address;
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
            create_settlement_obligation_with_balance, random_address, random_amount, random_fee,
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
        let receive_balance = create_receive_balance(intent.owner, &settlement_obligation);
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
            relayer_fee: random_fee(),
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
    pub fn create_receive_balance(owner: Address, obligation: &SettlementObligation) -> Balance {
        let mut rng = thread_rng();
        let max_existing_balance = max_amount() - obligation.amount_out;
        let amount = rng.gen_range(0..=max_existing_balance);

        Balance {
            mint: obligation.output_token,
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
    use crate::{
        test_helpers::{
            compute_min_amount_out, create_settlement_obligation_with_balance, random_address,
            random_scalar, random_small_intent,
        },
        zk_circuits::settlement::intent_and_balance_public_settlement::test_helpers::create_matching_balance_for_intent,
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
        let intent = random_small_intent();
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
        let intent = random_small_intent();
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
        let intent = random_small_intent();
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
        let intent = random_small_intent();
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
        let intent = random_small_intent();
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
