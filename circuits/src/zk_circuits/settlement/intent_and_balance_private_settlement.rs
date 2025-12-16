//! Defines the circuitry for a private settlement of an intent and balance
//!
//! This settlement is performed by a relayer cluster, and is used to settle an
//! intent and balance pair with private obligations

use circuit_macros::circuit_type;
use circuit_types::{
    PlonkCircuit,
    balance::{Balance, PostMatchBalanceShare},
    fee::FeeRatesVar,
    fixed_point::FixedPoint,
    intent::Intent,
    settlement_obligation::SettlementObligation,
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
        INTENT_AND_BALANCE_SETTLEMENT_PARTY0_LINK, INTENT_AND_BALANCE_SETTLEMENT_PARTY1_LINK,
        OUTPUT_BALANCE_SETTLEMENT_PARTY0_LINK, OUTPUT_BALANCE_SETTLEMENT_PARTY1_LINK,
        settlement_lib::SettlementGadget,
    },
    zk_gadgets::{comparators::EqGadget, primitives::bitlength::AmountGadget},
};

// ----------------------
// | Circuit Definition |
// ----------------------

/// The `INTENT AND BALANCE PRIVATE SETTLEMENT` circuit
pub struct IntentAndBalancePrivateSettlementCircuit;
impl IntentAndBalancePrivateSettlementCircuit {
    /// Apply the circuit constraints to a given constraint system
    pub fn circuit(
        statement: &IntentAndBalancePrivateSettlementStatementVar,
        witness: &mut IntentAndBalancePrivateSettlementWitnessVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // 1. Verify that the two settlement obligations are compatible with one another
        Self::validate_obligation_compatibility(witness, cs)?;

        // 2. Verify the settlement obligation constraints for each party
        // Party 0
        SettlementGadget::verify_intent_and_balance_obligation_constraints(
            &witness.intent0,
            &witness.input_balance0,
            &witness.output_balance0,
            &witness.settlement_obligation0,
            cs,
        )?;

        // Party 1
        SettlementGadget::verify_intent_and_balance_obligation_constraints(
            &witness.intent1,
            &witness.input_balance1,
            &witness.output_balance1,
            &witness.settlement_obligation1,
            cs,
        )?;

        // 3. Verify the state updates for each party
        let fee_rate0 = FeeRatesVar {
            relayer_fee_rate: statement.relayer_fee0,
            protocol_fee_rate: statement.protocol_fee,
        };
        let fee_rate1 = FeeRatesVar {
            relayer_fee_rate: statement.relayer_fee1,
            protocol_fee_rate: statement.protocol_fee,
        };

        // Party 0
        SettlementGadget::verify_state_updates(
            &fee_rate0,
            witness.pre_settlement_amount_public_share0,
            statement.new_amount_public_share0,
            &witness.pre_settlement_in_balance_shares0,
            &statement.new_in_balance_public_shares0,
            &witness.pre_settlement_out_balance_shares0,
            &statement.new_out_balance_public_shares0,
            &witness.settlement_obligation0,
            cs,
        )?;

        // Party 1
        SettlementGadget::verify_state_updates(
            &fee_rate1,
            witness.pre_settlement_amount_public_share1,
            statement.new_amount_public_share1,
            &witness.pre_settlement_in_balance_shares1,
            &statement.new_in_balance_public_shares1,
            &witness.pre_settlement_out_balance_shares1,
            &statement.new_out_balance_public_shares1,
            &witness.settlement_obligation1,
            cs,
        )
    }

    /// Verify that the two settlement obligations are compatible with one
    /// another
    pub fn validate_obligation_compatibility(
        witness: &IntentAndBalancePrivateSettlementWitnessVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let obligation0 = &witness.settlement_obligation0;
        let obligation1 = &witness.settlement_obligation1;

        // 1. The amounts on the obligation must be of valid bitlengths
        AmountGadget::constrain_valid_amount(obligation0.amount_in, cs)?;
        AmountGadget::constrain_valid_amount(obligation0.amount_out, cs)?;
        AmountGadget::constrain_valid_amount(obligation1.amount_in, cs)?;
        AmountGadget::constrain_valid_amount(obligation1.amount_out, cs)?;

        // 2. The input and output tokens of the two obligations must align
        EqGadget::constrain_eq(&obligation0.input_token, &obligation1.output_token, cs)?;
        EqGadget::constrain_eq(&obligation0.output_token, &obligation1.input_token, cs)?;

        // 3. The input and output amounts of the two obligations must align
        EqGadget::constrain_eq(&obligation0.amount_in, &obligation1.amount_out, cs)?;
        EqGadget::constrain_eq(&obligation0.amount_out, &obligation1.amount_in, cs)
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for `INTENT AND BALANCE PRIVATE SETTLEMENT`
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntentAndBalancePrivateSettlementWitness {
    // --- First Party --- //
    // The first party's settlement obligation
    pub settlement_obligation0: SettlementObligation,
    /// The first party's intent
    #[link_groups = "intent_and_balance_settlement_party0"]
    pub intent0: Intent,
    /// The pre-update public shares of the first party's intent amount
    #[link_groups = "intent_and_balance_settlement_party0"]
    pub pre_settlement_amount_public_share0: Scalar,
    /// The first party's input balance
    #[link_groups = "intent_and_balance_settlement_party0"]
    pub input_balance0: Balance,
    /// The pre-update public shares of the first party's input balance
    #[link_groups = "intent_and_balance_settlement_party0"]
    pub pre_settlement_in_balance_shares0: PostMatchBalanceShare,
    /// The first party's output balance
    #[link_groups = "output_balance_settlement_party0"]
    pub output_balance0: Balance,
    /// The pre-update public shares of the first party's output balance
    #[link_groups = "output_balance_settlement_party0"]
    pub pre_settlement_out_balance_shares0: PostMatchBalanceShare,

    // --- Second Party --- //
    /// The second party's settlement obligation
    pub settlement_obligation1: SettlementObligation,
    /// The second party's intent
    #[link_groups = "intent_and_balance_settlement_party1"]
    pub intent1: Intent,
    /// The pre-update public shares of the second party's intent amount
    #[link_groups = "intent_and_balance_settlement_party1"]
    pub pre_settlement_amount_public_share1: Scalar,
    /// The second party's input balance
    #[link_groups = "intent_and_balance_settlement_party1"]
    pub input_balance1: Balance,
    /// The pre-update public shares of the second party's input balance
    #[link_groups = "intent_and_balance_settlement_party1"]
    pub pre_settlement_in_balance_shares1: PostMatchBalanceShare,
    /// The second party's output balance
    #[link_groups = "output_balance_settlement_party1"]
    pub output_balance1: Balance,
    /// The pre-update public shares of the second party's output balance
    #[link_groups = "output_balance_settlement_party1"]
    pub pre_settlement_out_balance_shares1: PostMatchBalanceShare,
}

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for `INTENT AND BALANCE PRIVATE SETTLEMENT`
#[circuit_type(singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntentAndBalancePrivateSettlementStatement {
    // --- First Party --- //
    /// The updated public share of the first party's intent amount
    pub new_amount_public_share0: Scalar,
    /// The updated public shares of the first party's input balance
    pub new_in_balance_public_shares0: PostMatchBalanceShare,
    /// The updated public shares of the first party's output balance
    pub new_out_balance_public_shares0: PostMatchBalanceShare,

    // --- Second Party --- //
    /// The updated public share of the second party's intent amount
    pub new_amount_public_share1: Scalar,
    /// The updated public shares of the second party's input balance
    pub new_in_balance_public_shares1: PostMatchBalanceShare,
    /// The updated public shares of the second party's output balance
    pub new_out_balance_public_shares1: PostMatchBalanceShare,

    // --- Fees --- //
    /// The relayer fee applied to the first party's match
    pub relayer_fee0: FixedPoint,
    /// The relayer fee applied to the second party's match
    pub relayer_fee1: FixedPoint,
    /// The protocol fee applied to the match
    ///
    /// This is the same for both parties
    pub protocol_fee: FixedPoint,
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl SingleProverCircuit for IntentAndBalancePrivateSettlementCircuit {
    type Witness = IntentAndBalancePrivateSettlementWitness;
    type Statement = IntentAndBalancePrivateSettlementStatement;

    fn name() -> String {
        "Intent And Balance Private Settlement".to_string()
    }

    /// This circuit has four linking groups:
    /// - intent_and_balance_settlement_party0: The linking group between INTENT
    ///   AND BALANCE PRIVATE SETTLEMENT and the first party's intent and
    ///   balance
    /// - intent_and_balance_settlement_party1: The linking group between INTENT
    ///   AND BALANCE PRIVATE SETTLEMENT and the second party's intent and
    ///   balance
    /// - output_balance_settlement_party0: The linking group between INTENT AND
    ///   BALANCE PRIVATE SETTLEMENT and the first party's output balance
    /// - output_balance_settlement_party1: The linking group between INTENT AND
    ///   BALANCE PRIVATE SETTLEMENT and the second party's output balance
    ///
    /// This circuit places all its proof-linking groups and all other circuits
    /// inherit this layout.
    fn proof_linking_groups() -> Result<Vec<(String, Option<GroupLayout>)>, PlonkError> {
        Ok(vec![
            (INTENT_AND_BALANCE_SETTLEMENT_PARTY0_LINK.to_string(), None),
            (INTENT_AND_BALANCE_SETTLEMENT_PARTY1_LINK.to_string(), None),
            (OUTPUT_BALANCE_SETTLEMENT_PARTY0_LINK.to_string(), None),
            (OUTPUT_BALANCE_SETTLEMENT_PARTY1_LINK.to_string(), None),
        ])
    }

    fn apply_constraints(
        mut witness_var: IntentAndBalancePrivateSettlementWitnessVar,
        statement_var: IntentAndBalancePrivateSettlementStatementVar,
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
        fee::FeeRates,
        fixed_point::FixedPoint,
        intent::Intent,
        max_amount,
        settlement_obligation::SettlementObligation,
    };
    use constants::Scalar;
    use rand::{Rng, thread_rng};

    use crate::{
        test_helpers::{
            random_address, random_amount, random_fee, random_post_match_balance_share,
            random_scalar,
        },
        zk_circuits::settlement::intent_and_balance_private_settlement::{
            IntentAndBalancePrivateSettlementCircuit, IntentAndBalancePrivateSettlementStatement,
            IntentAndBalancePrivateSettlementWitness,
        },
    };

    // -----------
    // | Helpers |
    // -----------

    /// Check that the constraints are satisfied on the given witness and
    /// statement
    pub fn check_constraints(
        witness: &IntentAndBalancePrivateSettlementWitness,
        statement: &IntentAndBalancePrivateSettlementStatement,
    ) -> bool {
        crate::test_helpers::check_constraints_satisfied::<IntentAndBalancePrivateSettlementCircuit>(
            witness, statement,
        )
    }

    /// Construct a witness and statement with valid data
    pub fn create_witness_statement()
    -> (IntentAndBalancePrivateSettlementWitness, IntentAndBalancePrivateSettlementStatement) {
        // Create the intents, balances, and obligations
        let (intent0, intent1, obligation0, obligation1) = create_compatible_intents();
        let input_balance0 = create_send_balance(intent0.owner, &obligation0);
        let input_balance1 = create_send_balance(intent1.owner, &obligation1);
        let output_balance0 = create_receive_balance(intent0.owner, &obligation0);
        let output_balance1 = create_receive_balance(intent1.owner, &obligation1);
        let relayer_fee0 = random_fee();
        let relayer_fee1 = random_fee();
        let protocol_fee = random_fee();

        // Create the pre- and post-update shares
        let pre_settlement_amount_public_share0 = random_scalar();
        let pre_settlement_amount_public_share1 = random_scalar();
        let pre_settlement_in_balance_shares0 = random_post_match_balance_share();
        let pre_settlement_in_balance_shares1 = random_post_match_balance_share();
        let pre_settlement_out_balance_shares0 = random_post_match_balance_share();
        let pre_settlement_out_balance_shares1 = random_post_match_balance_share();

        // Update the public shares of the intents and input balances
        let new_amount_public_share0 =
            pre_settlement_amount_public_share0 - Scalar::from(obligation0.amount_in);
        let new_amount_public_share1 =
            pre_settlement_amount_public_share1 - Scalar::from(obligation1.amount_in);
        let new_in_balance_public_shares0 = PostMatchBalanceShare {
            amount: pre_settlement_in_balance_shares0.amount - Scalar::from(obligation0.amount_in),
            relayer_fee_balance: pre_settlement_in_balance_shares0.relayer_fee_balance,
            protocol_fee_balance: pre_settlement_in_balance_shares0.protocol_fee_balance,
        };
        let new_in_balance_public_shares1 = PostMatchBalanceShare {
            amount: pre_settlement_in_balance_shares1.amount - Scalar::from(obligation1.amount_in),
            relayer_fee_balance: pre_settlement_in_balance_shares1.relayer_fee_balance,
            protocol_fee_balance: pre_settlement_in_balance_shares1.protocol_fee_balance,
        };

        // Update the public shares of the output balances
        let fee_rates0 = FeeRates::new(relayer_fee0, protocol_fee);
        let fee_rates1 = FeeRates::new(relayer_fee1, protocol_fee);
        let fee_take0 = fee_rates0.compute_fee_take(obligation0.amount_out);
        let fee_take1 = fee_rates1.compute_fee_take(obligation1.amount_out);
        let net_receive0 = obligation0.amount_out - fee_take0.total();
        let net_receive1 = obligation1.amount_out - fee_take1.total();

        let mut new_out_balance_public_shares0 = pre_settlement_out_balance_shares0.clone();
        new_out_balance_public_shares0.amount += Scalar::from(net_receive0);
        new_out_balance_public_shares0.relayer_fee_balance += Scalar::from(fee_take0.relayer_fee);
        new_out_balance_public_shares0.protocol_fee_balance += Scalar::from(fee_take0.protocol_fee);

        let mut new_out_balance_public_shares1 = pre_settlement_out_balance_shares1.clone();
        new_out_balance_public_shares1.amount += Scalar::from(net_receive1);
        new_out_balance_public_shares1.relayer_fee_balance += Scalar::from(fee_take1.relayer_fee);
        new_out_balance_public_shares1.protocol_fee_balance += Scalar::from(fee_take1.protocol_fee);

        // Create the witness and statement
        let witness = IntentAndBalancePrivateSettlementWitness {
            settlement_obligation0: obligation0,
            intent0: intent0.clone(),
            pre_settlement_amount_public_share0,
            input_balance0: input_balance0.clone(),
            pre_settlement_in_balance_shares0,
            output_balance0: output_balance0.clone(),
            pre_settlement_out_balance_shares0,
            settlement_obligation1: obligation1,
            intent1: intent1.clone(),
            pre_settlement_amount_public_share1,
            input_balance1: input_balance1.clone(),
            pre_settlement_in_balance_shares1,
            output_balance1: output_balance1.clone(),
            pre_settlement_out_balance_shares1,
        };
        let statement = IntentAndBalancePrivateSettlementStatement {
            new_amount_public_share0,
            new_in_balance_public_shares0,
            new_out_balance_public_shares0,
            new_amount_public_share1,
            new_in_balance_public_shares1,
            new_out_balance_public_shares1,
            relayer_fee0,
            relayer_fee1,
            protocol_fee,
        };

        (witness, statement)
    }

    /// Create a pair of compatible intents, returns settlement obligations
    /// which correspond to the intents
    fn create_compatible_intents() -> (Intent, Intent, SettlementObligation, SettlementObligation) {
        let mut rng = thread_rng();
        let token0 = random_address();
        let token1 = random_address();
        let token0_amount = random_amount();
        let token1_amount = random_amount();
        let token0_traded = rng.gen_range(1..=token0_amount);
        let token1_traded = rng.gen_range(1..=token1_amount);

        // Compute the actual trade prices based on the traded amounts
        let trade_price0 = (token1_traded as f64) / (token0_traded as f64);
        let trade_price1 = (token0_traded as f64) / (token1_traded as f64);
        let min_price0 = rng.gen_range(0.0..=trade_price0);
        let min_price1 = rng.gen_range(0.0..=trade_price1);

        let intent0 = Intent {
            in_token: token0,
            out_token: token1,
            owner: random_address(),
            min_price: FixedPoint::from_f64_round_down(min_price0),
            amount_in: token0_amount,
        };

        let intent1 = Intent {
            in_token: token1,
            out_token: token0,
            owner: random_address(),
            min_price: FixedPoint::from_f64_round_down(min_price1),
            amount_in: token1_amount,
        };

        let obligation0 = SettlementObligation {
            input_token: token0,
            output_token: token1,
            amount_in: token0_traded,
            amount_out: token1_traded,
        };
        let obligation1 = SettlementObligation {
            input_token: token1,
            output_token: token0,
            amount_in: token1_traded,
            amount_out: token0_traded,
        };
        (intent0, intent1, obligation0, obligation1)
    }

    /// Create a send balance for a given obligation
    fn create_send_balance(owner: Address, obligation: &SettlementObligation) -> Balance {
        let mut rng = thread_rng();
        let amount = rng.gen_range(obligation.amount_in..=max_amount());
        Balance {
            mint: obligation.input_token,
            owner,
            relayer_fee_recipient: random_address(),
            one_time_authority: random_address(),
            relayer_fee_balance: random_amount(),
            protocol_fee_balance: random_amount(),
            amount,
        }
    }

    /// Create a receive balance for a given obligation
    fn create_receive_balance(owner: Address, obligation: &SettlementObligation) -> Balance {
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
#[allow(unused_braces)]
mod test {
    use crate::test_helpers::{compute_implied_price, random_address, random_scalar};

    use super::*;
    use circuit_types::{max_amount, traits::SingleProverCircuit};
    use rand::{Rng, thread_rng};

    macro_rules! rand_branch {
        // Base case: 2 branches
        ($branch1:tt, $branch2:tt) => {
            if thread_rng().gen_bool(0.5) { $branch1 } else { $branch2 }
        };
        // Recursive case: N branches (N > 2)
        // Randomly choose between first branch and the rest
        ($first:tt, $($rest:tt),+ $(,)?) => {
            {
                let mut rng = thread_rng();
                let n = 1 + count_branches!($($rest),+);
                let choice = rng.gen_range(0..n);
                if choice == 0 {
                    $first
                } else {
                    rand_branch!($($rest),+)
                }
            }
        };
    }

    // Helper macro to count branches
    #[allow(unused_macros)]
    macro_rules! count_branches {
        ($first:tt) => { 1 };
        ($first:tt, $($rest:tt),+ $(,)?) => {
            1 + count_branches!($($rest),+)
        };
    }

    /// A helper to print the number of constraints in the circuit
    ///
    /// Useful when benchmarking the circuit
    #[test]
    fn test_n_constraints() {
        let layout = IntentAndBalancePrivateSettlementCircuit::get_circuit_layout().unwrap();

        let n_gates = layout.n_gates;
        let circuit_size = layout.circuit_size();
        println!("Number of constraints: {n_gates}");
        println!("Next power of two: {circuit_size}");
    }

    /// Test that constraints are satisfied on a valid witness and statement
    #[test]
    fn test_valid_intent_and_balance_private_settlement_constraints() {
        let (witness, statement) = test_helpers::create_witness_statement();
        assert!(test_helpers::check_constraints(&witness, &statement));
    }

    // --- Incompatible Obligations --- //

    /// Test the case in which the obligation amounts are invalid
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_obligation__invalid_amount() {
        let (mut witness, statement) = test_helpers::create_witness_statement();

        // Pick a random obligation amount to corrupt
        let amount = rand_branch!(
            { &mut witness.settlement_obligation0.amount_in },
            { &mut witness.settlement_obligation0.amount_out },
            { &mut witness.settlement_obligation1.amount_in },
            { &mut witness.settlement_obligation1.amount_out }
        );

        *amount = max_amount() + 1;
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which an obligation input token is misconfigured
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_obligation__input_token_mismatch() {
        let (mut witness, statement) = test_helpers::create_witness_statement();

        let bad_token = random_address();
        rand_branch!(
            {
                witness.settlement_obligation0.input_token = bad_token;
                witness.intent0.in_token = bad_token;
            },
            {
                witness.settlement_obligation1.input_token = bad_token;
                witness.intent1.in_token = bad_token;
            }
        );

        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which an obligation output token is misconfigured
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_obligation__output_token_mismatch() {
        let (mut witness, statement) = test_helpers::create_witness_statement();

        let bad_token = random_address();
        rand_branch!(
            {
                witness.settlement_obligation0.output_token = bad_token;
                witness.intent0.out_token = bad_token;
                witness.output_balance0.mint = bad_token;
            },
            {
                witness.settlement_obligation1.output_token = bad_token;
                witness.intent1.out_token = bad_token;
                witness.output_balance1.mint = bad_token;
            }
        );
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the input and output amounts of the obligations
    /// are not aligned
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_obligation__amounts_not_aligned() {
        let (mut witness, mut statement) = test_helpers::create_witness_statement();

        rand_branch!(
            {
                witness.settlement_obligation0.amount_in -= 1;
                statement.new_amount_public_share0 -= Scalar::one();
                statement.new_in_balance_public_shares0.amount -= Scalar::one();
            },
            {
                witness.settlement_obligation1.amount_in -= 1;
                statement.new_amount_public_share1 -= Scalar::one();
                statement.new_in_balance_public_shares1.amount -= Scalar::one();
            }
        );
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    // --- Invalid Intent --- //

    /// Test the case in which an intent is incompatible with an obligation
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_obligation__intent_incompatible() {
        let (mut witness, statement) = test_helpers::create_witness_statement();

        let bad_token = random_address();
        #[rustfmt::skip]
        rand_branch!(
            { witness.intent0.out_token = bad_token; },
            { witness.intent0.in_token = bad_token; },
            { witness.intent1.in_token = bad_token; },
            { witness.intent1.out_token = bad_token; }
        );
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which an intent's input amount is violated
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_intent__input_amount_violated() {
        let (mut witness, statement) = test_helpers::create_witness_statement();

        #[rustfmt::skip]
        rand_branch!(
            { witness.intent0.amount_in = witness.settlement_obligation0.amount_in - 1; },
            { witness.intent1.amount_in = witness.settlement_obligation1.amount_in - 1; }
        );
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the intent's min price is violated
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_intent__min_price_violated() {
        let (mut witness, statement) = test_helpers::create_witness_statement();

        // Increase the min price by a factor of 2 so that the obligation violates it
        let two_scalar = Scalar::from(2u8);
        rand_branch!(
            {
                let obligation = &witness.settlement_obligation0;
                let trade_price =
                    compute_implied_price(obligation.amount_out, obligation.amount_in);
                witness.intent0.min_price = trade_price * two_scalar;
            },
            {
                let obligation = &witness.settlement_obligation1;
                let trade_price =
                    compute_implied_price(obligation.amount_out, obligation.amount_in);
                witness.intent1.min_price = trade_price * two_scalar;
            }
        );
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    // --- Invalid Input Balance --- //

    /// Test the case in which the input balance does not capitalize the
    /// obligation
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_input_balance__undercapitalized() {
        let (mut witness, statement) = test_helpers::create_witness_statement();

        #[rustfmt::skip]
        rand_branch!(
            { witness.input_balance0.amount = witness.settlement_obligation0.amount_in - 1; },
            { witness.input_balance1.amount = witness.settlement_obligation1.amount_in - 1; }
        );
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    // --- Invalid Output Balance --- //

    /// Test the case in which the output balance does not capitalize the
    /// obligation
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_output_balance__wrong_mint() {
        let (mut witness, statement) = test_helpers::create_witness_statement();

        let bad_mint = random_address();
        #[rustfmt::skip]
        rand_branch!(
            { witness.output_balance0.mint = bad_mint; },
            { witness.output_balance1.mint = bad_mint; }
        );
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the balance owner is not the same as the intent's
    /// owner
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_output_balance__owner_mismatch() {
        let (mut witness, statement) = test_helpers::create_witness_statement();

        let bad_owner = random_address();
        #[rustfmt::skip]
        rand_branch!(
            { witness.output_balance0.owner = bad_owner; },
            { witness.output_balance1.owner = bad_owner; }
        );
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the output balance overflows
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_output_balance__overflow() {
        let (mut witness, statement) = test_helpers::create_witness_statement();

        let bal_amt = max_amount() - 1;
        #[rustfmt::skip]
        rand_branch!(
            { witness.output_balance0.amount = bal_amt; },
            { witness.output_balance1.amount = bal_amt; }
        );
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    // --- Invalid State Updates --- //

    /// Test the case in which the intent's amount public share is modified
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_update__intent_amount_public_share_modified() {
        let (witness, mut statement) = test_helpers::create_witness_statement();

        #[rustfmt::skip]
        rand_branch!(
            { statement.new_amount_public_share0 = random_scalar(); },
            { statement.new_amount_public_share1 = random_scalar(); }
        );
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the input balance's public shares are modified
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_update__input_balance_public_shares_modified() {
        let mut rng = thread_rng();
        let (witness, mut statement) = test_helpers::create_witness_statement();

        rand_branch!(
            {
                let mut shares = statement.new_in_balance_public_shares0.to_scalars();
                let idx = rng.gen_range(0..shares.len());
                shares[idx] = random_scalar();
                statement.new_in_balance_public_shares0 =
                    PostMatchBalanceShare::from_scalars(&mut shares.into_iter());
            },
            {
                let mut shares = statement.new_in_balance_public_shares1.to_scalars();
                let idx = rng.gen_range(0..shares.len());
                shares[idx] = random_scalar();
                statement.new_in_balance_public_shares1 =
                    PostMatchBalanceShare::from_scalars(&mut shares.into_iter());
            }
        );
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the output balance's public shares are modified
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_update__output_balance_public_shares_modified() {
        let mut rng = thread_rng();
        let (witness, mut statement) = test_helpers::create_witness_statement();

        rand_branch!(
            {
                let mut shares = statement.new_out_balance_public_shares0.to_scalars();
                let idx = rng.gen_range(0..shares.len());
                shares[idx] = random_scalar();
                statement.new_out_balance_public_shares0 =
                    PostMatchBalanceShare::from_scalars(&mut shares.into_iter());
            },
            {
                let mut shares = statement.new_out_balance_public_shares1.to_scalars();
                let idx = rng.gen_range(0..shares.len());
                shares[idx] = random_scalar();
                statement.new_out_balance_public_shares1 =
                    PostMatchBalanceShare::from_scalars(&mut shares.into_iter());
            }
        );
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }
}
