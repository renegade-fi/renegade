//! Defines the circuitry for a private settlement of an intent and balance
//!
//! This settlement is performed by a relayer cluster, and is used to settle an
//! intent and balance pair with private obligations

use circuit_macros::circuit_type;
use circuit_types::{
    PlonkCircuit,
    balance::{Balance, PostMatchBalanceShare},
    intent::Intent,
    settlement_obligation::SettlementObligation,
    traits::{BaseType, CircuitBaseType, CircuitVarType},
};
use constants::{MERKLE_HEIGHT, Scalar, ScalarField};
use mpc_plonk::errors::PlonkError;
use mpc_relation::{Variable, errors::CircuitError, proof_linking::GroupLayout, traits::Circuit};
use serde::{Deserialize, Serialize};

use crate::{
    SingleProverCircuit,
    zk_circuits::settlement::settlement_lib::SettlementGadget,
    zk_gadgets::{bitlength::AmountGadget, comparators::EqGadget},
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
        // Party 0
        SettlementGadget::verify_state_updates(
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
    pub intent0: Intent,
    /// The pre-update public shares of the first party's intent amount
    pub pre_settlement_amount_public_share0: Scalar,
    /// The first party's input balance
    pub input_balance0: Balance,
    /// The pre-update public shares of the first party's input balance
    pub pre_settlement_in_balance_shares0: PostMatchBalanceShare,
    /// The first party's output balance
    pub output_balance0: Balance,
    /// The pre-update public shares of the first party's output balance
    pub pre_settlement_out_balance_shares0: PostMatchBalanceShare,

    // --- Second Party --- //
    /// The second party's settlement obligation
    pub settlement_obligation1: SettlementObligation,
    /// The second party's intent
    pub intent1: Intent,
    /// The pre-update public shares of the second party's intent amount
    pub pre_settlement_amount_public_share1: Scalar,
    /// The second party's input balance
    pub input_balance1: Balance,
    /// The pre-update public shares of the second party's input balance
    pub pre_settlement_in_balance_shares1: PostMatchBalanceShare,
    /// The second party's output balance
    pub output_balance1: Balance,
    /// The pre-update public shares of the second party's output balance
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
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl SingleProverCircuit for IntentAndBalancePrivateSettlementCircuit {
    type Witness = IntentAndBalancePrivateSettlementWitness;
    type Statement = IntentAndBalancePrivateSettlementStatement;

    fn name() -> String {
        format!("Intent And Balance Private Settlement ({MERKLE_HEIGHT})")
    }

    fn proof_linking_groups() -> Result<Vec<(String, Option<GroupLayout>)>, PlonkError> {
        // TODO: Add proof linking groups
        Ok(vec![])
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
    use circuit_types::{
        Amount,
        balance::{Balance, PostMatchBalanceShare},
        fixed_point::FixedPoint,
        intent::Intent,
        settlement_obligation::SettlementObligation,
    };
    use constants::Scalar;

    use crate::{
        test_helpers::{
            create_settlement_obligation_with_balance, random_address, random_amount,
            random_intent, random_scalar,
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
    pub fn check_constraints<const MERKLE_HEIGHT: usize>(
        witness: &IntentAndBalancePrivateSettlementWitness,
        statement: &IntentAndBalancePrivateSettlementStatement,
    ) -> bool {
        crate::test_helpers::check_constraints_satisfied::<IntentAndBalancePrivateSettlementCircuit>(
            witness, statement,
        )
    }

    /// Construct a witness and statement with valid data
    pub fn create_witness_statement<const MERKLE_HEIGHT: usize>()
    -> (IntentAndBalancePrivateSettlementWitness, IntentAndBalancePrivateSettlementStatement) {
        let intent = random_intent();
        create_witness_statement_with_intent::<MERKLE_HEIGHT>(&intent)
    }

    /// Create a witness and statement with the given base intent for party 0
    pub fn create_witness_statement_with_intent<const MERKLE_HEIGHT: usize>(
        base_intent: &Intent,
    ) -> (IntentAndBalancePrivateSettlementWitness, IntentAndBalancePrivateSettlementStatement)
    {
        // --- Party 0: intent and obligation --- //
        let intent0 = base_intent.clone();

        // Create a settlement obligation for party 0 that respects the intent's
        // size and min price
        let settlement_obligation0 =
            create_settlement_obligation_with_balance(&intent0, intent0.amount_in);

        // --- Party 1: intent and obligation --- //
        //
        // We construct a "reciprocal" intent and obligation for party 1 so that:
        // - The token pair is reversed relative to party 0
        // - The obligations are compatible as required by
        //   `validate_obligation_compatibility`
        //
        // Specifically, we require:
        //   obligation0.input_token == obligation1.output_token
        //   obligation0.output_token == obligation1.input_token
        //   obligation0.amount_in  == obligation1.amount_out
        //   obligation0.amount_out == obligation1.amount_in
        //
        // We also choose party 1's intent so that:
        //   obligation1.input_token == intent1.in_token
        //   obligation1.output_token == intent1.out_token
        //   obligation1.amount_in <= intent1.amount_in
        //   obligation1.amount_out >= floor(intent1.min_price * obligation1.amount_in)
        //
        // The latter is trivial to satisfy by choosing `intent1.min_price = 0`.

        let amount_in0: Amount = settlement_obligation0.amount_in;
        let amount_out0: Amount = settlement_obligation0.amount_out;

        let intent1 = Intent {
            in_token: intent0.out_token,
            out_token: intent0.in_token,
            owner: random_address(),
            min_price: FixedPoint::zero(),
            amount_in: amount_out0,
        };

        let settlement_obligation1 = SettlementObligation {
            input_token: intent1.in_token,
            output_token: intent1.out_token,
            amount_in: amount_out0,
            amount_out: amount_in0,
        };

        // Convert amounts to scalars for computation of public shares
        let amount_in0_scalar = Scalar::from(amount_in0);
        let amount_out0_scalar = Scalar::from(amount_out0);
        let amount_in1_scalar = Scalar::from(settlement_obligation1.amount_in);
        let amount_out1_scalar = Scalar::from(settlement_obligation1.amount_out);

        // Create pre-settlement shares for party 0
        let pre_settlement_amount_public_share0 = random_scalar();
        let pre_settlement_in_balance_shares0 = PostMatchBalanceShare {
            amount: random_scalar(),
            relayer_fee_balance: random_scalar(),
            protocol_fee_balance: random_scalar(),
        };
        let pre_settlement_out_balance_shares0 = PostMatchBalanceShare {
            amount: random_scalar(),
            relayer_fee_balance: random_scalar(),
            protocol_fee_balance: random_scalar(),
        };

        // Create pre-settlement shares for party 1
        let pre_settlement_amount_public_share1 = random_scalar();
        let pre_settlement_in_balance_shares1 = PostMatchBalanceShare {
            amount: random_scalar(),
            relayer_fee_balance: random_scalar(),
            protocol_fee_balance: random_scalar(),
        };
        let pre_settlement_out_balance_shares1 = PostMatchBalanceShare {
            amount: random_scalar(),
            relayer_fee_balance: random_scalar(),
            protocol_fee_balance: random_scalar(),
        };

        // Compute new shares for party 0
        let new_amount_public_share0 = pre_settlement_amount_public_share0 - amount_in0_scalar;
        let new_in_balance_public_shares0 = PostMatchBalanceShare {
            amount: pre_settlement_in_balance_shares0.amount - amount_in0_scalar,
            relayer_fee_balance: pre_settlement_in_balance_shares0.relayer_fee_balance,
            protocol_fee_balance: pre_settlement_in_balance_shares0.protocol_fee_balance,
        };
        let new_out_balance_public_shares0 = PostMatchBalanceShare {
            amount: pre_settlement_out_balance_shares0.amount + amount_out0_scalar,
            relayer_fee_balance: pre_settlement_out_balance_shares0.relayer_fee_balance,
            protocol_fee_balance: pre_settlement_out_balance_shares0.protocol_fee_balance,
        };

        // Compute new shares for party 1
        let new_amount_public_share1 = pre_settlement_amount_public_share1 - amount_in1_scalar;
        let new_in_balance_public_shares1 = PostMatchBalanceShare {
            amount: pre_settlement_in_balance_shares1.amount - amount_in1_scalar,
            relayer_fee_balance: pre_settlement_in_balance_shares1.relayer_fee_balance,
            protocol_fee_balance: pre_settlement_in_balance_shares1.protocol_fee_balance,
        };
        let new_out_balance_public_shares1 = PostMatchBalanceShare {
            amount: pre_settlement_out_balance_shares1.amount + amount_out1_scalar,
            relayer_fee_balance: pre_settlement_out_balance_shares1.relayer_fee_balance,
            protocol_fee_balance: pre_settlement_out_balance_shares1.protocol_fee_balance,
        };

        // --- Balances --- //
        //
        // Construct input/output balances for each party that satisfy the
        // SettlementGadget constraints:
        // - input_balance.amount >= obligation.amount_in
        // - output_balance.mint == obligation.output_token
        // - output_balance.owner == intent.owner
        // - output_balance.amount + obligation.amount_out is a valid amount

        let input_balance0 = Balance {
            mint: intent0.in_token,
            owner: intent0.owner,
            relayer_fee_recipient: random_address(),
            one_time_authority: random_address(),
            relayer_fee_balance: random_amount(),
            protocol_fee_balance: random_amount(),
            amount: amount_in0,
        };

        let output_balance0 = Balance {
            mint: settlement_obligation0.output_token,
            owner: intent0.owner,
            relayer_fee_recipient: random_address(),
            one_time_authority: random_address(),
            relayer_fee_balance: random_amount(),
            protocol_fee_balance: random_amount(),
            amount: 0,
        };

        let input_balance1 = Balance {
            mint: intent1.in_token,
            owner: intent1.owner,
            relayer_fee_recipient: random_address(),
            one_time_authority: random_address(),
            relayer_fee_balance: random_amount(),
            protocol_fee_balance: random_amount(),
            amount: settlement_obligation1.amount_in,
        };

        let output_balance1 = Balance {
            mint: settlement_obligation1.output_token,
            owner: intent1.owner,
            relayer_fee_recipient: random_address(),
            one_time_authority: random_address(),
            relayer_fee_balance: random_amount(),
            protocol_fee_balance: random_amount(),
            amount: 0,
        };

        let witness = IntentAndBalancePrivateSettlementWitness {
            settlement_obligation0,
            intent0,
            pre_settlement_amount_public_share0,
            input_balance0,
            pre_settlement_in_balance_shares0,
            output_balance0,
            pre_settlement_out_balance_shares0,
            settlement_obligation1,
            intent1,
            pre_settlement_amount_public_share1,
            input_balance1,
            pre_settlement_in_balance_shares1,
            output_balance1,
            pre_settlement_out_balance_shares1,
        };

        let statement = IntentAndBalancePrivateSettlementStatement {
            new_amount_public_share0,
            new_in_balance_public_shares0,
            new_out_balance_public_shares0,
            new_amount_public_share1,
            new_in_balance_public_shares1,
            new_out_balance_public_shares1,
        };

        (witness, statement)
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
        let layout = IntentAndBalancePrivateSettlementCircuit::get_circuit_layout().unwrap();

        let n_gates = layout.n_gates;
        let circuit_size = layout.circuit_size();
        println!("Number of constraints: {n_gates}");
        println!("Next power of two: {circuit_size}");
    }

    /// Test that constraints are satisfied on a valid witness and statement
    #[test]
    fn test_valid_intent_and_balance_private_settlement_constraints() {
        let (witness, statement) = test_helpers::create_witness_statement::<MERKLE_HEIGHT>();
        assert!(test_helpers::check_constraints::<MERKLE_HEIGHT>(&witness, &statement));
    }
}
