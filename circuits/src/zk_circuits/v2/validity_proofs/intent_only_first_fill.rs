//! The validity statement for a private intent on its first fill, capitalized
//! by a public balance
//!
//! Because the balance is public, we need not prove the balance's validity;
//! this can be checked by the contracts directly.

use alloy_primitives::Address;
use circuit_macros::circuit_type;
use circuit_types::{
    Commitment, PlonkCircuit,
    csprng::PoseidonCSPRNG,
    intent::{DarkpoolStateIntentVar, Intent, IntentShare},
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
        INTENT_ONLY_PUBLIC_SETTLEMENT_LINK,
        intent_only_public_settlement::IntentOnlyPublicSettlementCircuit,
    },
    zk_gadgets::{
        bitlength::{AmountGadget, PriceGadget},
        comparators::EqGadget,
        shares::ShareGadget,
        state_primitives::{CommitmentGadget, RecoveryIdGadget},
    },
};

// ----------------------
// | Circuit Definition |
// ----------------------

/// The `INTENT ONLY FIRST FILL VALIDITY` circuit
pub struct IntentOnlyFirstFillValidityCircuit;

impl IntentOnlyFirstFillValidityCircuit {
    /// Apply the circuit constraints to a given constraint system
    pub fn circuit(
        statement: &IntentOnlyFirstFillValidityStatementVar,
        witness: &mut IntentOnlyFirstFillValidityWitnessVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // 1. Validate the intent
        let mut intent = Self::build_and_validate_intent(witness, statement, cs)?;

        // 2. Validate that the witness' public share of the amount matches the public
        //    share computed for the intent
        EqGadget::constrain_eq(
            &witness.new_amount_public_share,
            &intent.public_share.amount_in,
            cs,
        )?;

        // 2. Compute the recovery identifier for the new intent
        let recovery_id = RecoveryIdGadget::compute_recovery_id(&mut intent, cs)?;
        EqGadget::constrain_eq(&recovery_id, &statement.recovery_id, cs)?;

        // 3. Compute the commitment to the private shares only
        let private_commitment =
            CommitmentGadget::compute_private_commitment(&witness.private_shares, &intent, cs)?;
        EqGadget::constrain_eq(&private_commitment, &statement.intent_partial_commitment, cs)?;

        Ok(())
    }

    /// Validate the intent and construct its state element wrapper
    fn build_and_validate_intent(
        witness: &IntentOnlyFirstFillValidityWitnessVar,
        statement: &IntentOnlyFirstFillValidityStatementVar,
        cs: &mut PlonkCircuit,
    ) -> Result<DarkpoolStateIntentVar, CircuitError> {
        let intent = &witness.intent;

        // The intent amount and minimum price must be of valid bitlengths
        AmountGadget::constrain_valid_amount(intent.amount_in, cs)?;
        PriceGadget::constrain_valid_price(intent.min_price, cs)?;

        // The intent owner must match the statement owner
        EqGadget::constrain_eq(&intent.owner, &statement.owner, cs)?;

        // Compute the public shares of the intent
        let public_share =
            ShareGadget::compute_complementary_shares(&witness.private_shares, intent, cs)?;
        EqGadget::constrain_eq(&public_share, &statement.intent_public_share, cs)?;

        // Build the state element wrapper
        let state_wrapper = DarkpoolStateIntentVar {
            inner: intent.clone(),
            share_stream: witness.initial_intent_share_stream.clone(),
            recovery_stream: witness.initial_intent_recovery_stream.clone(),
            public_share,
        };
        Ok(state_wrapper)
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for `INTENT ONLY FIRST FILL VALIDITY`
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntentOnlyFirstFillValidityWitness {
    /// The new intent
    ///
    /// The owner will sign a commitment to the intent, and this will be used to
    /// authorize the first fill. Subsequent fills are authorized by the
    /// intent's presence in the Merkle tree.
    ///
    /// For this reason, we do not need to verify the intent's encryption here.
    /// This is bundled into the commitment which the owner signs. Thereby the
    /// encryption is authorized by the user.
    #[link_groups = "intent_only_public_settlement"]
    pub intent: Intent,
    /// The public share of the intent's `amount_in` field
    ///
    /// Places here in the witness to enable proof linking between this
    /// circuit's witness and the `INTENT ONLY PUBLIC SETTLEMENT` circuit's
    /// witness.
    #[link_groups = "intent_only_public_settlement"]
    pub new_amount_public_share: Scalar,
    /// The initial intent share CSPRNG
    pub initial_intent_share_stream: PoseidonCSPRNG,
    /// The initial intent recovery stream
    pub initial_intent_recovery_stream: PoseidonCSPRNG,
    /// The private shares of the intent
    pub private_shares: IntentShare,
}

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for `INTENT ONLY FIRST FILL VALIDITY`
#[circuit_type(singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntentOnlyFirstFillValidityStatement {
    /// The owner of the intent
    ///
    /// We leak this value here to allow the contracts to verify that the intent
    /// is authorized by its owner on the first fill.
    pub owner: Address,
    /// A partial commitment to the new intent
    ///
    /// We omit the public share of the `amount_in` field here as this will
    /// change during the first fill. Instead, we commit to _all_ private shares
    /// and _all_ public shares other than the `amount_in` field.
    ///
    /// The match will update the public share of the `amount_in` field and the
    /// contracts will resume the commitment to the intent. See the
    /// `CommitmentGadget` for more details on resumable commitments.
    pub intent_partial_commitment: Commitment,
    /// The recovery identifier of the intent
    pub recovery_id: Scalar,
    /// The encrypted intent; i.e. the public shares of the intent without the
    /// `amount_in` field. The `amount_in` field is leaked after it's been
    /// updated by the settlement circuit.
    pub intent_public_share: IntentShare,
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl SingleProverCircuit for IntentOnlyFirstFillValidityCircuit {
    type Witness = IntentOnlyFirstFillValidityWitness;
    type Statement = IntentOnlyFirstFillValidityStatement;

    fn name() -> String {
        "Intent Only First Fill Validity".to_string()
    }

    /// INTENT ONLY FIRST FILL VALIDITY has one proof linking group:
    /// - intent_only_public_settlement: The linking group between INTENT ONLY
    ///   FIRST FILL VALIDITY and INTENT ONLY PUBLIC SETTLEMENT. This group is
    ///   placed by the settlement circuit, so we inherit its layout here.
    fn proof_linking_groups() -> Result<Vec<(String, Option<GroupLayout>)>, PlonkError> {
        let layout = IntentOnlyPublicSettlementCircuit::<MERKLE_HEIGHT>::get_circuit_layout()?;
        let settlement_group = layout.get_group_layout(INTENT_ONLY_PUBLIC_SETTLEMENT_LINK);
        let group_name = INTENT_ONLY_PUBLIC_SETTLEMENT_LINK.to_string();

        Ok(vec![(group_name, Some(settlement_group))])
    }

    fn apply_constraints(
        mut witness_var: IntentOnlyFirstFillValidityWitnessVar,
        statement_var: IntentOnlyFirstFillValidityStatementVar,
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

    use crate::{
        test_helpers::{check_constraints_satisfied, create_state_wrapper, random_intent},
        zk_circuits::v2::validity_proofs::intent_only_first_fill::{
            IntentOnlyFirstFillValidityCircuit, IntentOnlyFirstFillValidityStatement,
            IntentOnlyFirstFillValidityWitness,
        },
    };

    // -----------
    // | Helpers |
    // -----------

    /// Check that the constraints are satisfied on the given witness and
    /// statement
    pub fn check_constraints(
        witness: &IntentOnlyFirstFillValidityWitness,
        statement: &IntentOnlyFirstFillValidityStatement,
    ) -> bool {
        check_constraints_satisfied::<IntentOnlyFirstFillValidityCircuit>(witness, statement)
    }

    /// Construct a witness and statement with valid data
    pub fn create_witness_statement()
    -> (IntentOnlyFirstFillValidityWitness, IntentOnlyFirstFillValidityStatement) {
        let intent = random_intent();
        create_witness_statement_with_intent(&intent)
    }

    /// Create a witness and statement with the given intent
    pub fn create_witness_statement_with_intent(
        intent: &Intent,
    ) -> (IntentOnlyFirstFillValidityWitness, IntentOnlyFirstFillValidityStatement) {
        // Create the witness intent with initial stream states
        let initial_intent = create_state_wrapper(intent.clone());
        let mut intent_clone = initial_intent.clone();
        let recovery_id = intent_clone.compute_recovery_id();
        let intent_partial_commitment = intent_clone.compute_private_commitment();

        // Get shares from the initial (pre-mutation) state
        let private_shares = initial_intent.private_shares();
        let intent_public_share = initial_intent.public_share();
        let new_amount_public_share = intent_public_share.amount_in;

        // Build the witness with the pre-mutation state
        let witness = IntentOnlyFirstFillValidityWitness {
            intent: initial_intent.inner,
            initial_intent_share_stream: initial_intent.share_stream,
            initial_intent_recovery_stream: initial_intent.recovery_stream,
            new_amount_public_share,
            private_shares,
        };
        let statement = IntentOnlyFirstFillValidityStatement {
            owner: intent.owner,
            intent_partial_commitment,
            recovery_id,
            intent_public_share,
        };

        (witness, statement)
    }
}

#[cfg(test)]
mod test {
    use crate::test_helpers::{max_amount, random_address, random_intent, random_scalar};

    use super::*;
    use circuit_types::{fixed_point::FixedPoint, max_price, traits::SingleProverCircuit};
    use rand::{Rng, thread_rng};

    /// A helper to print the number of constraints in the circuit
    ///
    /// Useful when benchmarking the circuit
    #[test]
    fn test_n_constraints() {
        let layout = IntentOnlyFirstFillValidityCircuit::get_circuit_layout().unwrap();

        let n_gates = layout.n_gates;
        let circuit_size = layout.circuit_size();
        println!("Number of constraints: {n_gates}");
        println!("Next power of two: {circuit_size}");
    }

    /// Test that constraints are satisfied on a valid witness and statement
    #[test]
    fn test_valid_intent_only_first_fill_constraints() {
        let (witness, statement) = test_helpers::create_witness_statement();
        assert!(test_helpers::check_constraints(&witness, &statement));
    }

    // --- Intent Validation Tests --- //

    /// Test the case in which the intent's amount is too large
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_intent__amount_too_large() {
        let mut intent = random_intent();
        intent.amount_in = max_amount() + 1;

        let (witness, statement) = test_helpers::create_witness_statement_with_intent(&intent);
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the intent's price is too large
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_intent__price_too_large() {
        let mut intent = random_intent();
        intent.min_price = max_price() + FixedPoint::from_integer(1);

        let (witness, statement) = test_helpers::create_witness_statement_with_intent(&intent);
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the intent's owner does not match the statement
    /// owner
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_intent__owner_does_not_match_statement_owner() {
        let (witness, mut statement) = test_helpers::create_witness_statement();
        statement.owner = random_address();

        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which a public share is modified in the statement
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_intent__public_share_modified() {
        let mut rng = thread_rng();
        let (witness, mut statement) = test_helpers::create_witness_statement();

        let mut public_share = statement.intent_public_share.to_scalars();
        let random_index = rng.gen_range(0..public_share.len());
        public_share[random_index] = random_scalar();
        statement.intent_public_share = IntentShare::from_scalars(&mut public_share.into_iter());

        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the public share of the amount is not correctly
    /// set in the witness
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_intent__public_share_amount_not_correctly_set() {
        let (mut witness, statement) = test_helpers::create_witness_statement();
        witness.new_amount_public_share = random_scalar();

        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    // --- Recovery ID and Commitment Tests --- //

    /// Test the case in which the recovery ID is modified
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_recovery_id() {
        let (witness, mut statement) = test_helpers::create_witness_statement();
        statement.recovery_id = random_scalar();
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the commitment is modified
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_commitment() {
        let (witness, mut statement) = test_helpers::create_witness_statement();
        statement.intent_partial_commitment = random_scalar();
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }
}
