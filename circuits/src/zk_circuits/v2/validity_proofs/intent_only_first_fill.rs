//! The validity statement for a private intent on its first fill, capitalized
//! by a public balance
//!
//! Because the balance is public, we need not prove the balance's validity;
//! this can be checked by the contracts directly.

use alloy_primitives::Address;
use circuit_macros::circuit_type;
use circuit_types::{
    Commitment, PlonkCircuit,
    intent::{DarkpoolStateIntent, DarkpoolStateIntentVar, IntentShare},
    traits::{BaseType, CircuitBaseType, CircuitVarType},
};
use constants::{Scalar, ScalarField};
use mpc_plonk::errors::PlonkError;
use mpc_relation::{Variable, errors::CircuitError, traits::Circuit};
use serde::{Deserialize, Serialize};

use crate::{
    SingleProverCircuit,
    zk_gadgets::{
        bitlength::{AmountGadget, PriceGadget},
        comparators::EqGadget,
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
        Self::validate_intent(&witness.intent, statement, cs)?;

        // 2. Compute the recovery identifier for the new intent
        let recovery_id = RecoveryIdGadget::compute_recovery_id(&mut witness.intent, cs)?;
        EqGadget::constrain_eq(&recovery_id, &statement.recovery_id, cs)?;

        // 3. Compute the commitment to the private shares only
        // This must be done after encrypting and computing the recovery identifier so
        // that we commit to the updated stream states for the CSPRNGs
        let private_commitment = CommitmentGadget::compute_private_commitment(
            &witness.private_shares,
            &witness.intent,
            cs,
        )?;
        EqGadget::constrain_eq(&private_commitment, &statement.intent_partial_commitment, cs)?;

        Ok(())
    }

    /// Validate the intent
    fn validate_intent(
        intent: &DarkpoolStateIntentVar,
        statement: &IntentOnlyFirstFillValidityStatementVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // The intent amount and minimum price must be of valid bitlengths
        AmountGadget::constrain_valid_amount(intent.inner.amount_in, cs)?;
        PriceGadget::constrain_valid_price(intent.inner.min_price, cs)?;

        // The intent owner must match the statement owner
        EqGadget::constrain_eq(&intent.inner.owner, &statement.owner, cs)?;
        EqGadget::constrain_eq(&intent.public_share, &statement.intent_public_share, cs)?;
        Ok(())
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
    pub intent: DarkpoolStateIntent,
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
    /// The encrypted intent; i.e. the public shares of the intent
    ///
    /// TODO: This doesn't need to appear in the statement, it can just be sent
    /// as calldata
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

        // Build the witness with the pre-mutation state
        let witness = IntentOnlyFirstFillValidityWitness { intent: initial_intent, private_shares };
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
    use super::*;
    use circuit_types::traits::SingleProverCircuit;

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
}
