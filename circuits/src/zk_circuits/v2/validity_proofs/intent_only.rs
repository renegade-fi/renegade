//! The validity statement for a private intent on subsequent fills (not the
//! first fill)
//!
//! For subsequent fills, the intent is already present in the Merkle tree, so
//! we need to prove its existence via a Merkle opening rather than owner
//! authorization.

use circuit_macros::circuit_type;
use circuit_types::{
    Commitment, Nullifier, PlonkCircuit,
    intent::{DarkpoolStateIntent, DarkpoolStateIntentVar, Intent, IntentShare},
    merkle::{MerkleOpening, MerkleRoot},
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
        comparators::EqGadget,
        shares::ShareGadget,
        state_rotation::{StateElementRotationArgs, StateElementRotationGadget},
        stream_cipher::StreamCipherGadget,
    },
};

// ----------------------
// | Circuit Definition |
// ----------------------

/// The `INTENT ONLY VALIDITY` circuit
pub struct IntentOnlyValidityCircuit<const MERKLE_HEIGHT: usize>;

impl<const MERKLE_HEIGHT: usize> IntentOnlyValidityCircuit<MERKLE_HEIGHT> {
    /// Apply the circuit constraints to a given constraint system
    pub fn circuit(
        statement: &IntentOnlyValidityStatementVar,
        witness: &mut IntentOnlyValidityWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // 1. Recover the old intent private shares
        let old_private_shares = ShareGadget::compute_complementary_shares(
            &witness.old_intent.public_share,
            &witness.old_intent.inner,
            cs,
        )?;

        // 2. Build the new intent state
        let (new_intent, new_private_shares) =
            Self::build_new_intent(&old_private_shares, witness, cs)?;

        // 3. Validate that the computed intent and new amount public share match their
        //    counterparts that are factored out in the witness type to enable a proof
        //    link into the settlement circuit
        EqGadget::constrain_eq(&new_intent.inner, &witness.intent, cs)?;
        EqGadget::constrain_eq(
            &new_intent.public_share.amount_in,
            &witness.new_amount_public_share,
            cs,
        )?;

        // 4. Verify state rotation (Merkle proof, nullifier, recovery_id, commitment)
        // TODO: Compute only a partial commitment here
        let mut rotation_args = StateElementRotationArgs {
            old_version: witness.old_intent.clone(),
            old_private_share: old_private_shares,
            old_opening: witness.old_intent_opening.clone(),
            merkle_root: statement.merkle_root,
            nullifier: statement.old_intent_nullifier,
            new_version: new_intent,
            new_private_share: new_private_shares,
            new_commitment: statement.new_intent_partial_commitment,
            recovery_id: statement.recovery_id,
        };
        StateElementRotationGadget::rotate_version(&mut rotation_args, cs)?;

        Ok(())
    }

    /// Build the new intent state from the old intent
    ///
    /// The intent remains the same, but we re-encrypt the `amount_in` field so
    /// that it may be modified in the match without leaking the match amount or
    /// re-appearing in calldata, which would allow an intent to be tracked
    /// across settlements.
    fn build_new_intent(
        old_private_shares: &<IntentShare as CircuitBaseType>::VarType,
        witness: &IntentOnlyValidityWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(DarkpoolStateIntentVar, <IntentShare as CircuitBaseType>::VarType), CircuitError>
    {
        let mut new_intent = witness.old_intent.clone();
        let mut new_intent_private_shares = old_private_shares.clone();

        let (new_amount_private_share, new_amount_public_share) =
            StreamCipherGadget::encrypt::<Variable>(
                &new_intent.inner.amount_in,
                &mut new_intent.share_stream,
                cs,
            )?;
        new_intent_private_shares.amount_in = new_amount_private_share;
        new_intent.public_share.amount_in = new_amount_public_share;

        Ok((new_intent, new_intent_private_shares))
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for `INTENT ONLY VALIDITY`
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntentOnlyValidityWitness<const MERKLE_HEIGHT: usize> {
    /// The existing intent in the darkpool state
    pub old_intent: DarkpoolStateIntent,
    /// The Merkle opening proving the old intent exists in the tree
    pub old_intent_opening: MerkleOpening<MERKLE_HEIGHT>,
    /// The intent which this circuit is settling a match for
    ///
    /// This value is denormalized from the `old_intent` to enable proof linking
    /// between this circuit's witness and the `INTENT ONLY PUBLIC
    /// SETTLEMENT` circuit's witness.
    #[link_groups = "intent_only_public_settlement"]
    pub intent: Intent,
    /// The new public share of the `amount_in` field after the value has been
    /// re-encrypted. This value appears only in the witness and is proof-linked
    /// into the settlement proof. Doing so prevents the verifier from learning
    /// the pre- and post- public share or the `amount_in` field which would
    /// leak the match size.
    #[link_groups = "intent_only_public_settlement"]
    pub new_amount_public_share: Scalar,
}

/// A `INTENT ONLY VALIDITY` witness with default const generic sizing
/// parameters
pub type SizedIntentOnlyValidityWitness = IntentOnlyValidityWitness<MERKLE_HEIGHT>;

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for `INTENT ONLY VALIDITY`
#[circuit_type(singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntentOnlyValidityStatement {
    /// The Merkle root to which the old intent opens
    pub merkle_root: MerkleRoot,
    /// The nullifier of the old intent
    pub old_intent_nullifier: Nullifier,
    /// A partial commitment to the new intent
    ///
    /// We omit the public share of the `amount_in` field here as this will
    /// change _during_ the match settlement. Instead, we commit to _all_
    /// private shares and _all_ public shares other than the `amount_in`
    /// field.
    pub new_intent_partial_commitment: Commitment,
    /// The recovery identifier of the new intent
    pub recovery_id: Scalar,
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl<const MERKLE_HEIGHT: usize> SingleProverCircuit for IntentOnlyValidityCircuit<MERKLE_HEIGHT> {
    type Witness = IntentOnlyValidityWitness<MERKLE_HEIGHT>;
    type Statement = IntentOnlyValidityStatement;

    fn name() -> String {
        format!("Intent Only Validity ({MERKLE_HEIGHT})")
    }

    /// INTENT ONLY VALIDITY has a single proof linking group:
    /// - intent_only_public_settlement: The linking group between INTENT ONLY
    ///   VALIDITY and INTENT ONLY PUBLIC SETTLEMENT. This group is placed by
    ///   the settlement circuit, so we inherit its layout here.
    fn proof_linking_groups() -> Result<Vec<(String, Option<GroupLayout>)>, PlonkError> {
        let layout = IntentOnlyPublicSettlementCircuit::<MERKLE_HEIGHT>::get_circuit_layout()?;
        let settlement_group = layout.get_group_layout(INTENT_ONLY_PUBLIC_SETTLEMENT_LINK);
        let group_name = INTENT_ONLY_PUBLIC_SETTLEMENT_LINK.to_string();

        Ok(vec![(group_name, Some(settlement_group))])
    }

    fn apply_constraints(
        mut witness_var: IntentOnlyValidityWitnessVar<MERKLE_HEIGHT>,
        statement_var: IntentOnlyValidityStatementVar,
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
        test_helpers::{check_constraints_satisfied, create_merkle_opening, random_intent},
        zk_circuits::v2::validity_proofs::intent_only::{
            IntentOnlyValidityCircuit, IntentOnlyValidityStatement, IntentOnlyValidityWitness,
        },
    };

    // -----------
    // | Helpers |
    // -----------

    /// Check that the constraints are satisfied on the given witness and
    /// statement
    pub fn check_constraints<const MERKLE_HEIGHT: usize>(
        witness: &IntentOnlyValidityWitness<MERKLE_HEIGHT>,
        statement: &IntentOnlyValidityStatement,
    ) -> bool {
        check_constraints_satisfied::<IntentOnlyValidityCircuit<MERKLE_HEIGHT>>(witness, statement)
    }

    /// Construct a witness and statement with valid data
    pub fn create_witness_statement<const MERKLE_HEIGHT: usize>()
    -> (IntentOnlyValidityWitness<MERKLE_HEIGHT>, IntentOnlyValidityStatement) {
        let intent = random_intent();
        create_witness_statement_with_intent::<MERKLE_HEIGHT>(intent)
    }

    /// Create a witness and statement with the given intent
    pub fn create_witness_statement_with_intent<const MERKLE_HEIGHT: usize>(
        intent: Intent,
    ) -> (IntentOnlyValidityWitness<MERKLE_HEIGHT>, IntentOnlyValidityStatement) {
        use crate::test_helpers::create_random_state_wrapper;

        // Create the old intent with initial stream states
        // Use create_random_state_wrapper to ensure the recovery stream has been
        // advanced (for subsequent fills, the intent must have been updated at
        // least once)
        let mut old_intent = create_random_state_wrapper(intent.clone());

        // Advance the recovery stream once to simulate a previous update
        old_intent.compute_recovery_id();

        // Compute commitment and nullifier for the old intent
        let old_intent_commitment = old_intent.compute_commitment();
        let old_intent_nullifier = old_intent.compute_nullifier();

        // Create a Merkle opening for the old intent
        let (merkle_root, old_intent_opening) =
            create_merkle_opening::<MERKLE_HEIGHT>(old_intent_commitment);

        // Create a new intent by cloning and re-encrypting amount_in
        let mut new_intent = old_intent.clone();

        // Re-encrypt the amount_in field to get a new public share
        let new_amount_scalar = Scalar::from(new_intent.inner.amount_in);
        let new_amount_public_share = new_intent.stream_cipher_encrypt(&new_amount_scalar);
        new_intent.public_share.amount_in = new_amount_public_share;

        // Compute recovery_id and commitment for the new intent
        // Note: StateElementRotationGadget computes a full commitment, so we need to
        // compute the full commitment here, not just the private commitment
        let recovery_id = new_intent.compute_recovery_id();
        let new_intent_partial_commitment = new_intent.compute_commitment();

        // Build the witness and statement
        let witness = IntentOnlyValidityWitness {
            old_intent,
            old_intent_opening,
            intent,
            new_amount_public_share,
        };
        let statement = IntentOnlyValidityStatement {
            merkle_root,
            old_intent_nullifier,
            new_intent_partial_commitment,
            recovery_id,
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
        let layout = IntentOnlyValidityCircuit::<MERKLE_HEIGHT>::get_circuit_layout().unwrap();

        let n_gates = layout.n_gates;
        let circuit_size = layout.circuit_size();
        println!("Number of constraints: {n_gates}");
        println!("Next power of two: {circuit_size}");
    }

    /// Test that constraints are satisfied on a valid witness and statement
    #[test]
    fn test_valid_intent_only_constraints() {
        let (witness, statement) = test_helpers::create_witness_statement::<MERKLE_HEIGHT>();
        assert!(test_helpers::check_constraints::<MERKLE_HEIGHT>(&witness, &statement));
    }
}
