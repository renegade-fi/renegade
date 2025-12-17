//! Helpers for linking proofs between intent only validity and settlement
//! circuits

use circuit_types::{
    PlonkLinkProof, PlonkProof, ProofLinkingHint, errors::ProverError, traits::SingleProverCircuit,
};
use constants::MERKLE_HEIGHT;
use mpc_plonk::{proof_system::PlonkKzgSnark, transcript::SolidityTranscript};
use mpc_relation::proof_linking::GroupLayout;

use crate::zk_circuits::{
    settlement::{
        INTENT_ONLY_SETTLEMENT_LINK,
        intent_only_public_settlement::IntentOnlyPublicSettlementCircuit,
    },
    validity_proofs::intent_only::IntentOnlyValidityCircuit,
};

// ----------------------------------------------------------------------
// | Intent Only Validity <-> Intent Only Settlement (Exact or Bounded) |
// ----------------------------------------------------------------------

/// Link an intent only validity proof with a proof of INTENT ONLY
/// SETTLEMENT (exact or bounded) using the system wide sizing constants
pub fn link_sized_intent_only_settlement(
    validity_link_hint: &ProofLinkingHint,
    settlement_link_hint: &ProofLinkingHint,
) -> Result<PlonkLinkProof, ProverError> {
    link_intent_only_settlement::<MERKLE_HEIGHT>(validity_link_hint, settlement_link_hint)
}

/// Link an intent only validity proof with a proof of INTENT ONLY
/// SETTLEMENT (exact or bounded)
pub fn link_intent_only_settlement<const MERKLE_HEIGHT: usize>(
    validity_link_hint: &ProofLinkingHint,
    settlement_link_hint: &ProofLinkingHint,
) -> Result<PlonkLinkProof, ProverError> {
    // Get the group layout for the first fill <-> settlement link group
    let layout = get_intent_only_settlement_group_layout()?;
    let pk = IntentOnlyValidityCircuit::<MERKLE_HEIGHT>::proving_key();

    PlonkKzgSnark::link_proofs::<SolidityTranscript>(
        validity_link_hint,
        settlement_link_hint,
        &layout,
        &pk.commit_key,
    )
    .map_err(ProverError::Plonk)
}

/// Validate a link between an intent only validity proof with a
/// proof of INTENT ONLY SETTLEMENT (exact or bounded) using the system wide
/// sizing constants
pub fn validate_sized_intent_only_settlement_link(
    link_proof: &PlonkLinkProof,
    validity_proof: &PlonkProof,
    settlement_proof: &PlonkProof,
) -> Result<(), ProverError> {
    validate_intent_only_settlement_link::<MERKLE_HEIGHT>(
        link_proof,
        validity_proof,
        settlement_proof,
    )
}

/// Validate a link between an intent only validity proof with a
/// proof of INTENT ONLY SETTLEMENT (exact or bounded)
pub fn validate_intent_only_settlement_link<const MERKLE_HEIGHT: usize>(
    link_proof: &PlonkLinkProof,
    validity_proof: &PlonkProof,
    settlement_proof: &PlonkProof,
) -> Result<(), ProverError> {
    // Get the group layout for the first fill <-> settlement link group
    let layout = get_intent_only_settlement_group_layout()?;
    let vk = IntentOnlyValidityCircuit::<MERKLE_HEIGHT>::verifying_key();

    PlonkKzgSnark::verify_link_proof::<SolidityTranscript>(
        validity_proof,
        settlement_proof,
        link_proof,
        &layout,
        &vk.open_key,
    )
    .map_err(ProverError::Plonk)
}

/// Get the group layout for the intent only validity <-> intent only settlement
/// link group
///
/// This layout is shared by both exact and bounded settlement circuits.
pub fn get_intent_only_settlement_group_layout() -> Result<GroupLayout, ProverError> {
    let circuit_layout =
        IntentOnlyPublicSettlementCircuit::get_circuit_layout().map_err(ProverError::Plonk)?;
    Ok(circuit_layout.get_group_layout(INTENT_ONLY_SETTLEMENT_LINK))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        singleprover_prove_with_hint,
        zk_circuits::{
            settlement::intent_only_bounded_settlement::IntentOnlyBoundedSettlementCircuit,
            validity_proofs::{
                intent_only::IntentOnlyValidityCircuit,
                intent_only_first_fill::IntentOnlyFirstFillValidityCircuit,
            },
        },
    };
    use circuit_types::traits::SingleProverCircuit;

    /// The Merkle height used for testing
    const TEST_MERKLE_HEIGHT: usize = 3;
    /// Intent only first fill validity with testing sizing
    type SizedIntentOnlyFirstFillValidity = IntentOnlyFirstFillValidityCircuit;
    /// Intent only validity with testing sizing
    type SizedIntentOnlyValidity = IntentOnlyValidityCircuit<TEST_MERKLE_HEIGHT>;

    // --------------------
    // | Exact Settlement |
    // --------------------

    // -----------
    // | Helpers |
    // -----------

    /// Prove INTENT ONLY FIRST FILL VALIDITY and INTENT ONLY PUBLIC SETTLEMENT,
    /// then link the proofs and verify the link
    fn test_intent_first_fill_exact_settlement_link(
        first_fill_witness: <SizedIntentOnlyFirstFillValidity as SingleProverCircuit>::Witness,
        first_fill_statement: <SizedIntentOnlyFirstFillValidity as SingleProverCircuit>::Statement,
        settlement_witness: <IntentOnlyPublicSettlementCircuit as SingleProverCircuit>::Witness,
        settlement_statement: <IntentOnlyPublicSettlementCircuit as SingleProverCircuit>::Statement,
    ) -> Result<(), ProverError> {
        // Create a proof of INTENT ONLY FIRST FILL VALIDITY and one of INTENT ONLY
        // PUBLIC SETTLEMENT
        let (first_fill_proof, first_fill_hint) = singleprover_prove_with_hint::<
            SizedIntentOnlyFirstFillValidity,
        >(
            &first_fill_witness, &first_fill_statement
        )?;
        let (settlement_proof, settlement_hint) = singleprover_prove_with_hint::<
            IntentOnlyPublicSettlementCircuit,
        >(
            &settlement_witness, &settlement_statement
        )?;

        // Link the proofs and verify the link
        let link_proof =
            link_intent_only_settlement::<TEST_MERKLE_HEIGHT>(&first_fill_hint, &settlement_hint)?;
        validate_intent_only_settlement_link::<TEST_MERKLE_HEIGHT>(
            &link_proof,
            &first_fill_proof,
            &settlement_proof,
        )
    }

    /// Build a first fill and settlement witness and statement with valid data
    ///
    /// This involves modifying the witness and statements for each circuit to
    /// align with one another so that they may be linked
    fn build_intent_first_fill_exact_settlement_data() -> (
        <SizedIntentOnlyFirstFillValidity as SingleProverCircuit>::Witness,
        <SizedIntentOnlyFirstFillValidity as SingleProverCircuit>::Statement,
        <IntentOnlyPublicSettlementCircuit as SingleProverCircuit>::Witness,
        <IntentOnlyPublicSettlementCircuit as SingleProverCircuit>::Statement,
    ) {
        use crate::test_helpers::random_intent;
        use crate::zk_circuits::{
            settlement::intent_only_public_settlement::test_helpers::create_witness_statement_with_intent as create_settlement_witness_statement,
            validity_proofs::intent_only_first_fill::test_helpers::create_witness_statement_with_intent as create_first_fill_witness_statement,
        };

        // Create a random intent
        let intent = random_intent();

        // Create the first fill witness and statement
        let (first_fill_witness, first_fill_statement) =
            create_first_fill_witness_statement(&intent);

        // Create the settlement witness and statement with the same intent
        let (settlement_witness, settlement_statement) =
            create_settlement_witness_statement(&intent);

        (first_fill_witness, first_fill_statement, settlement_witness, settlement_statement)
    }

    /// Build a validity and settlement witness and statement with valid data
    ///
    /// This involves modifying the witness and statements for each circuit to
    /// align with one another so that they may be linked
    fn build_intent_validity_exact_settlement_data() -> (
        <SizedIntentOnlyValidity as SingleProverCircuit>::Witness,
        <SizedIntentOnlyValidity as SingleProverCircuit>::Statement,
        <IntentOnlyPublicSettlementCircuit as SingleProverCircuit>::Witness,
        <IntentOnlyPublicSettlementCircuit as SingleProverCircuit>::Statement,
    ) {
        use crate::test_helpers::random_intent;
        use crate::zk_circuits::{
            settlement::intent_only_public_settlement::test_helpers::create_witness_statement_with_intent as create_settlement_witness_statement,
            validity_proofs::intent_only::test_helpers::create_witness_statement_with_intent as create_validity_witness_statement,
        };

        // Create a random intent
        let intent = random_intent();

        // Create the validity witness and statement
        let (validity_witness, validity_statement) =
            create_validity_witness_statement::<TEST_MERKLE_HEIGHT>(intent.clone());

        // Create the settlement witness and statement with the same intent
        let (settlement_witness, settlement_statement) =
            create_settlement_witness_statement(&intent);

        (validity_witness, validity_statement, settlement_witness, settlement_statement)
    }

    /// Prove INTENT ONLY VALIDITY and INTENT ONLY PUBLIC SETTLEMENT, then link
    /// the proofs and verify the link
    fn test_intent_validity_exact_settlement_link(
        validity_witness: <SizedIntentOnlyValidity as SingleProverCircuit>::Witness,
        validity_statement: <SizedIntentOnlyValidity as SingleProverCircuit>::Statement,
        settlement_witness: <IntentOnlyPublicSettlementCircuit as SingleProverCircuit>::Witness,
        settlement_statement: <IntentOnlyPublicSettlementCircuit as SingleProverCircuit>::Statement,
    ) -> Result<(), ProverError> {
        // Create a proof of INTENT ONLY VALIDITY and one of INTENT ONLY PUBLIC
        // SETTLEMENT
        let (validity_proof, validity_hint) = singleprover_prove_with_hint::<
            SizedIntentOnlyValidity,
        >(&validity_witness, &validity_statement)?;
        let (settlement_proof, settlement_hint) = singleprover_prove_with_hint::<
            IntentOnlyPublicSettlementCircuit,
        >(
            &settlement_witness, &settlement_statement
        )?;

        // Link the proofs and verify the link
        let link_proof =
            link_intent_only_settlement::<TEST_MERKLE_HEIGHT>(&validity_hint, &settlement_hint)?;
        validate_intent_only_settlement_link::<TEST_MERKLE_HEIGHT>(
            &link_proof,
            &validity_proof,
            &settlement_proof,
        )
    }

    // --------------
    // | Test Cases |
    // --------------

    /// Tests a valid link between a proof of INTENT ONLY FIRST FILL VALIDITY
    /// and a proof of INTENT ONLY PUBLIC SETTLEMENT
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    fn test_intent_first_fill_exact_settlement_valid_link() {
        let (first_fill_witness, first_fill_statement, settlement_witness, settlement_statement) =
            build_intent_first_fill_exact_settlement_data();

        test_intent_first_fill_exact_settlement_link(
            first_fill_witness,
            first_fill_statement,
            settlement_witness,
            settlement_statement,
        )
        .unwrap();
    }

    /// Tests a valid link between a proof of INTENT ONLY VALIDITY and a proof
    /// of INTENT ONLY PUBLIC SETTLEMENT
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    fn test_intent_validity_exact_settlement_valid_link() {
        let (validity_witness, validity_statement, settlement_witness, settlement_statement) =
            build_intent_validity_exact_settlement_data();

        test_intent_validity_exact_settlement_link(
            validity_witness,
            validity_statement,
            settlement_witness,
            settlement_statement,
        )
        .unwrap();
    }

    /// Tests an invalid link between a proof of INTENT ONLY FIRST FILL VALIDITY
    /// and a proof of INTENT ONLY PUBLIC SETTLEMENT wherein the intent is
    /// modified between the two proofs
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    #[should_panic(expected = "ProofLinkVerification")]
    #[allow(non_snake_case)]
    fn test_intent_first_fill_exact_settlement_invalid_link__modified_intent() {
        let (
            first_fill_witness,
            first_fill_statement,
            mut settlement_witness,
            settlement_statement,
        ) = build_intent_first_fill_exact_settlement_data();

        // Modify the intent in the settlement witness to break the link
        settlement_witness.intent.amount_in += 1;

        test_intent_first_fill_exact_settlement_link(
            first_fill_witness,
            first_fill_statement,
            settlement_witness,
            settlement_statement,
        )
        .unwrap();
    }

    // ----------------------
    // | Bounded Settlement |
    // ----------------------

    // -----------
    // | Helpers |
    // -----------

    /// Prove INTENT ONLY FIRST FILL VALIDITY and INTENT ONLY BOUNDED
    /// SETTLEMENT, then link the proofs and verify the link
    fn test_intent_first_fill_bounded_settlement_link(
        first_fill_witness: <SizedIntentOnlyFirstFillValidity as SingleProverCircuit>::Witness,
        first_fill_statement: <SizedIntentOnlyFirstFillValidity as SingleProverCircuit>::Statement,
        settlement_witness: <IntentOnlyBoundedSettlementCircuit as SingleProverCircuit>::Witness,
        settlement_statement: <IntentOnlyBoundedSettlementCircuit as SingleProverCircuit>::Statement,
    ) -> Result<(), ProverError> {
        // Create a proof of INTENT ONLY FIRST FILL VALIDITY and one of INTENT ONLY
        // BOUNDED SETTLEMENT
        let (first_fill_proof, first_fill_hint) = singleprover_prove_with_hint::<
            SizedIntentOnlyFirstFillValidity,
        >(
            &first_fill_witness, &first_fill_statement
        )?;
        let (settlement_proof, settlement_hint) = singleprover_prove_with_hint::<
            IntentOnlyBoundedSettlementCircuit,
        >(
            &settlement_witness, &settlement_statement
        )?;

        // Link the proofs and verify the link
        let link_proof =
            link_intent_only_settlement::<TEST_MERKLE_HEIGHT>(&first_fill_hint, &settlement_hint)?;
        validate_intent_only_settlement_link::<TEST_MERKLE_HEIGHT>(
            &link_proof,
            &first_fill_proof,
            &settlement_proof,
        )
    }

    /// Build a first fill and bounded settlement witness and statement with
    /// valid data
    ///
    /// This involves modifying the witness and statements for each circuit to
    /// align with one another so that they may be linked
    fn build_intent_first_fill_bounded_settlement_data() -> (
        <SizedIntentOnlyFirstFillValidity as SingleProverCircuit>::Witness,
        <SizedIntentOnlyFirstFillValidity as SingleProverCircuit>::Statement,
        <IntentOnlyBoundedSettlementCircuit as SingleProverCircuit>::Witness,
        <IntentOnlyBoundedSettlementCircuit as SingleProverCircuit>::Statement,
    ) {
        use crate::test_helpers::random_intent;
        use crate::zk_circuits::{
            settlement::intent_only_bounded_settlement::test_helpers::create_witness_statement_with_intent as create_settlement_witness_statement,
            validity_proofs::intent_only_first_fill::test_helpers::create_witness_statement_with_intent as create_first_fill_witness_statement,
        };

        // Create a random intent
        let intent = random_intent();

        // Create the first fill witness and statement
        let (first_fill_witness, first_fill_statement) =
            create_first_fill_witness_statement(&intent);

        // Create the settlement witness and statement with the same intent
        let (settlement_witness, settlement_statement) =
            create_settlement_witness_statement(&intent);

        (first_fill_witness, first_fill_statement, settlement_witness, settlement_statement)
    }

    /// Build a validity and bounded settlement witness and statement with valid
    /// data
    ///
    /// This involves modifying the witness and statements for each circuit to
    /// align with one another so that they may be linked
    fn build_intent_validity_bounded_settlement_data() -> (
        <SizedIntentOnlyValidity as SingleProverCircuit>::Witness,
        <SizedIntentOnlyValidity as SingleProverCircuit>::Statement,
        <IntentOnlyBoundedSettlementCircuit as SingleProverCircuit>::Witness,
        <IntentOnlyBoundedSettlementCircuit as SingleProverCircuit>::Statement,
    ) {
        use crate::test_helpers::random_intent;
        use crate::zk_circuits::{
            settlement::intent_only_bounded_settlement::test_helpers::create_witness_statement_with_intent as create_settlement_witness_statement,
            validity_proofs::intent_only::test_helpers::create_witness_statement_with_intent as create_validity_witness_statement,
        };

        // Create a random intent
        let intent = random_intent();

        // Create the validity witness and statement
        let (validity_witness, validity_statement) =
            create_validity_witness_statement::<TEST_MERKLE_HEIGHT>(intent.clone());

        // Create the settlement witness and statement with the same intent
        let (settlement_witness, settlement_statement) =
            create_settlement_witness_statement(&intent);

        (validity_witness, validity_statement, settlement_witness, settlement_statement)
    }

    /// Prove INTENT ONLY VALIDITY and INTENT ONLY BOUNDED SETTLEMENT, then link
    /// the proofs and verify the link
    fn test_intent_validity_bounded_settlement_link(
        validity_witness: <SizedIntentOnlyValidity as SingleProverCircuit>::Witness,
        validity_statement: <SizedIntentOnlyValidity as SingleProverCircuit>::Statement,
        settlement_witness: <IntentOnlyBoundedSettlementCircuit as SingleProverCircuit>::Witness,
        settlement_statement: <IntentOnlyBoundedSettlementCircuit as SingleProverCircuit>::Statement,
    ) -> Result<(), ProverError> {
        // Create a proof of INTENT ONLY VALIDITY and one of INTENT ONLY BOUNDED
        // SETTLEMENT
        let (validity_proof, validity_hint) = singleprover_prove_with_hint::<
            SizedIntentOnlyValidity,
        >(&validity_witness, &validity_statement)?;
        let (settlement_proof, settlement_hint) = singleprover_prove_with_hint::<
            IntentOnlyBoundedSettlementCircuit,
        >(
            &settlement_witness, &settlement_statement
        )?;

        // Link the proofs and verify the link
        let link_proof =
            link_intent_only_settlement::<TEST_MERKLE_HEIGHT>(&validity_hint, &settlement_hint)?;
        validate_intent_only_settlement_link::<TEST_MERKLE_HEIGHT>(
            &link_proof,
            &validity_proof,
            &settlement_proof,
        )
    }

    // --------------
    // | Test Cases |
    // --------------

    /// Tests a valid link between a proof of INTENT ONLY FIRST FILL VALIDITY
    /// and a proof of INTENT ONLY BOUNDED SETTLEMENT
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    fn test_intent_first_fill_bounded_settlement_valid_link() {
        let (first_fill_witness, first_fill_statement, settlement_witness, settlement_statement) =
            build_intent_first_fill_bounded_settlement_data();

        test_intent_first_fill_bounded_settlement_link(
            first_fill_witness,
            first_fill_statement,
            settlement_witness,
            settlement_statement,
        )
        .unwrap();
    }

    /// Tests a valid link between a proof of INTENT ONLY VALIDITY and a proof
    /// of INTENT ONLY BOUNDED SETTLEMENT
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    fn test_intent_validity_bounded_settlement_valid_link() {
        let (validity_witness, validity_statement, settlement_witness, settlement_statement) =
            build_intent_validity_bounded_settlement_data();

        test_intent_validity_bounded_settlement_link(
            validity_witness,
            validity_statement,
            settlement_witness,
            settlement_statement,
        )
        .unwrap();
    }

    /// Tests an invalid link between a proof of INTENT ONLY FIRST FILL VALIDITY
    /// and a proof of INTENT ONLY BOUNDED SETTLEMENT wherein the intent is
    /// modified between the two proofs
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    #[should_panic(expected = "ProofLinkVerification")]
    #[allow(non_snake_case)]
    fn test_intent_first_fill_bounded_settlement_invalid_link__modified_intent() {
        let (
            first_fill_witness,
            first_fill_statement,
            mut settlement_witness,
            settlement_statement,
        ) = build_intent_first_fill_bounded_settlement_data();

        // Modify the intent in the settlement witness to break the link
        settlement_witness.intent.amount_in += 1;

        test_intent_first_fill_bounded_settlement_link(
            first_fill_witness,
            first_fill_statement,
            settlement_witness,
            settlement_statement,
        )
        .unwrap();
    }
}
