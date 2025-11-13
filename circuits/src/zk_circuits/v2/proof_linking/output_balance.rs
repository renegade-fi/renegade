//! Helpers for linking proofs between output balance validity and
//! settlement circuits

use circuit_types::{
    PlonkLinkProof, PlonkProof, ProofLinkingHint, errors::ProverError, traits::SingleProverCircuit,
};
use constants::MERKLE_HEIGHT;
use mpc_plonk::{proof_system::PlonkKzgSnark, transcript::SolidityTranscript};
use mpc_relation::proof_linking::GroupLayout;

use crate::zk_circuits::v2::{
    settlement::{
        OUTPUT_BALANCE_SETTLEMENT_LINK,
        intent_and_balance_public_settlement::IntentAndBalancePublicSettlementCircuit,
    },
    validity_proofs::output_balance::OutputBalanceValidityCircuit,
};

// --------------------------------------------------------------------
// | Output Balance Validity <-> Intent And Balance Public Settlement |
// --------------------------------------------------------------------

/// Link an output balance validity proof with a proof of INTENT AND BALANCE
/// PUBLIC SETTLEMENT using the system wide sizing constants
pub fn link_sized_output_balance_settlement(
    validity_link_hint: &ProofLinkingHint,
    settlement_link_hint: &ProofLinkingHint,
) -> Result<PlonkLinkProof, ProverError> {
    link_output_balance_settlement::<MERKLE_HEIGHT>(validity_link_hint, settlement_link_hint)
}

/// Link an output balance validity proof with a proof of INTENT AND BALANCE
/// PUBLIC SETTLEMENT
pub fn link_output_balance_settlement<const MERKLE_HEIGHT: usize>(
    validity_link_hint: &ProofLinkingHint,
    settlement_link_hint: &ProofLinkingHint,
) -> Result<PlonkLinkProof, ProverError> {
    // Get the group layout for the validity <-> settlement link group
    let layout = get_group_layout::<MERKLE_HEIGHT>()?;
    let pk = OutputBalanceValidityCircuit::<MERKLE_HEIGHT>::proving_key();

    PlonkKzgSnark::link_proofs::<SolidityTranscript>(
        validity_link_hint,
        settlement_link_hint,
        &layout,
        &pk.commit_key,
    )
    .map_err(ProverError::Plonk)
}

/// Validate a link between an output balance validity proof with a
/// proof of INTENT AND BALANCE PUBLIC SETTLEMENT using the system wide sizing
/// constants
pub fn validate_sized_output_balance_settlement_link(
    link_proof: &PlonkLinkProof,
    validity_proof: &PlonkProof,
    settlement_proof: &PlonkProof,
) -> Result<(), ProverError> {
    validate_output_balance_settlement_link::<MERKLE_HEIGHT>(
        link_proof,
        validity_proof,
        settlement_proof,
    )
}

/// Validate a link between an output balance validity proof with a
/// proof of INTENT AND BALANCE PUBLIC SETTLEMENT
pub fn validate_output_balance_settlement_link<const MERKLE_HEIGHT: usize>(
    link_proof: &PlonkLinkProof,
    validity_proof: &PlonkProof,
    settlement_proof: &PlonkProof,
) -> Result<(), ProverError> {
    // Get the group layout for the validity <-> settlement link group
    let layout = get_group_layout::<MERKLE_HEIGHT>()?;
    let vk = OutputBalanceValidityCircuit::<MERKLE_HEIGHT>::verifying_key();

    PlonkKzgSnark::verify_link_proof::<SolidityTranscript>(
        validity_proof,
        settlement_proof,
        link_proof,
        &layout,
        &vk.open_key,
    )
    .map_err(ProverError::Plonk)
}

/// Get the group layout for the output balance validity <-> public
/// settlement link group
pub fn get_group_layout<const MERKLE_HEIGHT: usize>() -> Result<GroupLayout, ProverError> {
    let circuit_layout = IntentAndBalancePublicSettlementCircuit::get_circuit_layout()
        .map_err(ProverError::Plonk)?;
    Ok(circuit_layout.get_group_layout(OUTPUT_BALANCE_SETTLEMENT_LINK))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        singleprover_prove_with_hint,
        zk_circuits::{
            settlement::intent_and_balance_public_settlement::{
                IntentAndBalancePublicSettlementStatement, IntentAndBalancePublicSettlementWitness,
                test_helpers::{
                    create_matching_balance_for_intent,
                    create_witness_statement_with_intent_balance_and_obligation as create_settlement_witness_statement,
                },
            },
            validity_proofs::output_balance::{
                OutputBalanceValidityStatement, OutputBalanceValidityWitness,
                test_helpers::create_witness_statement as create_validity_witness_statement,
            },
        },
    };
    use circuit_types::balance::PostMatchBalanceShare;
    use constants::Scalar;
    use rand::thread_rng;

    /// The Merkle height used for testing
    const TEST_MERKLE_HEIGHT: usize = 3;
    /// Output balance validity with testing sizing
    type SizedOutputBalanceValidity = OutputBalanceValidityCircuit<TEST_MERKLE_HEIGHT>;

    // -----------
    // | Helpers |
    // -----------

    /// Prove OUTPUT BALANCE VALIDITY and INTENT AND BALANCE PUBLIC
    /// SETTLEMENT, then link the proofs and verify the link
    fn test_output_balance_validity_settlement_link(
        validity_witness: OutputBalanceValidityWitness<TEST_MERKLE_HEIGHT>,
        validity_statement: OutputBalanceValidityStatement,
        settlement_witness: IntentAndBalancePublicSettlementWitness,
        settlement_statement: IntentAndBalancePublicSettlementStatement,
    ) -> Result<(), ProverError> {
        // Create a proof of OUTPUT BALANCE VALIDITY and one of INTENT AND BALANCE
        // PUBLIC SETTLEMENT
        let (validity_proof, validity_hint) = singleprover_prove_with_hint::<
            SizedOutputBalanceValidity,
        >(validity_witness, validity_statement)?;
        let (settlement_proof, settlement_hint) = singleprover_prove_with_hint::<
            IntentAndBalancePublicSettlementCircuit,
        >(
            settlement_witness, settlement_statement
        )?;

        // Link the proofs and verify the link
        let link_proof =
            link_output_balance_settlement::<TEST_MERKLE_HEIGHT>(&validity_hint, &settlement_hint)?;
        validate_output_balance_settlement_link::<TEST_MERKLE_HEIGHT>(
            &link_proof,
            &validity_proof,
            &settlement_proof,
        )
    }

    /// Build a validity and settlement witness and statement with valid data
    ///
    /// This involves modifying the witness and statements for each circuit to
    /// align with one another so that they may be linked
    fn build_output_balance_validity_settlement_data() -> (
        OutputBalanceValidityWitness<TEST_MERKLE_HEIGHT>,
        OutputBalanceValidityStatement,
        IntentAndBalancePublicSettlementWitness,
        IntentAndBalancePublicSettlementStatement,
    ) {
        use crate::test_helpers::{create_settlement_obligation_with_balance, random_intent};

        // Create the validity witness and statement
        let (validity_witness, validity_statement) =
            create_validity_witness_statement::<TEST_MERKLE_HEIGHT>();

        // Create an intent and input balance for the settlement
        let output_balance = validity_witness.balance.clone();
        let mut intent = random_intent();
        intent.out_token = output_balance.mint;
        let input_balance = create_matching_balance_for_intent(&intent);
        let settlement_obligation =
            create_settlement_obligation_with_balance(&intent, input_balance.amount);

        // Create the settlement witness and statement
        let (mut settlement_witness, mut settlement_statement) =
            create_settlement_witness_statement::<TEST_MERKLE_HEIGHT>(
                &intent,
                &input_balance,
                settlement_obligation,
            );

        // Align the settlement witness with the validity witness
        settlement_witness.out_balance = validity_witness.balance.clone();
        settlement_witness.pre_settlement_out_balance_shares =
            validity_witness.post_match_balance_shares.clone();

        // Update the statement to reflect the settlement
        let amt_out = Scalar::from(settlement_statement.settlement_obligation.amount_out);
        let original_shares = settlement_witness.pre_settlement_out_balance_shares.clone();
        settlement_statement.new_out_balance_public_shares = PostMatchBalanceShare {
            amount: original_shares.amount + amt_out,
            relayer_fee_balance: original_shares.relayer_fee_balance,
            protocol_fee_balance: original_shares.protocol_fee_balance,
        };

        (validity_witness, validity_statement, settlement_witness, settlement_statement)
    }

    // --------------
    // | Test Cases |
    // --------------

    /// Tests a valid link between a proof of OUTPUT BALANCE VALIDITY and a
    /// proof of INTENT AND BALANCE PUBLIC SETTLEMENT
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    fn test_output_balance_valid_link() {
        let (validity_witness, validity_statement, settlement_witness, settlement_statement) =
            build_output_balance_validity_settlement_data();

        test_output_balance_validity_settlement_link(
            validity_witness,
            validity_statement,
            settlement_witness,
            settlement_statement,
        )
        .unwrap();
    }

    /// Tests an invalid link between a proof of OUTPUT BALANCE VALIDITY
    /// and a proof of INTENT AND BALANCE PUBLIC SETTLEMENT wherein the balance
    /// is modified between the two proofs
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    #[should_panic(expected = "ProofLinkVerification")]
    #[allow(non_snake_case)]
    fn test_output_balance_invalid_link__modified_balance() {
        let (validity_witness, validity_statement, mut settlement_witness, settlement_statement) =
            build_output_balance_validity_settlement_data();

        // Modify the balance in the settlement witness to break the link
        settlement_witness.out_balance.amount += 1;
        test_output_balance_validity_settlement_link(
            validity_witness,
            validity_statement,
            settlement_witness,
            settlement_statement,
        )
        .unwrap();
    }

    /// Tests an invalid link between a proof of OUTPUT BALANCE VALIDITY
    /// and a proof of INTENT AND BALANCE PUBLIC SETTLEMENT wherein the balance
    /// shares are modified between the two proofs
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    #[should_panic(expected = "ProofLinkVerification")]
    #[allow(non_snake_case)]
    fn test_output_balance_invalid_link__modified_balance_shares() {
        let (
            validity_witness,
            validity_statement,
            mut settlement_witness,
            mut settlement_statement,
        ) = build_output_balance_validity_settlement_data();

        // Modify the balance shares in the settlement witness to break the link
        // We also need to update the statement to keep the settlement circuit valid
        let mut rng = thread_rng();
        let modification = Scalar::random(&mut rng);
        settlement_witness.pre_settlement_out_balance_shares.amount += modification;
        // Update the statement to keep the settlement circuit constraints satisfied
        settlement_statement.new_out_balance_public_shares.amount += modification;

        // Now the settlement circuit is valid, but the link will fail
        test_output_balance_validity_settlement_link(
            validity_witness,
            validity_statement,
            settlement_witness,
            settlement_statement,
        )
        .unwrap();
    }
}
