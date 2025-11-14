//! Helpers for linking proofs between intent and balance validity and
//! settlement circuits

use circuit_types::{
    PlonkLinkProof, PlonkProof, ProofLinkingHint, errors::ProverError, traits::SingleProverCircuit,
};
use constants::MERKLE_HEIGHT;
use mpc_plonk::{proof_system::PlonkKzgSnark, transcript::SolidityTranscript};
use mpc_relation::proof_linking::GroupLayout;

use crate::zk_circuits::{
    settlement::{
        INTENT_AND_BALANCE_SETTLEMENT_PARTY0_LINK,
        intent_and_balance_public_settlement::IntentAndBalancePublicSettlementCircuit,
    },
    validity_proofs::intent_and_balance::IntentAndBalanceValidityCircuit,
};

// ------------------------------------------------------------------------
// | Intent And Balance Validity <-> Intent And Balance Public Settlement |
// ------------------------------------------------------------------------

/// Link an intent and balance validity proof with a proof of INTENT AND BALANCE
/// PUBLIC SETTLEMENT using the system wide sizing constants
pub fn link_sized_intent_and_balance_settlement(
    validity_link_hint: &ProofLinkingHint,
    settlement_link_hint: &ProofLinkingHint,
) -> Result<PlonkLinkProof, ProverError> {
    link_intent_and_balance_settlement::<MERKLE_HEIGHT>(validity_link_hint, settlement_link_hint)
}

/// Link an intent and balance validity proof with a proof of INTENT AND BALANCE
/// PUBLIC SETTLEMENT
pub fn link_intent_and_balance_settlement<const MERKLE_HEIGHT: usize>(
    validity_link_hint: &ProofLinkingHint,
    settlement_link_hint: &ProofLinkingHint,
) -> Result<PlonkLinkProof, ProverError> {
    // Get the group layout for the validity <-> settlement link group
    let layout = get_group_layout::<MERKLE_HEIGHT>()?;
    let pk = IntentAndBalanceValidityCircuit::<MERKLE_HEIGHT>::proving_key();

    PlonkKzgSnark::link_proofs::<SolidityTranscript>(
        validity_link_hint,
        settlement_link_hint,
        &layout,
        &pk.commit_key,
    )
    .map_err(ProverError::Plonk)
}

/// Validate a link between an intent and balance validity proof with a
/// proof of INTENT AND BALANCE PUBLIC SETTLEMENT using the system wide sizing
/// constants
pub fn validate_sized_intent_and_balance_settlement_link(
    link_proof: &PlonkLinkProof,
    validity_proof: &PlonkProof,
    settlement_proof: &PlonkProof,
) -> Result<(), ProverError> {
    validate_intent_and_balance_settlement_link::<MERKLE_HEIGHT>(
        link_proof,
        validity_proof,
        settlement_proof,
    )
}

/// Validate a link between an intent and balance validity proof with a
/// proof of INTENT AND BALANCE PUBLIC SETTLEMENT
pub fn validate_intent_and_balance_settlement_link<const MERKLE_HEIGHT: usize>(
    link_proof: &PlonkLinkProof,
    validity_proof: &PlonkProof,
    settlement_proof: &PlonkProof,
) -> Result<(), ProverError> {
    // Get the group layout for the validity <-> settlement link group
    let layout = get_group_layout::<MERKLE_HEIGHT>()?;
    let vk = IntentAndBalanceValidityCircuit::<MERKLE_HEIGHT>::verifying_key();

    PlonkKzgSnark::verify_link_proof::<SolidityTranscript>(
        validity_proof,
        settlement_proof,
        link_proof,
        &layout,
        &vk.open_key,
    )
    .map_err(ProverError::Plonk)
}

/// Get the group layout for the intent and balance validity <-> public
/// settlement link group
pub fn get_group_layout<const MERKLE_HEIGHT: usize>() -> Result<GroupLayout, ProverError> {
    let circuit_layout = IntentAndBalancePublicSettlementCircuit::get_circuit_layout()
        .map_err(ProverError::Plonk)?;
    Ok(circuit_layout.get_group_layout(INTENT_AND_BALANCE_SETTLEMENT_PARTY0_LINK))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        singleprover_prove_with_hint,
        test_helpers::{create_settlement_obligation_with_balance, random_intent},
        zk_circuits::{
            settlement::intent_and_balance_public_settlement::{
                IntentAndBalancePublicSettlementStatement, IntentAndBalancePublicSettlementWitness,
                test_helpers::create_witness_statement_with_intent_balance_and_obligation as create_settlement_witness_statement,
            },
            validity_proofs::{
                intent_and_balance::{
                    IntentAndBalanceValidityStatement, IntentAndBalanceValidityWitness,
                    test_helpers::create_witness_statement_with_intent as create_validity_witness_statement,
                },
                intent_and_balance_first_fill::{
                    IntentAndBalanceFirstFillValidityCircuit,
                    IntentAndBalanceFirstFillValidityStatement,
                    IntentAndBalanceFirstFillValidityWitness,
                    test_helpers::create_witness_statement as create_witness_statement_first_fill,
                },
            },
        },
    };
    use circuit_types::balance::PostMatchBalanceShare;
    use constants::Scalar;
    use rand::thread_rng;

    /// The Merkle height used for testing
    const TEST_MERKLE_HEIGHT: usize = 3;
    /// Intent and balance validity with testing sizing
    type SizedIntentAndBalanceValidity = IntentAndBalanceValidityCircuit<TEST_MERKLE_HEIGHT>;
    /// Intent and balance first fill validity with testing sizing
    type SizedIntentAndBalanceFirstFillValidity =
        IntentAndBalanceFirstFillValidityCircuit<TEST_MERKLE_HEIGHT>;

    // -----------
    // | Helpers |
    // -----------

    /// Prove INTENT AND BALANCE VALIDITY and INTENT AND BALANCE PUBLIC
    /// SETTLEMENT, then link the proofs and verify the link
    fn test_intent_and_balance_validity_settlement_link(
        validity_witness: IntentAndBalanceValidityWitness<TEST_MERKLE_HEIGHT>,
        validity_statement: IntentAndBalanceValidityStatement,
        settlement_witness: IntentAndBalancePublicSettlementWitness,
        settlement_statement: IntentAndBalancePublicSettlementStatement,
    ) -> Result<(), ProverError> {
        // Create a proof of INTENT AND BALANCE VALIDITY and one of INTENT AND BALANCE
        // PUBLIC SETTLEMENT
        let (validity_proof, validity_hint) = singleprover_prove_with_hint::<
            SizedIntentAndBalanceValidity,
        >(validity_witness, validity_statement)?;
        let (settlement_proof, settlement_hint) = singleprover_prove_with_hint::<
            IntentAndBalancePublicSettlementCircuit,
        >(
            settlement_witness, settlement_statement
        )?;

        // Link the proofs and verify the link
        let link_proof = link_intent_and_balance_settlement::<TEST_MERKLE_HEIGHT>(
            &validity_hint,
            &settlement_hint,
        )?;
        validate_intent_and_balance_settlement_link::<TEST_MERKLE_HEIGHT>(
            &link_proof,
            &validity_proof,
            &settlement_proof,
        )
    }

    /// Build a validity and settlement witness and statement with valid data
    ///
    /// This involves modifying the witness and statements for each circuit to
    /// align with one another so that they may be linked
    fn build_intent_and_balance_validity_settlement_data() -> (
        IntentAndBalanceValidityWitness<TEST_MERKLE_HEIGHT>,
        IntentAndBalanceValidityStatement,
        IntentAndBalancePublicSettlementWitness,
        IntentAndBalancePublicSettlementStatement,
    ) {
        // Create the validity witness and statement
        let intent = random_intent();
        let (validity_witness, validity_statement) =
            create_validity_witness_statement::<TEST_MERKLE_HEIGHT>(intent.clone());

        // Create a settlement obligation that matches the validity witness
        let settlement_obligation = create_settlement_obligation_with_balance(
            &validity_witness.intent,
            validity_witness.balance.amount,
        );

        // Create the settlement witness and statement using the validity witness data
        let (mut settlement_witness, mut settlement_statement) =
            create_settlement_witness_statement::<TEST_MERKLE_HEIGHT>(
                &validity_witness.intent,
                &validity_witness.balance,
                settlement_obligation,
            );

        // Align the settlement witness with the validity witness
        settlement_witness.pre_settlement_amount_public_share =
            validity_witness.new_amount_public_share;
        settlement_witness.intent = validity_witness.intent.clone();
        settlement_witness.in_balance = validity_witness.balance.clone();
        settlement_witness.pre_settlement_in_balance_shares =
            validity_witness.post_match_balance_shares.clone();

        // Update the statement to reflect the settlement
        let amt_int = Scalar::from(settlement_statement.settlement_obligation.amount_in);
        settlement_statement.new_amount_public_share =
            settlement_witness.pre_settlement_amount_public_share - amt_int;

        // Update the balance shares in the statement
        let amt_out = Scalar::from(settlement_statement.settlement_obligation.amount_out);
        settlement_statement.new_in_balance_public_shares = PostMatchBalanceShare {
            amount: settlement_witness.pre_settlement_in_balance_shares.amount - amt_int,
            relayer_fee_balance: settlement_witness
                .pre_settlement_in_balance_shares
                .relayer_fee_balance,
            protocol_fee_balance: settlement_witness
                .pre_settlement_in_balance_shares
                .protocol_fee_balance,
        };
        settlement_statement.new_out_balance_public_shares = PostMatchBalanceShare {
            amount: settlement_witness.pre_settlement_out_balance_shares.amount + amt_out,
            relayer_fee_balance: settlement_witness
                .pre_settlement_out_balance_shares
                .relayer_fee_balance,
            protocol_fee_balance: settlement_witness
                .pre_settlement_out_balance_shares
                .protocol_fee_balance,
        };

        (validity_witness, validity_statement, settlement_witness, settlement_statement)
    }

    /// Prove INTENT AND BALANCE FIRST FILL VALIDITY and INTENT AND BALANCE
    /// PUBLIC SETTLEMENT, then link the proofs and verify the link
    fn test_intent_and_balance_first_fill_validity_settlement_link(
        validity_witness: IntentAndBalanceFirstFillValidityWitness<TEST_MERKLE_HEIGHT>,
        validity_statement: IntentAndBalanceFirstFillValidityStatement,
        settlement_witness: IntentAndBalancePublicSettlementWitness,
        settlement_statement: IntentAndBalancePublicSettlementStatement,
    ) -> Result<(), ProverError> {
        // Create a proof of INTENT AND BALANCE FIRST FILL VALIDITY and one of INTENT
        // AND BALANCE PUBLIC SETTLEMENT
        let (validity_proof, validity_hint) = singleprover_prove_with_hint::<
            SizedIntentAndBalanceFirstFillValidity,
        >(validity_witness, validity_statement)?;
        let (settlement_proof, settlement_hint) = singleprover_prove_with_hint::<
            IntentAndBalancePublicSettlementCircuit,
        >(
            settlement_witness, settlement_statement
        )?;

        let link_proof = link_intent_and_balance_settlement::<TEST_MERKLE_HEIGHT>(
            &validity_hint,
            &settlement_hint,
        )?;
        validate_intent_and_balance_settlement_link::<TEST_MERKLE_HEIGHT>(
            &link_proof,
            &validity_proof,
            &settlement_proof,
        )
    }

    /// Build a first fill validity and settlement witness and statement with
    /// valid data
    ///
    /// This involves modifying the witness and statements for each circuit to
    /// align with one another so that they may be linked
    fn build_intent_and_balance_first_fill_validity_settlement_data() -> (
        IntentAndBalanceFirstFillValidityWitness<TEST_MERKLE_HEIGHT>,
        IntentAndBalanceFirstFillValidityStatement,
        IntentAndBalancePublicSettlementWitness,
        IntentAndBalancePublicSettlementStatement,
    ) {
        let (validity_witness, validity_statement) = create_witness_statement_first_fill();

        // Create a settlement obligation that matches the validity witness
        let settlement_obligation = create_settlement_obligation_with_balance(
            &validity_witness.intent,
            validity_witness.balance.amount,
        );

        // Create the settlement witness and statement using the validity witness data
        let (mut settlement_witness, mut settlement_statement) =
            create_settlement_witness_statement::<TEST_MERKLE_HEIGHT>(
                &validity_witness.intent,
                &validity_witness.balance,
                settlement_obligation,
            );

        // Align the settlement witness with the validity witness
        settlement_witness.pre_settlement_amount_public_share =
            validity_witness.new_amount_public_share;
        settlement_witness.intent = validity_witness.intent.clone();
        settlement_witness.in_balance = validity_witness.balance.clone();
        settlement_witness.pre_settlement_in_balance_shares =
            validity_witness.post_match_balance_shares.clone();

        // Update the statement to reflect the settlement
        let amt_in = Scalar::from(settlement_statement.settlement_obligation.amount_in);
        settlement_statement.new_amount_public_share =
            settlement_witness.pre_settlement_amount_public_share - amt_in;

        let original_shares = settlement_witness.pre_settlement_in_balance_shares.clone();
        settlement_statement.new_in_balance_public_shares = PostMatchBalanceShare {
            amount: original_shares.amount - amt_in,
            relayer_fee_balance: original_shares.relayer_fee_balance,
            protocol_fee_balance: original_shares.protocol_fee_balance,
        };

        (validity_witness, validity_statement, settlement_witness, settlement_statement)
    }

    // --------------
    // | Test Cases |
    // --------------

    /// Tests a valid link between a proof of INTENT AND BALANCE VALIDITY and a
    /// proof of INTENT AND BALANCE PUBLIC SETTLEMENT
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    fn test_intent_and_balance_valid_link() {
        let (validity_witness, validity_statement, settlement_witness, settlement_statement) =
            build_intent_and_balance_validity_settlement_data();

        test_intent_and_balance_validity_settlement_link(
            validity_witness,
            validity_statement,
            settlement_witness,
            settlement_statement,
        )
        .unwrap();
    }

    /// Tests a valid link between a proof of INTENT AND BALANCE FIRST FILL
    /// VALIDITY and a proof of INTENT AND BALANCE PUBLIC SETTLEMENT
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    fn test_intent_and_balance_first_fill_valid_link() {
        let (validity_witness, validity_statement, settlement_witness, settlement_statement) =
            build_intent_and_balance_first_fill_validity_settlement_data();

        test_intent_and_balance_first_fill_validity_settlement_link(
            validity_witness,
            validity_statement,
            settlement_witness,
            settlement_statement,
        )
        .unwrap();
    }

    /// Tests an invalid link between a proof of INTENT AND BALANCE VALIDITY
    /// and a proof of INTENT AND BALANCE PUBLIC SETTLEMENT wherein the intent
    /// is modified between the two proofs
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    #[should_panic(expected = "ProofLinkVerification")]
    #[allow(non_snake_case)]
    fn test_intent_and_balance_invalid_link__modified_intent() {
        let (validity_witness, validity_statement, mut settlement_witness, settlement_statement) =
            build_intent_and_balance_validity_settlement_data();

        // Modify the intent in the settlement witness to break the link
        settlement_witness.intent.amount_in += 1;
        test_intent_and_balance_validity_settlement_link(
            validity_witness,
            validity_statement,
            settlement_witness,
            settlement_statement,
        )
        .unwrap();
    }

    /// Tests an invalid link between a proof of INTENT AND BALANCE VALIDITY
    /// and a proof of INTENT AND BALANCE PUBLIC SETTLEMENT wherein the amount
    /// public share is modified between the two proofs
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    #[should_panic(expected = "ProofLinkVerification")]
    #[allow(non_snake_case)]
    fn test_intent_and_balance_invalid_link__modified_amount_public_share() {
        let (
            validity_witness,
            validity_statement,
            mut settlement_witness,
            mut settlement_statement,
        ) = build_intent_and_balance_validity_settlement_data();

        // Modify the amount public share in the settlement witness to break the link
        // We also need to update the statement to keep the settlement circuit valid
        let mut rng = thread_rng();
        let modification = Scalar::random(&mut rng);
        settlement_witness.pre_settlement_amount_public_share += modification;
        // Update the statement to keep the settlement circuit constraints satisfied
        settlement_statement.new_amount_public_share += modification;

        // Now the settlement circuit is valid, but the link will fail
        test_intent_and_balance_validity_settlement_link(
            validity_witness,
            validity_statement,
            settlement_witness,
            settlement_statement,
        )
        .unwrap();
    }

    /// Tests an invalid link between a proof of INTENT AND BALANCE VALIDITY
    /// and a proof of INTENT AND BALANCE PUBLIC SETTLEMENT wherein the balance
    /// is modified between the two proofs
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    #[should_panic(expected = "ProofLinkVerification")]
    #[allow(non_snake_case)]
    fn test_intent_and_balance_invalid_link__modified_balance() {
        use crate::test_helpers::{random_address, random_amount};
        use circuit_types::balance::Balance;

        let (validity_witness, validity_statement, mut settlement_witness, settlement_statement) =
            build_intent_and_balance_validity_settlement_data();

        // Modify the balance in the settlement witness to break the link
        settlement_witness.in_balance = Balance {
            mint: random_address(),
            owner: random_address(),
            relayer_fee_recipient: random_address(),
            one_time_authority: random_address(),
            relayer_fee_balance: random_amount(),
            protocol_fee_balance: random_amount(),
            amount: random_amount(),
        };

        test_intent_and_balance_validity_settlement_link(
            validity_witness,
            validity_statement,
            settlement_witness,
            settlement_statement,
        )
        .unwrap();
    }

    /// Tests an invalid link between a proof of INTENT AND BALANCE VALIDITY
    /// and a proof of INTENT AND BALANCE PUBLIC SETTLEMENT wherein the balance
    /// shares are modified between the two proofs
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    #[should_panic(expected = "ProofLinkVerification")]
    #[allow(non_snake_case)]
    fn test_intent_and_balance_invalid_link__modified_balance_shares() {
        use constants::Scalar;
        use rand::thread_rng;

        let (
            validity_witness,
            validity_statement,
            mut settlement_witness,
            mut settlement_statement,
        ) = build_intent_and_balance_validity_settlement_data();

        // Modify the balance shares in the settlement witness to break the link
        // We also need to update the statement to keep the settlement circuit valid
        let mut rng = thread_rng();
        let modification = Scalar::random(&mut rng);
        settlement_witness.pre_settlement_in_balance_shares.amount += modification;
        // Update the statement to keep the settlement circuit constraints satisfied
        settlement_statement.new_in_balance_public_shares.amount += modification;

        // Now the settlement circuit is valid, but the link will fail because
        // settlement_witness.pre_settlement_in_balance_shares doesn't match
        // validity_witness.post_match_balance_shares
        test_intent_and_balance_validity_settlement_link(
            validity_witness,
            validity_statement,
            settlement_witness,
            settlement_statement,
        )
        .unwrap();
    }
}
