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
        INTENT_AND_BALANCE_SETTLEMENT_PARTY0_LINK, INTENT_AND_BALANCE_SETTLEMENT_PARTY1_LINK,
        intent_and_balance_private_settlement::IntentAndBalancePrivateSettlementCircuit,
    },
    validity_proofs::intent_and_balance::IntentAndBalanceValidityCircuit,
};

// ------------------------------------------------------------------------------------
// | Intent And Balance Validity <-> Intent And Balance Settlement (Exact or Bounded) |
// ------------------------------------------------------------------------------------

/// Link an intent and balance validity proof with a proof of INTENT AND BALANCE
/// SETTLEMENT (exact, bounded, or private) using the system wide sizing
/// constant for party 0
///
/// This is also used for settlement circuits which only settle one user's
/// intent and balance
pub fn link_sized_intent_and_balance_settlement(
    validity_link_hint: &ProofLinkingHint,
    settlement_link_hint: &ProofLinkingHint,
) -> Result<PlonkLinkProof, ProverError> {
    link_intent_and_balance_settlement_with_party::<MERKLE_HEIGHT>(
        0, // party_id
        validity_link_hint,
        settlement_link_hint,
    )
}

/// Link an intent and balance validity proof with a proof of INTENT AND BALANCE
/// SETTLEMENT (exact, bounded, or private) using the system wide sizing
/// constants for the given party
pub fn link_sized_intent_and_balance_settlement_with_party(
    party_id: u8,
    validity_link_hint: &ProofLinkingHint,
    settlement_link_hint: &ProofLinkingHint,
) -> Result<PlonkLinkProof, ProverError> {
    link_intent_and_balance_settlement_with_party::<MERKLE_HEIGHT>(
        party_id,
        validity_link_hint,
        settlement_link_hint,
    )
}

/// Link an intent and balance validity proof with a proof of INTENT AND BALANCE
/// SETTLEMENT (exact, bounded, or private)
pub fn link_intent_and_balance_settlement_with_party<const MERKLE_HEIGHT: usize>(
    party_id: u8,
    validity_link_hint: &ProofLinkingHint,
    settlement_link_hint: &ProofLinkingHint,
) -> Result<PlonkLinkProof, ProverError> {
    // Get the group layout for the validity <-> settlement link group
    let layout = get_group_layout(party_id)?;
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
/// proof of INTENT AND BALANCE SETTLEMENT (exact, bounded, or private) using
/// the system wide sizing constants for party 0
pub fn validate_sized_intent_and_balance_settlement_link(
    link_proof: &PlonkLinkProof,
    validity_proof: &PlonkProof,
    settlement_proof: &PlonkProof,
) -> Result<(), ProverError> {
    validate_intent_and_balance_settlement_link_with_party::<MERKLE_HEIGHT>(
        0, // party_id
        link_proof,
        validity_proof,
        settlement_proof,
    )
}

/// Validate a link between an intent and balance validity proof with a
/// proof of INTENT AND BALANCE SETTLEMENT (exact, bounded, or private) using
/// the system wide sizing constants for the given party
pub fn validate_sized_intent_and_balance_settlement_link_with_party(
    party_id: u8,
    link_proof: &PlonkLinkProof,
    validity_proof: &PlonkProof,
    settlement_proof: &PlonkProof,
) -> Result<(), ProverError> {
    validate_intent_and_balance_settlement_link_with_party::<MERKLE_HEIGHT>(
        party_id,
        link_proof,
        validity_proof,
        settlement_proof,
    )
}

/// Validate a link between an intent and balance validity proof with a
/// proof of INTENT AND BALANCE SETTLEMENT (exact, bounded, or private)
pub fn validate_intent_and_balance_settlement_link_with_party<const MERKLE_HEIGHT: usize>(
    party_id: u8,
    link_proof: &PlonkLinkProof,
    validity_proof: &PlonkProof,
    settlement_proof: &PlonkProof,
) -> Result<(), ProverError> {
    // Get the group layout for the validity <-> settlement link group
    let layout = get_group_layout(party_id)?;
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

/// Get the group layout for the intent and balance validity <-> settlement
/// link group (exact, bounded, or private)
pub fn get_group_layout(party_id: u8) -> Result<GroupLayout, ProverError> {
    let layout_name = match party_id {
        0 => INTENT_AND_BALANCE_SETTLEMENT_PARTY0_LINK,
        1 => INTENT_AND_BALANCE_SETTLEMENT_PARTY1_LINK,
        _ => panic!("Invalid proof linking party ID: {party_id}"),
    };

    let circuit_layout = IntentAndBalancePrivateSettlementCircuit::get_circuit_layout()
        .map_err(ProverError::Plonk)?;
    Ok(circuit_layout.get_group_layout(layout_name))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        singleprover_prove_with_hint,
        test_helpers::{
            create_bounded_match_result_with_balance, create_random_state_wrapper,
            create_settlement_obligation_with_balance, random_intent, random_schnorr_keypair,
            random_schnorr_public_key,
        },
        zk_circuits::{
            settlement::{
                intent_and_balance_bounded_settlement::{
                    IntentAndBalanceBoundedSettlementCircuit,
                    IntentAndBalanceBoundedSettlementStatement,
                    IntentAndBalanceBoundedSettlementWitness,
                    test_helpers::create_witness_statement_with_intent_balance_and_bounded_match_result as create_bounded_settlement_witness_statement,
                },
                intent_and_balance_private_settlement::{
                    IntentAndBalancePrivateSettlementCircuit,
                    IntentAndBalancePrivateSettlementStatement,
                    IntentAndBalancePrivateSettlementWitness,
                    test_helpers::create_witness_statement as create_exact_private_settlement_witness_statement,
                },
                intent_and_balance_public_settlement::{
                    IntentAndBalancePublicSettlementCircuit,
                    IntentAndBalancePublicSettlementStatement,
                    IntentAndBalancePublicSettlementWitness,
                    test_helpers::create_witness_statement_with_intent_balance_and_obligation as create_exact_public_settlement_witness_statement,
                },
            },
            validity_proofs::{
                intent_and_balance::{
                    IntentAndBalanceValidityStatement, IntentAndBalanceValidityWitness,
                    test_helpers::{
                        create_witness_statement_with_intent as create_validity_witness_statement,
                        create_witness_statement_with_intent_and_balance as create_validity_witness_statement_with_balance,
                    },
                },
                intent_and_balance_first_fill::{
                    IntentAndBalanceFirstFillValidityCircuit,
                    IntentAndBalanceFirstFillValidityStatement,
                    IntentAndBalanceFirstFillValidityWitness,
                    test_helpers::{
                        create_witness_statement as create_witness_statement_first_fill,
                        create_witness_statement_with_intent_and_balance as create_first_fill_witness_statement_with_balance,
                    },
                },
            },
        },
    };
    use constants::Scalar;
    use rand::{seq::SliceRandom, thread_rng};

    /// The Merkle height used for testing
    const TEST_MERKLE_HEIGHT: usize = 3;
    /// Intent and balance validity with testing sizing
    type SizedIntentAndBalanceValidity = IntentAndBalanceValidityCircuit<TEST_MERKLE_HEIGHT>;
    /// Intent and balance first fill validity with testing sizing
    type SizedIntentAndBalanceFirstFillValidity =
        IntentAndBalanceFirstFillValidityCircuit<TEST_MERKLE_HEIGHT>;

    // ---------------------------
    // | Exact Public Settlement |
    // ---------------------------

    // -----------
    // | Helpers |
    // -----------

    /// Prove INTENT AND BALANCE VALIDITY and INTENT AND BALANCE PUBLIC
    /// SETTLEMENT, then link the proofs and verify the link
    fn test_intent_and_balance_validity_exact_public_settlement_link(
        validity_witness: &IntentAndBalanceValidityWitness<TEST_MERKLE_HEIGHT>,
        validity_statement: &IntentAndBalanceValidityStatement,
        settlement_witness: &IntentAndBalancePublicSettlementWitness,
        settlement_statement: &IntentAndBalancePublicSettlementStatement,
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
        let party_id = 0;
        let link_proof = link_intent_and_balance_settlement_with_party::<TEST_MERKLE_HEIGHT>(
            party_id,
            &validity_hint,
            &settlement_hint,
        )?;
        validate_intent_and_balance_settlement_link_with_party::<TEST_MERKLE_HEIGHT>(
            party_id,
            &link_proof,
            &validity_proof,
            &settlement_proof,
        )
    }

    /// Build a validity and exact settlement witness and statement with valid
    /// data
    ///
    /// This involves modifying the witness and statements for each circuit to
    /// align with one another so that they may be linked
    fn build_intent_and_balance_validity_exact_public_settlement_data() -> (
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
            create_exact_public_settlement_witness_statement::<TEST_MERKLE_HEIGHT>(
                &validity_witness.intent,
                &validity_witness.balance,
                settlement_obligation,
            );

        // Align the settlement witness with the validity witness
        settlement_witness.pre_settlement_amount_public_share =
            validity_witness.new_amount_public_share;
        settlement_witness.intent = validity_witness.intent.clone();
        settlement_witness.in_balance = validity_witness.balance.clone();

        let original_in_shares = validity_witness.post_match_balance_shares.clone();
        settlement_witness.pre_settlement_in_balance_shares = original_in_shares.clone();
        settlement_statement.in_balance_public_shares = original_in_shares;

        // Update the statement to reflect the settlement
        settlement_statement.amount_public_share =
            settlement_witness.pre_settlement_amount_public_share;

        (validity_witness, validity_statement, settlement_witness, settlement_statement)
    }

    /// Prove INTENT AND BALANCE FIRST FILL VALIDITY and INTENT AND BALANCE
    /// PUBLIC SETTLEMENT, then link the proofs and verify the link
    fn test_intent_and_balance_first_fill_validity_exact_public_settlement_link(
        validity_witness: &IntentAndBalanceFirstFillValidityWitness<TEST_MERKLE_HEIGHT>,
        validity_statement: &IntentAndBalanceFirstFillValidityStatement,
        settlement_witness: &IntentAndBalancePublicSettlementWitness,
        settlement_statement: &IntentAndBalancePublicSettlementStatement,
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

        let link_proof = link_intent_and_balance_settlement_with_party::<TEST_MERKLE_HEIGHT>(
            0,
            &validity_hint,
            &settlement_hint,
        )?;
        validate_intent_and_balance_settlement_link_with_party::<TEST_MERKLE_HEIGHT>(
            0,
            &link_proof,
            &validity_proof,
            &settlement_proof,
        )
    }

    /// Build a first fill validity and exact settlement witness and statement
    /// with valid data
    ///
    /// This involves modifying the witness and statements for each circuit to
    /// align with one another so that they may be linked
    fn build_intent_and_balance_first_fill_validity_exact_public_settlement_data() -> (
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
            create_exact_public_settlement_witness_statement::<TEST_MERKLE_HEIGHT>(
                &validity_witness.intent,
                &validity_witness.balance,
                settlement_obligation,
            );

        // Align the settlement witness with the validity witness
        settlement_witness.pre_settlement_amount_public_share =
            validity_witness.new_amount_public_share;
        settlement_witness.intent = validity_witness.intent.clone();
        settlement_witness.in_balance = validity_witness.balance.clone();

        let original_in_shares = validity_witness.post_match_balance_shares.clone();
        settlement_witness.pre_settlement_in_balance_shares = original_in_shares.clone();
        settlement_statement.in_balance_public_shares = original_in_shares;

        settlement_statement.amount_public_share =
            settlement_witness.pre_settlement_amount_public_share;

        (validity_witness, validity_statement, settlement_witness, settlement_statement)
    }

    // --------------
    // | Test Cases |
    // --------------

    // --- Valid Test Cases --- //

    /// Tests a valid link between a proof of INTENT AND BALANCE VALIDITY and a
    /// proof of INTENT AND BALANCE PUBLIC SETTLEMENT
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    fn test_intent_and_balance_exact_public_settlement_valid_link() {
        let (validity_witness, validity_statement, settlement_witness, settlement_statement) =
            build_intent_and_balance_validity_exact_public_settlement_data();

        test_intent_and_balance_validity_exact_public_settlement_link(
            &validity_witness,
            &validity_statement,
            &settlement_witness,
            &settlement_statement,
        )
        .unwrap();
    }

    /// Tests a valid link between a proof of INTENT AND BALANCE FIRST FILL
    /// VALIDITY and a proof of INTENT AND BALANCE PUBLIC SETTLEMENT
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    fn test_intent_and_balance_first_fill_exact_public_settlement_valid_link() {
        let (validity_witness, validity_statement, settlement_witness, settlement_statement) =
            build_intent_and_balance_first_fill_validity_exact_public_settlement_data();

        test_intent_and_balance_first_fill_validity_exact_public_settlement_link(
            &validity_witness,
            &validity_statement,
            &settlement_witness,
            &settlement_statement,
        )
        .unwrap();
    }

    // --- Invalid Test Cases --- //

    /// Tests an invalid link between a proof of INTENT AND BALANCE VALIDITY
    /// and a proof of INTENT AND BALANCE PUBLIC SETTLEMENT wherein the amount
    /// public share is modified between the two proofs
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    #[should_panic(expected = "ProofLinkVerification")]
    #[allow(non_snake_case)]
    fn test_intent_and_balance_exact_public_settlement_invalid_link__modified_amount_public_share()
    {
        let (
            validity_witness,
            validity_statement,
            mut settlement_witness,
            mut settlement_statement,
        ) = build_intent_and_balance_validity_exact_public_settlement_data();

        // Modify the amount public share in the settlement witness to break the link
        // We also need to update the statement to keep the settlement circuit valid
        let mut rng = thread_rng();
        let modification = Scalar::random(&mut rng);
        settlement_witness.pre_settlement_amount_public_share += modification;
        // Update the statement to keep the settlement circuit constraints satisfied
        settlement_statement.amount_public_share += modification;

        // Now the settlement circuit is valid, but the link will fail
        test_intent_and_balance_validity_exact_public_settlement_link(
            &validity_witness,
            &validity_statement,
            &settlement_witness,
            &settlement_statement,
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
    fn test_intent_and_balance_exact_public_settlement_invalid_link__modified_balance() {
        use crate::test_helpers::{random_address, random_amount};
        use darkpool_types::balance::Balance;

        let (validity_witness, validity_statement, mut settlement_witness, settlement_statement) =
            build_intent_and_balance_validity_exact_public_settlement_data();

        // Modify the balance in the settlement witness to break the link
        settlement_witness.in_balance = Balance {
            mint: random_address(),
            owner: random_address(),
            relayer_fee_recipient: random_address(),
            authority: random_schnorr_public_key(),
            relayer_fee_balance: random_amount(),
            protocol_fee_balance: random_amount(),
            amount: random_amount(),
        };

        test_intent_and_balance_validity_exact_public_settlement_link(
            &validity_witness,
            &validity_statement,
            &settlement_witness,
            &settlement_statement,
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
    fn test_intent_and_balance_exact_public_settlement_invalid_link__modified_balance_shares() {
        use constants::Scalar;
        use rand::thread_rng;

        let (
            validity_witness,
            validity_statement,
            mut settlement_witness,
            mut settlement_statement,
        ) = build_intent_and_balance_validity_exact_public_settlement_data();

        // Modify the balance shares in the settlement witness to break the link
        // We also need to update the statement to keep the settlement circuit valid
        let mut rng = thread_rng();
        let modification = Scalar::random(&mut rng);
        settlement_witness.pre_settlement_in_balance_shares.amount += modification;
        // Update the statement to keep the settlement circuit constraints satisfied
        settlement_statement.in_balance_public_shares.amount += modification;

        // Now the settlement circuit is valid, but the link will fail because
        // settlement_witness.pre_settlement_in_balance_shares doesn't match
        // validity_witness.post_match_balance_shares
        test_intent_and_balance_validity_exact_public_settlement_link(
            &validity_witness,
            &validity_statement,
            &settlement_witness,
            &settlement_statement,
        )
        .unwrap();
    }

    // ----------------------------
    // | Exact Private Settlement |
    // ----------------------------

    // -----------
    // | Helpers |
    // -----------

    /// Prove INTENT AND BALANCE VALIDITY (for both parties) and INTENT AND
    /// BALANCE PRIVATE SETTLEMENT, then link the proofs and verify the
    /// links
    fn test_intent_and_balance_exact_private_settlement_link(
        party_id: u8,
        validity_witness: &IntentAndBalanceValidityWitness<TEST_MERKLE_HEIGHT>,
        validity_statement: &IntentAndBalanceValidityStatement,
        settlement_witness: &IntentAndBalancePrivateSettlementWitness,
        settlement_statement: &IntentAndBalancePrivateSettlementStatement,
    ) -> Result<(), ProverError> {
        // Create proofs of INTENT AND BALANCE VALIDITY for both parties
        let (validity_proof, validity_hint) = singleprover_prove_with_hint::<
            SizedIntentAndBalanceValidity,
        >(validity_witness, validity_statement)?;

        // Create a proof of INTENT AND BALANCE PRIVATE SETTLEMENT
        let (settlement_proof, settlement_hint) = singleprover_prove_with_hint::<
            IntentAndBalancePrivateSettlementCircuit,
        >(
            settlement_witness, settlement_statement
        )?;

        // Link the proofs and verify the link
        let link_proof = link_intent_and_balance_settlement_with_party::<TEST_MERKLE_HEIGHT>(
            party_id,
            &validity_hint,
            &settlement_hint,
        )?;
        validate_intent_and_balance_settlement_link_with_party::<TEST_MERKLE_HEIGHT>(
            party_id,
            &link_proof,
            &validity_proof,
            &settlement_proof,
        )
    }

    /// Build validity and private settlement witness and statement data with
    /// valid data
    ///
    /// This involves modifying the witness and statements for each circuit to
    /// align with one another so that they may be linked
    fn build_intent_and_balance_exact_private_settlement_data(
        party_id: u8,
    ) -> (
        IntentAndBalanceValidityWitness<TEST_MERKLE_HEIGHT>,
        IntentAndBalanceValidityStatement,
        IntentAndBalancePrivateSettlementWitness,
        IntentAndBalancePrivateSettlementStatement,
    ) {
        // Create the private settlement witness and statement with compatible intents
        let (mut settlement_witness, mut settlement_statement) =
            create_exact_private_settlement_witness_statement();

        // Get mutable references to the relevant fields based on the party ID
        let (intent, balance, new_amount_public_share, pre_settlement_in_balance_shares) =
            if party_id == 0 {
                (
                    &mut settlement_witness.intent0,
                    &mut settlement_witness.input_balance0,
                    &mut settlement_witness.pre_settlement_amount_public_share0,
                    &mut settlement_witness.pre_settlement_in_balance_shares0,
                )
            } else {
                (
                    &mut settlement_witness.intent1,
                    &mut settlement_witness.input_balance1,
                    &mut settlement_witness.pre_settlement_amount_public_share1,
                    &mut settlement_witness.pre_settlement_in_balance_shares1,
                )
            };

        let capitalizing_balance = create_random_state_wrapper(balance.clone());
        let (validity_witness, validity_statement) = create_validity_witness_statement_with_balance::<
            TEST_MERKLE_HEIGHT,
        >(
            intent.clone(), &capitalizing_balance
        );

        // Re-align the settlement witness share updates
        let in_amt0 = Scalar::from(settlement_witness.settlement_obligation0.amount_in);
        let in_amt1 = Scalar::from(settlement_witness.settlement_obligation1.amount_in);

        *new_amount_public_share = validity_witness.new_amount_public_share;
        *pre_settlement_in_balance_shares = validity_witness.post_match_balance_shares.clone();

        settlement_statement.new_amount_public_share0 =
            settlement_witness.pre_settlement_amount_public_share0;
        settlement_statement.new_amount_public_share1 =
            settlement_witness.pre_settlement_amount_public_share1;
        settlement_statement.new_amount_public_share0 -= in_amt0;
        settlement_statement.new_amount_public_share1 -= in_amt1;
        settlement_statement.new_in_balance_public_shares0 =
            settlement_witness.pre_settlement_in_balance_shares0.clone();
        settlement_statement.new_in_balance_public_shares1 =
            settlement_witness.pre_settlement_in_balance_shares1.clone();
        settlement_statement.new_in_balance_public_shares0.amount -= in_amt0;
        settlement_statement.new_in_balance_public_shares1.amount -= in_amt1;

        (validity_witness, validity_statement, settlement_witness, settlement_statement)
    }

    /// Prove INTENT AND BALANCE FIRST FILL VALIDITY and INTENT AND BALANCE
    /// PRIVATE SETTLEMENT, then link the proofs and verify the link
    fn test_intent_and_balance_first_fill_exact_private_settlement_link(
        party_id: u8,
        validity_witness: &IntentAndBalanceFirstFillValidityWitness<TEST_MERKLE_HEIGHT>,
        validity_statement: &IntentAndBalanceFirstFillValidityStatement,
        settlement_witness: &IntentAndBalancePrivateSettlementWitness,
        settlement_statement: &IntentAndBalancePrivateSettlementStatement,
    ) -> Result<(), ProverError> {
        // Create a proof of INTENT AND BALANCE FIRST FILL VALIDITY
        let (validity_proof, validity_hint) = singleprover_prove_with_hint::<
            SizedIntentAndBalanceFirstFillValidity,
        >(validity_witness, validity_statement)?;

        // Create a proof of INTENT AND BALANCE PRIVATE SETTLEMENT
        let (settlement_proof, settlement_hint) = singleprover_prove_with_hint::<
            IntentAndBalancePrivateSettlementCircuit,
        >(
            settlement_witness, settlement_statement
        )?;

        // Link the proofs and verify the link
        let link_proof = link_intent_and_balance_settlement_with_party::<TEST_MERKLE_HEIGHT>(
            party_id,
            &validity_hint,
            &settlement_hint,
        )?;
        validate_intent_and_balance_settlement_link_with_party::<TEST_MERKLE_HEIGHT>(
            party_id,
            &link_proof,
            &validity_proof,
            &settlement_proof,
        )
    }

    /// Build first fill validity and private settlement witness and statement
    /// data with valid data
    ///
    /// This involves modifying the witness and statements for each circuit to
    /// align with one another so that they may be linked
    fn build_intent_and_balance_first_fill_exact_private_settlement_data(
        party_id: u8,
    ) -> (
        IntentAndBalanceFirstFillValidityWitness<TEST_MERKLE_HEIGHT>,
        IntentAndBalanceFirstFillValidityStatement,
        IntentAndBalancePrivateSettlementWitness,
        IntentAndBalancePrivateSettlementStatement,
    ) {
        // Create the private settlement witness and statement with compatible intents
        let (mut settlement_witness, mut settlement_statement) =
            create_exact_private_settlement_witness_statement();

        // Sample a keypair to authorize the intent creation, then override the
        // authority keys for all balances
        let (key, public_key) = random_schnorr_keypair();
        settlement_witness.input_balance0.authority = public_key;
        settlement_witness.input_balance1.authority = public_key;
        settlement_witness.output_balance0.authority = public_key;
        settlement_witness.output_balance1.authority = public_key;

        // Get mutable references to the relevant fields based on the party ID
        let (intent, balance, new_amount_public_share, pre_settlement_in_balance_shares) =
            if party_id == 0 {
                (
                    &mut settlement_witness.intent0,
                    &mut settlement_witness.input_balance0,
                    &mut settlement_witness.pre_settlement_amount_public_share0,
                    &mut settlement_witness.pre_settlement_in_balance_shares0,
                )
            } else {
                (
                    &mut settlement_witness.intent1,
                    &mut settlement_witness.input_balance1,
                    &mut settlement_witness.pre_settlement_amount_public_share1,
                    &mut settlement_witness.pre_settlement_in_balance_shares1,
                )
            };

        let capitalizing_balance = create_random_state_wrapper(balance.clone());
        let (validity_witness, validity_statement) =
            create_first_fill_witness_statement_with_balance::<TEST_MERKLE_HEIGHT>(
                intent,
                capitalizing_balance,
                key,
            );

        // Re-align the settlement witness share updates
        let in_amt0 = Scalar::from(settlement_witness.settlement_obligation0.amount_in);
        let in_amt1 = Scalar::from(settlement_witness.settlement_obligation1.amount_in);

        *new_amount_public_share = validity_witness.new_amount_public_share;
        *pre_settlement_in_balance_shares = validity_witness.post_match_balance_shares.clone();

        settlement_statement.new_amount_public_share0 =
            settlement_witness.pre_settlement_amount_public_share0;
        settlement_statement.new_amount_public_share1 =
            settlement_witness.pre_settlement_amount_public_share1;
        settlement_statement.new_amount_public_share0 -= in_amt0;
        settlement_statement.new_amount_public_share1 -= in_amt1;
        settlement_statement.new_in_balance_public_shares0 =
            settlement_witness.pre_settlement_in_balance_shares0.clone();
        settlement_statement.new_in_balance_public_shares1 =
            settlement_witness.pre_settlement_in_balance_shares1.clone();
        settlement_statement.new_in_balance_public_shares0.amount -= in_amt0;
        settlement_statement.new_in_balance_public_shares1.amount -= in_amt1;

        (validity_witness, validity_statement, settlement_witness, settlement_statement)
    }

    // --------------
    // | Test Cases |
    // --------------

    // --- Valid Test Cases --- //

    /// Tests a valid link between a proof of INTENT AND BALANCE VALIDITY and a
    /// proof of INTENT AND BALANCE PUBLIC SETTLEMENT
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    fn test_intent_and_balance_valid_link() {
        let (validity_witness, validity_statement, settlement_witness, settlement_statement) =
            build_intent_and_balance_validity_exact_public_settlement_data();

        test_intent_and_balance_validity_exact_public_settlement_link(
            &validity_witness,
            &validity_statement,
            &settlement_witness,
            &settlement_statement,
        )
        .unwrap();
    }

    /// Tests a valid link between a proof of INTENT AND BALANCE FIRST FILL
    /// VALIDITY and a proof of INTENT AND BALANCE PUBLIC SETTLEMENT
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    fn test_intent_and_balance_first_fill_valid_link() {
        let (validity_witness, validity_statement, settlement_witness, settlement_statement) =
            build_intent_and_balance_first_fill_validity_exact_public_settlement_data();

        test_intent_and_balance_first_fill_validity_exact_public_settlement_link(
            &validity_witness,
            &validity_statement,
            &settlement_witness,
            &settlement_statement,
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
            build_intent_and_balance_validity_exact_public_settlement_data();

        // Modify the intent in the settlement witness to break the link
        settlement_witness.intent.amount_in += 1;
        test_intent_and_balance_validity_exact_public_settlement_link(
            &validity_witness,
            &validity_statement,
            &settlement_witness,
            &settlement_statement,
        )
        .unwrap();
    }

    /// Tests a valid link between a proof of INTENT AND BALANCE VALIDITY (for
    /// both parties) and a proof of INTENT AND BALANCE PRIVATE SETTLEMENT
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    fn test_intent_and_balance_exact_private_settlement_valid_link() {
        let mut rng = thread_rng();
        let party_id = *[0u8, 1].choose(&mut rng).unwrap();
        let (validity_witness, validity_statement, settlement_witness, settlement_statement) =
            build_intent_and_balance_exact_private_settlement_data(party_id);

        test_intent_and_balance_exact_private_settlement_link(
            party_id,
            &validity_witness,
            &validity_statement,
            &settlement_witness,
            &settlement_statement,
        )
        .unwrap()
    }

    /// Tests a valid link between a proof of INTENT AND BALANCE FIRST FILL
    /// VALIDITY and a proof of INTENT AND BALANCE PRIVATE SETTLEMENT
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    fn test_intent_and_balance_first_fill_exact_private_settlement_valid_link() {
        let mut rng = thread_rng();
        let party_id = *[0u8, 1].choose(&mut rng).unwrap();
        let (validity_witness, validity_statement, settlement_witness, settlement_statement) =
            build_intent_and_balance_first_fill_exact_private_settlement_data(party_id);

        test_intent_and_balance_first_fill_exact_private_settlement_link(
            party_id,
            &validity_witness,
            &validity_statement,
            &settlement_witness,
            &settlement_statement,
        )
        .unwrap()
    }

    // ----------------------
    // | Bounded Settlement |
    // ----------------------

    // -----------
    // | Helpers |
    // -----------

    /// Prove INTENT AND BALANCE VALIDITY and INTENT AND BALANCE BOUNDED
    /// SETTLEMENT, then link the proofs and verify the link
    fn test_intent_and_balance_validity_bounded_settlement_link(
        validity_witness: &IntentAndBalanceValidityWitness<TEST_MERKLE_HEIGHT>,
        validity_statement: &IntentAndBalanceValidityStatement,
        settlement_witness: &IntentAndBalanceBoundedSettlementWitness,
        settlement_statement: &IntentAndBalanceBoundedSettlementStatement,
    ) -> Result<(), ProverError> {
        // Create a proof of INTENT AND BALANCE VALIDITY and one of INTENT AND BALANCE
        // BOUNDED SETTLEMENT
        let (validity_proof, validity_hint) = singleprover_prove_with_hint::<
            SizedIntentAndBalanceValidity,
        >(validity_witness, validity_statement)?;
        let (settlement_proof, settlement_hint) = singleprover_prove_with_hint::<
            IntentAndBalanceBoundedSettlementCircuit,
        >(
            settlement_witness, settlement_statement
        )?;

        // Link the proofs and verify the link
        let party_id = 0;
        let link_proof = link_intent_and_balance_settlement_with_party::<TEST_MERKLE_HEIGHT>(
            party_id,
            &validity_hint,
            &settlement_hint,
        )?;
        validate_intent_and_balance_settlement_link_with_party::<TEST_MERKLE_HEIGHT>(
            party_id,
            &link_proof,
            &validity_proof,
            &settlement_proof,
        )
    }

    /// Build a validity and bounded settlement witness and statement with valid
    /// data
    ///
    /// This involves modifying the witness and statements for each circuit to
    /// align with one another so that they may be linked
    fn build_intent_and_balance_validity_bounded_settlement_data() -> (
        IntentAndBalanceValidityWitness<TEST_MERKLE_HEIGHT>,
        IntentAndBalanceValidityStatement,
        IntentAndBalanceBoundedSettlementWitness,
        IntentAndBalanceBoundedSettlementStatement,
    ) {
        // Create the validity witness and statement
        let intent = random_intent();
        let (validity_witness, validity_statement) =
            create_validity_witness_statement::<TEST_MERKLE_HEIGHT>(intent.clone());

        // Create a bounded match result that matches the validity witness
        let bounded_match_result = create_bounded_match_result_with_balance(
            &validity_witness.intent,
            validity_witness.balance.amount,
        );

        // Create the bounded settlement witness and statement using the validity
        // witness data
        let (mut settlement_witness, mut settlement_statement) =
            create_bounded_settlement_witness_statement(
                &validity_witness.intent,
                &validity_witness.balance,
                bounded_match_result,
            );

        // Align the settlement witness with the validity witness
        settlement_witness.pre_settlement_amount_public_share =
            validity_witness.new_amount_public_share;
        settlement_witness.intent = validity_witness.intent.clone();
        settlement_witness.in_balance = validity_witness.balance.clone();

        let original_in_shares = validity_witness.post_match_balance_shares.clone();
        settlement_witness.pre_settlement_in_balance_shares = original_in_shares.clone();
        settlement_statement.in_balance_public_shares = original_in_shares;

        // Update the statement to reflect the settlement
        settlement_statement.amount_public_share =
            settlement_witness.pre_settlement_amount_public_share;

        (validity_witness, validity_statement, settlement_witness, settlement_statement)
    }

    /// Prove INTENT AND BALANCE FIRST FILL VALIDITY and INTENT AND BALANCE
    /// BOUNDED SETTLEMENT, then link the proofs and verify the link
    fn test_intent_and_balance_first_fill_validity_bounded_settlement_link(
        validity_witness: &IntentAndBalanceFirstFillValidityWitness<TEST_MERKLE_HEIGHT>,
        validity_statement: &IntentAndBalanceFirstFillValidityStatement,
        settlement_witness: &IntentAndBalanceBoundedSettlementWitness,
        settlement_statement: &IntentAndBalanceBoundedSettlementStatement,
    ) -> Result<(), ProverError> {
        // Create a proof of INTENT AND BALANCE FIRST FILL VALIDITY and one of INTENT
        // AND BALANCE BOUNDED SETTLEMENT
        let (validity_proof, validity_hint) = singleprover_prove_with_hint::<
            SizedIntentAndBalanceFirstFillValidity,
        >(validity_witness, validity_statement)?;
        let (settlement_proof, settlement_hint) = singleprover_prove_with_hint::<
            IntentAndBalanceBoundedSettlementCircuit,
        >(
            settlement_witness, settlement_statement
        )?;

        let link_proof = link_intent_and_balance_settlement_with_party::<TEST_MERKLE_HEIGHT>(
            0,
            &validity_hint,
            &settlement_hint,
        )?;
        validate_intent_and_balance_settlement_link_with_party::<TEST_MERKLE_HEIGHT>(
            0,
            &link_proof,
            &validity_proof,
            &settlement_proof,
        )
    }

    /// Build a first fill validity and bounded settlement witness and statement
    /// with valid data
    ///
    /// This involves modifying the witness and statements for each circuit to
    /// align with one another so that they may be linked
    fn build_intent_and_balance_first_fill_validity_bounded_settlement_data() -> (
        IntentAndBalanceFirstFillValidityWitness<TEST_MERKLE_HEIGHT>,
        IntentAndBalanceFirstFillValidityStatement,
        IntentAndBalanceBoundedSettlementWitness,
        IntentAndBalanceBoundedSettlementStatement,
    ) {
        let (validity_witness, validity_statement) = create_witness_statement_first_fill();

        // Create a bounded match result that matches the validity witness
        let bounded_match_result = crate::test_helpers::create_bounded_match_result_with_balance(
            &validity_witness.intent,
            validity_witness.balance.amount,
        );

        // Create the bounded settlement witness and statement using the validity
        // witness data
        let (mut settlement_witness, mut settlement_statement) =
            create_bounded_settlement_witness_statement(
                &validity_witness.intent,
                &validity_witness.balance,
                bounded_match_result,
            );

        // Align the settlement witness with the validity witness
        settlement_witness.pre_settlement_amount_public_share =
            validity_witness.new_amount_public_share;
        settlement_witness.intent = validity_witness.intent.clone();
        settlement_witness.in_balance = validity_witness.balance.clone();

        let original_in_shares = validity_witness.post_match_balance_shares.clone();
        settlement_witness.pre_settlement_in_balance_shares = original_in_shares.clone();
        settlement_statement.in_balance_public_shares = original_in_shares;

        settlement_statement.amount_public_share =
            settlement_witness.pre_settlement_amount_public_share;

        (validity_witness, validity_statement, settlement_witness, settlement_statement)
    }

    // --------------
    // | Test Cases |
    // --------------

    // --- Valid Test Cases --- //

    /// Tests a valid link between a proof of INTENT AND BALANCE VALIDITY and a
    /// proof of INTENT AND BALANCE BOUNDED SETTLEMENT
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    fn test_intent_and_balance_bounded_settlement_valid_link() {
        let (validity_witness, validity_statement, settlement_witness, settlement_statement) =
            build_intent_and_balance_validity_bounded_settlement_data();

        test_intent_and_balance_validity_bounded_settlement_link(
            &validity_witness,
            &validity_statement,
            &settlement_witness,
            &settlement_statement,
        )
        .unwrap();
    }

    /// Tests a valid link between a proof of INTENT AND BALANCE FIRST FILL
    /// VALIDITY and a proof of INTENT AND BALANCE BOUNDED SETTLEMENT
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    fn test_intent_and_balance_first_fill_bounded_settlement_valid_link() {
        let (validity_witness, validity_statement, settlement_witness, settlement_statement) =
            build_intent_and_balance_first_fill_validity_bounded_settlement_data();

        test_intent_and_balance_first_fill_validity_bounded_settlement_link(
            &validity_witness,
            &validity_statement,
            &settlement_witness,
            &settlement_statement,
        )
        .unwrap();
    }

    // --- Invalid Test Cases --- //

    /// Tests an invalid link between a proof of INTENT AND BALANCE VALIDITY
    /// and a proof of INTENT AND BALANCE BOUNDED SETTLEMENT wherein the intent
    /// is modified between the two proofs
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    #[should_panic(expected = "ProofLinkVerification")]
    #[allow(non_snake_case)]
    fn test_intent_and_balance_bounded_settlement_invalid_link__modified_intent_amount_in() {
        let (validity_witness, validity_statement, mut settlement_witness, settlement_statement) =
            build_intent_and_balance_validity_bounded_settlement_data();

        // Modify the intent in the settlement witness to break the link
        settlement_witness.intent.amount_in += 1;
        test_intent_and_balance_validity_bounded_settlement_link(
            &validity_witness,
            &validity_statement,
            &settlement_witness,
            &settlement_statement,
        )
        .unwrap();
    }

    /// Tests an invalid link between a proof of INTENT AND BALANCE VALIDITY
    /// and a proof of INTENT AND BALANCE BOUNDED SETTLEMENT wherein the amount
    /// public share is modified between the two proofs
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    #[should_panic(expected = "ProofLinkVerification")]
    #[allow(non_snake_case)]
    fn test_intent_and_balance_bounded_settlement_invalid_link__modified_amount_public_share() {
        use constants::Scalar;
        use rand::thread_rng;

        let (
            validity_witness,
            validity_statement,
            mut settlement_witness,
            mut settlement_statement,
        ) = build_intent_and_balance_validity_bounded_settlement_data();

        // Modify the amount public share in the settlement witness to break the link
        // We also need to update the statement to keep the settlement circuit valid
        let mut rng = thread_rng();
        let modification = Scalar::random(&mut rng);
        settlement_witness.pre_settlement_amount_public_share += modification;
        // Update the statement to keep the settlement circuit constraints satisfied
        settlement_statement.amount_public_share += modification;

        // Now the settlement circuit is valid, but the link will fail
        test_intent_and_balance_validity_bounded_settlement_link(
            &validity_witness,
            &validity_statement,
            &settlement_witness,
            &settlement_statement,
        )
        .unwrap();
    }

    /// Tests an invalid link between a proof of INTENT AND BALANCE VALIDITY
    /// and a proof of INTENT AND BALANCE BOUNDED SETTLEMENT wherein the balance
    /// is modified between the two proofs
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    #[should_panic(expected = "ProofLinkVerification")]
    #[allow(non_snake_case)]
    fn test_intent_and_balance_bounded_settlement_invalid_link__modified_balance() {
        use crate::test_helpers::{random_address, random_amount};
        use darkpool_types::balance::Balance;

        let (validity_witness, validity_statement, mut settlement_witness, settlement_statement) =
            build_intent_and_balance_validity_bounded_settlement_data();

        // Modify the balance in the settlement witness to break the link
        settlement_witness.in_balance = Balance {
            mint: random_address(),
            owner: random_address(),
            relayer_fee_recipient: random_address(),
            authority: random_schnorr_public_key(),
            relayer_fee_balance: random_amount(),
            protocol_fee_balance: random_amount(),
            amount: random_amount(),
        };

        test_intent_and_balance_validity_bounded_settlement_link(
            &validity_witness,
            &validity_statement,
            &settlement_witness,
            &settlement_statement,
        )
        .unwrap();
    }

    /// Tests an invalid link between a proof of INTENT AND BALANCE VALIDITY
    /// and a proof of INTENT AND BALANCE BOUNDED SETTLEMENT wherein the balance
    /// shares are modified between the two proofs
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    #[should_panic(expected = "ProofLinkVerification")]
    #[allow(non_snake_case)]
    fn test_intent_and_balance_bounded_settlement_invalid_link__modified_balance_shares() {
        use constants::Scalar;
        use rand::thread_rng;

        let (
            validity_witness,
            validity_statement,
            mut settlement_witness,
            mut settlement_statement,
        ) = build_intent_and_balance_validity_bounded_settlement_data();

        // Modify the balance shares in the settlement witness to break the link
        // We also need to update the statement to keep the settlement circuit valid
        let mut rng = thread_rng();
        let modification = Scalar::random(&mut rng);
        settlement_witness.pre_settlement_in_balance_shares.amount += modification;
        // Update the statement to keep the settlement circuit constraints satisfied
        settlement_statement.in_balance_public_shares.amount += modification;

        // Now the settlement circuit is valid, but the link will fail because
        // settlement_witness.pre_settlement_in_balance_shares doesn't match
        // validity_witness.post_match_balance_shares
        test_intent_and_balance_validity_bounded_settlement_link(
            &validity_witness,
            &validity_statement,
            &settlement_witness,
            &settlement_statement,
        )
        .unwrap();
    }
}
