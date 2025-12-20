//! Helpers for linking proofs between output balance validity and
//! settlement circuits

use circuit_types::{
    PlonkLinkProof, PlonkProof, ProofLinkingHint, errors::ProverError, traits::SingleProverCircuit,
};
use constants::MERKLE_HEIGHT;
use mpc_plonk::{proof_system::PlonkKzgSnark, transcript::SolidityTranscript};
use mpc_relation::proof_linking::GroupLayout;

use crate::zk_circuits::{
    settlement::{
        OUTPUT_BALANCE_SETTLEMENT_PARTY0_LINK, OUTPUT_BALANCE_SETTLEMENT_PARTY1_LINK,
        intent_and_balance_private_settlement::IntentAndBalancePrivateSettlementCircuit,
    },
    validity_proofs::output_balance::OutputBalanceValidityCircuit,
};

// --------------------------------------------------------------------
// | Output Balance Validity <-> Intent And Balance Public Settlement |
// --------------------------------------------------------------------

/// Link an output balance validity proof with an INTENT AND BALANCE settlement
/// proof using the system wide sizing constants for party 0
pub fn link_sized_output_balance_settlement(
    validity_link_hint: &ProofLinkingHint,
    settlement_link_hint: &ProofLinkingHint,
) -> Result<PlonkLinkProof, ProverError> {
    link_output_balance_settlement_with_party::<MERKLE_HEIGHT>(
        0, // party_id
        validity_link_hint,
        settlement_link_hint,
    )
}

/// Link an output balance validity proof with an INTENT AND BALANCE settlement
/// proof using the system wide sizing constants for the given party
pub fn link_sized_output_balance_settlement_with_party(
    party_id: u8,
    validity_link_hint: &ProofLinkingHint,
    settlement_link_hint: &ProofLinkingHint,
) -> Result<PlonkLinkProof, ProverError> {
    link_output_balance_settlement_with_party::<MERKLE_HEIGHT>(
        party_id,
        validity_link_hint,
        settlement_link_hint,
    )
}

/// Link an output balance validity proof with an INTENT AND BALANCE settlement
/// proof
pub fn link_output_balance_settlement_with_party<const MERKLE_HEIGHT: usize>(
    party_id: u8,
    validity_link_hint: &ProofLinkingHint,
    settlement_link_hint: &ProofLinkingHint,
) -> Result<PlonkLinkProof, ProverError> {
    // Get the group layout for the validity <-> settlement link group
    let layout = get_group_layout(party_id)?;
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
/// an INTENT AND BALANCE settlement proof using the system wide sizing
/// constants for party 0
pub fn validate_output_balance_settlement_link<const MERKLE_HEIGHT: usize>(
    link_proof: &PlonkLinkProof,
    validity_proof: &PlonkProof,
    settlement_proof: &PlonkProof,
) -> Result<(), ProverError> {
    validate_output_balance_settlement_link_with_party::<MERKLE_HEIGHT>(
        0, // party_id
        link_proof,
        validity_proof,
        settlement_proof,
    )
}

/// Validate a link between an output balance validity proof with a
/// an INTENT AND BALANCE settlement proof using the system wide sizing
/// constants
pub fn validate_sized_output_balance_settlement_link_with_party(
    party_id: u8,
    link_proof: &PlonkLinkProof,
    validity_proof: &PlonkProof,
    settlement_proof: &PlonkProof,
) -> Result<(), ProverError> {
    validate_output_balance_settlement_link_with_party::<MERKLE_HEIGHT>(
        party_id,
        link_proof,
        validity_proof,
        settlement_proof,
    )
}

/// Validate a link between an output balance validity proof with a
/// an INTENT AND BALANCE settlement proof
pub fn validate_output_balance_settlement_link_with_party<const MERKLE_HEIGHT: usize>(
    party_id: u8,
    link_proof: &PlonkLinkProof,
    validity_proof: &PlonkProof,
    settlement_proof: &PlonkProof,
) -> Result<(), ProverError> {
    // Get the group layout for the validity <-> settlement link group
    let layout = get_group_layout(party_id)?;
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

/// Get the group layout for the output balance validity <-> settlement
/// link group
pub fn get_group_layout(party_id: u8) -> Result<GroupLayout, ProverError> {
    let layout_name = match party_id {
        0 => OUTPUT_BALANCE_SETTLEMENT_PARTY0_LINK,
        1 => OUTPUT_BALANCE_SETTLEMENT_PARTY1_LINK,
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
            create_matching_balance_for_intent, create_settlement_obligation_with_balance,
            random_intent, random_small_balance, random_small_intent, random_zeroed_balance,
        },
        zk_circuits::{
            settlement::{
                intent_and_balance_private_settlement::{
                    IntentAndBalancePrivateSettlementCircuit,
                    IntentAndBalancePrivateSettlementStatement,
                    IntentAndBalancePrivateSettlementWitness,
                    test_helpers::create_witness_statement as create_private_settlement_witness_statement,
                },
                intent_and_balance_public_settlement::{
                    IntentAndBalancePublicSettlementCircuit,
                    IntentAndBalancePublicSettlementStatement,
                    IntentAndBalancePublicSettlementWitness,
                    test_helpers::create_witness_statement_with_intent_balance_and_obligation as create_settlement_witness_statement,
                },
            },
            validity_proofs::{
                new_output_balance::{
                    NewOutputBalanceValidityCircuit, NewOutputBalanceValidityStatement,
                    NewOutputBalanceValidityWitness,
                    test_helpers::{
                        create_witness_statement as create_new_output_balance_witness_statement,
                        create_witness_statement_with_balance as create_new_output_balance_witness_statement_with_balance,
                    },
                },
                output_balance::{
                    OutputBalanceValidityStatement, OutputBalanceValidityWitness,
                    test_helpers::create_witness_statement_with_balance as create_validity_witness_statement,
                },
            },
        },
    };
    use circuit_types::fee::FeeRates;
    use constants::Scalar;
    use rand::{seq::SliceRandom, thread_rng};

    /// The Merkle height used for testing
    const TEST_MERKLE_HEIGHT: usize = 3;
    /// Output balance validity with testing sizing
    type SizedOutputBalanceValidity = OutputBalanceValidityCircuit<TEST_MERKLE_HEIGHT>;

    // -----------
    // | Helpers |
    // -----------

    // --- Output Balance Public Settlement Link --- //

    /// Prove OUTPUT BALANCE VALIDITY and INTENT AND BALANCE PUBLIC
    /// SETTLEMENT, then link the proofs and verify the link
    fn test_output_balance_validity_settlement_link(
        validity_witness: &OutputBalanceValidityWitness<TEST_MERKLE_HEIGHT>,
        validity_statement: &OutputBalanceValidityStatement,
        settlement_witness: &IntentAndBalancePublicSettlementWitness,
        settlement_statement: &IntentAndBalancePublicSettlementStatement,
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
        let party_id = 0;
        let link_proof = link_output_balance_settlement_with_party::<TEST_MERKLE_HEIGHT>(
            party_id,
            &validity_hint,
            &settlement_hint,
        )?;
        validate_output_balance_settlement_link_with_party::<TEST_MERKLE_HEIGHT>(
            party_id,
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
        // Create the validity witness and statement
        let balance = random_small_balance();
        let (validity_witness, validity_statement) =
            create_validity_witness_statement::<TEST_MERKLE_HEIGHT>(balance.clone());

        // Create an intent and input balance for the settlement
        let output_balance = validity_witness.balance.clone();
        let mut intent = random_small_intent();
        intent.out_token = output_balance.mint;
        intent.owner = output_balance.owner;
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
        let out_shares = validity_witness.post_match_balance_shares.clone();
        settlement_witness.pre_settlement_out_balance_shares = out_shares.clone();
        settlement_statement.out_balance_public_shares = out_shares;

        (validity_witness, validity_statement, settlement_witness, settlement_statement)
    }

    // --- New Output Balance Public Settlement Link --- //

    /// Prove NEW OUTPUT BALANCE VALIDITY and INTENT AND BALANCE PUBLIC
    /// SETTLEMENT, then link the proofs and verify the link
    fn test_new_output_balance_validity_settlement_link(
        validity_witness: &NewOutputBalanceValidityWitness<TEST_MERKLE_HEIGHT>,
        validity_statement: &NewOutputBalanceValidityStatement,
        settlement_witness: &IntentAndBalancePublicSettlementWitness,
        settlement_statement: &IntentAndBalancePublicSettlementStatement,
    ) -> Result<(), ProverError> {
        // Create a proof of NEW OUTPUT BALANCE VALIDITY and one of INTENT AND BALANCE
        // PUBLIC SETTLEMENT
        let (validity_proof, validity_hint) = singleprover_prove_with_hint::<
            NewOutputBalanceValidityCircuit<TEST_MERKLE_HEIGHT>,
        >(validity_witness, validity_statement)?;
        let (settlement_proof, settlement_hint) = singleprover_prove_with_hint::<
            IntentAndBalancePublicSettlementCircuit,
        >(
            settlement_witness, settlement_statement
        )?;

        // Link the proofs and verify the link using the existing sized methods
        let party_id = 0;
        let link_proof = link_output_balance_settlement_with_party::<TEST_MERKLE_HEIGHT>(
            party_id,
            &validity_hint,
            &settlement_hint,
        )?;
        validate_output_balance_settlement_link_with_party::<TEST_MERKLE_HEIGHT>(
            party_id,
            &link_proof,
            &validity_proof,
            &settlement_proof,
        )
    }

    /// Build a new output balance validity and settlement witness and statement
    /// with valid data
    ///
    /// This involves modifying the witness and statements for each circuit to
    /// align with one another so that they may be linked
    fn build_new_output_balance_validity_settlement_data() -> (
        NewOutputBalanceValidityWitness<TEST_MERKLE_HEIGHT>,
        NewOutputBalanceValidityStatement,
        IntentAndBalancePublicSettlementWitness,
        IntentAndBalancePublicSettlementStatement,
    ) {
        // Create the validity witness and statement
        let (validity_witness, validity_statement) =
            create_new_output_balance_witness_statement::<TEST_MERKLE_HEIGHT>();

        // Create an intent and input balance for the settlement
        let output_balance = validity_witness.balance.clone();
        let mut intent = random_intent();
        intent.out_token = output_balance.mint;
        intent.owner = output_balance.owner;
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
        let out_shares = validity_witness.post_match_balance_shares.clone();
        settlement_witness.pre_settlement_out_balance_shares = out_shares.clone();
        settlement_statement.out_balance_public_shares = out_shares;

        (validity_witness, validity_statement, settlement_witness, settlement_statement)
    }

    // --- Output Balance Private Settlement Link --- //

    /// Prove OUTPUT BALANCE VALIDITY and INTENT AND BALANCE PRIVATE
    /// SETTLEMENT, then link the proofs and verify the link
    fn test_output_balance_private_settlement_link(
        party_id: u8,
        validity_witness: &OutputBalanceValidityWitness<TEST_MERKLE_HEIGHT>,
        validity_statement: &OutputBalanceValidityStatement,
        settlement_witness: &IntentAndBalancePrivateSettlementWitness,
        settlement_statement: &IntentAndBalancePrivateSettlementStatement,
    ) -> Result<(), ProverError> {
        // Create a proof of OUTPUT BALANCE VALIDITY
        let (validity_proof, validity_hint) = singleprover_prove_with_hint::<
            SizedOutputBalanceValidity,
        >(validity_witness, validity_statement)?;

        // Create a proof of INTENT AND BALANCE PRIVATE SETTLEMENT
        let (settlement_proof, settlement_hint) = singleprover_prove_with_hint::<
            IntentAndBalancePrivateSettlementCircuit,
        >(
            settlement_witness, settlement_statement
        )?;

        // Link the proofs and verify the link
        let link_proof = link_output_balance_settlement_with_party::<TEST_MERKLE_HEIGHT>(
            party_id,
            &validity_hint,
            &settlement_hint,
        )?;
        validate_output_balance_settlement_link_with_party::<TEST_MERKLE_HEIGHT>(
            party_id,
            &link_proof,
            &validity_proof,
            &settlement_proof,
        )
    }

    /// Build output balance validity and private settlement witness and
    /// statement data with valid data
    ///
    /// This involves modifying the witness and statements for each circuit to
    /// align with one another so that they may be linked
    fn build_output_balance_private_settlement_data(
        party_id: u8,
    ) -> (
        OutputBalanceValidityWitness<TEST_MERKLE_HEIGHT>,
        OutputBalanceValidityStatement,
        IntentAndBalancePrivateSettlementWitness,
        IntentAndBalancePrivateSettlementStatement,
    ) {
        // Create the private settlement witness and statement with compatible intents
        let (mut settlement_witness, mut settlement_statement) =
            create_private_settlement_witness_statement();

        // Get mutable references to the relevant fields based on the party ID
        let (output_balance, pre_settlement_out_balance_shares) = if party_id == 0 {
            (
                &mut settlement_witness.output_balance0,
                &mut settlement_witness.pre_settlement_out_balance_shares0,
            )
        } else {
            (
                &mut settlement_witness.output_balance1,
                &mut settlement_witness.pre_settlement_out_balance_shares1,
            )
        };

        // Create the validity witness and statement using the output balance from
        // settlement
        let (validity_witness, validity_statement) =
            create_validity_witness_statement::<TEST_MERKLE_HEIGHT>(output_balance.clone());

        // Align the settlement witness with the validity witness
        *output_balance = validity_witness.balance.clone();
        *pre_settlement_out_balance_shares = validity_witness.post_match_balance_shares.clone();

        // Update the settlement statement to reflect the settlement
        let amt_out0 = settlement_witness.settlement_obligation0.amount_out;
        let amt_out1 = settlement_witness.settlement_obligation1.amount_out;

        settlement_statement.new_out_balance_public_shares0 =
            settlement_witness.pre_settlement_out_balance_shares0.clone();
        settlement_statement.new_out_balance_public_shares1 =
            settlement_witness.pre_settlement_out_balance_shares1.clone();
        let fee_rate0 =
            FeeRates::new(settlement_statement.relayer_fee0, settlement_statement.protocol_fee);
        let fee_rate1 =
            FeeRates::new(settlement_statement.relayer_fee1, settlement_statement.protocol_fee);
        let fee_take0 = fee_rate0.compute_fee_take(amt_out0);
        let fee_take1 = fee_rate1.compute_fee_take(amt_out1);
        let net_receive0 = amt_out0 - fee_take0.total();
        let net_receive1 = amt_out1 - fee_take1.total();

        settlement_statement.new_out_balance_public_shares0.amount += Scalar::from(net_receive0);
        settlement_statement.new_out_balance_public_shares0.relayer_fee_balance +=
            Scalar::from(fee_take0.relayer_fee);
        settlement_statement.new_out_balance_public_shares0.protocol_fee_balance +=
            Scalar::from(fee_take0.protocol_fee);
        settlement_statement.new_out_balance_public_shares1.amount += Scalar::from(net_receive1);
        settlement_statement.new_out_balance_public_shares1.relayer_fee_balance +=
            Scalar::from(fee_take1.relayer_fee);
        settlement_statement.new_out_balance_public_shares1.protocol_fee_balance +=
            Scalar::from(fee_take1.protocol_fee);

        (validity_witness, validity_statement, settlement_witness, settlement_statement)
    }

    // --- New Output Balance Private Settlement Link --- //

    /// Prove NEW OUTPUT BALANCE VALIDITY and INTENT AND BALANCE PRIVATE
    /// SETTLEMENT, then link the proofs and verify the link
    fn test_new_output_balance_private_settlement_link(
        party_id: u8,
        validity_witness: &NewOutputBalanceValidityWitness<TEST_MERKLE_HEIGHT>,
        validity_statement: &NewOutputBalanceValidityStatement,
        settlement_witness: &IntentAndBalancePrivateSettlementWitness,
        settlement_statement: &IntentAndBalancePrivateSettlementStatement,
    ) -> Result<(), ProverError> {
        // Create a proof of NEW OUTPUT BALANCE VALIDITY
        let (validity_proof, validity_hint) = singleprover_prove_with_hint::<
            NewOutputBalanceValidityCircuit<TEST_MERKLE_HEIGHT>,
        >(validity_witness, validity_statement)?;

        // Create a proof of INTENT AND BALANCE PRIVATE SETTLEMENT
        let (settlement_proof, settlement_hint) = singleprover_prove_with_hint::<
            IntentAndBalancePrivateSettlementCircuit,
        >(
            settlement_witness, settlement_statement
        )?;

        // Link the proofs and verify the link
        let link_proof = link_output_balance_settlement_with_party::<TEST_MERKLE_HEIGHT>(
            party_id,
            &validity_hint,
            &settlement_hint,
        )?;
        validate_output_balance_settlement_link_with_party::<TEST_MERKLE_HEIGHT>(
            party_id,
            &link_proof,
            &validity_proof,
            &settlement_proof,
        )
    }

    /// Build new output balance validity and private settlement witness and
    /// statement data with valid data
    ///
    /// This involves modifying the witness and statements for each circuit to
    /// align with one another so that they may be linked
    fn build_new_output_balance_private_settlement_data(
        party_id: u8,
    ) -> (
        NewOutputBalanceValidityWitness<TEST_MERKLE_HEIGHT>,
        NewOutputBalanceValidityStatement,
        IntentAndBalancePrivateSettlementWitness,
        IntentAndBalancePrivateSettlementStatement,
    ) {
        // Create the private settlement witness and statement with compatible intents
        let (mut settlement_witness, mut settlement_statement) =
            create_private_settlement_witness_statement();

        // Get mutable references to the relevant fields based on the party ID
        let (output_balance, pre_settlement_out_balance_shares) = if party_id == 0 {
            (
                &mut settlement_witness.output_balance0,
                &mut settlement_witness.pre_settlement_out_balance_shares0,
            )
        } else {
            (
                &mut settlement_witness.output_balance1,
                &mut settlement_witness.pre_settlement_out_balance_shares1,
            )
        };

        // Create a zeroed balance matching the settlement's output balance (mint and
        // owner)
        let mut zeroed_balance = random_zeroed_balance();
        zeroed_balance.mint = output_balance.mint;
        zeroed_balance.owner = output_balance.owner;

        // Create the validity witness and statement using the zeroed balance
        let (validity_witness, validity_statement) =
            create_new_output_balance_witness_statement_with_balance::<TEST_MERKLE_HEIGHT>(
                zeroed_balance,
            );

        // Align the settlement witness with the validity witness
        *output_balance = validity_witness.balance.clone();
        *pre_settlement_out_balance_shares = validity_witness.post_match_balance_shares.clone();

        // Update the settlement statement to reflect the settlement
        let amt_out0 = settlement_witness.settlement_obligation0.amount_out;
        let amt_out1 = settlement_witness.settlement_obligation1.amount_out;
        let fee_rate0 =
            FeeRates::new(settlement_statement.relayer_fee0, settlement_statement.protocol_fee);
        let fee_rate1 =
            FeeRates::new(settlement_statement.relayer_fee1, settlement_statement.protocol_fee);
        let fee_take0 = fee_rate0.compute_fee_take(amt_out0);
        let fee_take1 = fee_rate1.compute_fee_take(amt_out1);
        let net_receive0 = amt_out0 - fee_take0.total();
        let net_receive1 = amt_out1 - fee_take1.total();

        settlement_statement.new_out_balance_public_shares0 =
            settlement_witness.pre_settlement_out_balance_shares0.clone();
        settlement_statement.new_out_balance_public_shares1 =
            settlement_witness.pre_settlement_out_balance_shares1.clone();

        settlement_statement.new_out_balance_public_shares0.amount += Scalar::from(net_receive0);
        settlement_statement.new_out_balance_public_shares0.relayer_fee_balance +=
            Scalar::from(fee_take0.relayer_fee);
        settlement_statement.new_out_balance_public_shares0.protocol_fee_balance +=
            Scalar::from(fee_take0.protocol_fee);
        settlement_statement.new_out_balance_public_shares1.amount += Scalar::from(net_receive1);
        settlement_statement.new_out_balance_public_shares1.relayer_fee_balance +=
            Scalar::from(fee_take1.relayer_fee);
        settlement_statement.new_out_balance_public_shares1.protocol_fee_balance +=
            Scalar::from(fee_take1.protocol_fee);

        (validity_witness, validity_statement, settlement_witness, settlement_statement)
    }

    // --------------
    // | Test Cases |
    // --------------

    // --- Valid Test Cases --- //

    /// Tests a valid link between a proof of OUTPUT BALANCE VALIDITY and a
    /// proof of INTENT AND BALANCE PUBLIC SETTLEMENT
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    fn test_output_balance_valid_link() {
        let (validity_witness, validity_statement, settlement_witness, settlement_statement) =
            build_output_balance_validity_settlement_data();

        test_output_balance_validity_settlement_link(
            &validity_witness,
            &validity_statement,
            &settlement_witness,
            &settlement_statement,
        )
        .unwrap();
    }

    /// Tests a valid link between a proof of NEW OUTPUT BALANCE VALIDITY and a
    /// proof of INTENT AND BALANCE PUBLIC SETTLEMENT
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    fn test_new_output_balance_valid_link() {
        let (validity_witness, validity_statement, settlement_witness, settlement_statement) =
            build_new_output_balance_validity_settlement_data();

        test_new_output_balance_validity_settlement_link(
            &validity_witness,
            &validity_statement,
            &settlement_witness,
            &settlement_statement,
        )
        .unwrap();
    }

    /// Tests a valid link between a proof of OUTPUT BALANCE VALIDITY and a
    /// proof of INTENT AND BALANCE PRIVATE SETTLEMENT
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    fn test_output_balance_valid_private_link() {
        let mut rng = thread_rng();
        let party_id = *[0u8, 1].choose(&mut rng).unwrap();
        let (validity_witness, validity_statement, settlement_witness, settlement_statement) =
            build_output_balance_private_settlement_data(party_id);

        test_output_balance_private_settlement_link(
            party_id,
            &validity_witness,
            &validity_statement,
            &settlement_witness,
            &settlement_statement,
        )
        .unwrap()
    }

    /// Tests a valid link between a proof of NEW OUTPUT BALANCE VALIDITY and a
    /// proof of INTENT AND BALANCE PRIVATE SETTLEMENT
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    fn test_new_output_balance_valid_private_link() {
        let mut rng = thread_rng();
        let party_id = *[0u8, 1].choose(&mut rng).unwrap();
        let (validity_witness, validity_statement, settlement_witness, settlement_statement) =
            build_new_output_balance_private_settlement_data(party_id);

        test_new_output_balance_private_settlement_link(
            party_id,
            &validity_witness,
            &validity_statement,
            &settlement_witness,
            &settlement_statement,
        )
        .unwrap()
    }

    // --- Invalid Test Cases --- //

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
            &validity_witness,
            &validity_statement,
            &settlement_witness,
            &settlement_statement,
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
        settlement_statement.out_balance_public_shares.amount += modification;

        // Now the settlement circuit is valid, but the link will fail
        test_output_balance_validity_settlement_link(
            &validity_witness,
            &validity_statement,
            &settlement_witness,
            &settlement_statement,
        )
        .unwrap();
    }
}
