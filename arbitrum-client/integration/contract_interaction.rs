//! Integration tests for contract interaction client functionality

use circuit_types::transfers::ExternalTransfer;
use common::types::proof_bundles::{
    mocks::{
        dummy_link_proof, dummy_relayer_fee_settlement_bundle, dummy_valid_match_settle_bundle,
        dummy_valid_wallet_update_bundle, dummy_validity_proof_bundle,
    },
    MatchBundle,
};
use eyre::Result;
use test_helpers::{assert_eq_result, integration_test_async};

use crate::{
    helpers::{deploy_new_wallet, random_wallet_shares},
    IntegrationTestArgs,
};

/// Tests submitting a new wallet and then recovering its shares from the
/// contract
async fn test_new_wallet(test_args: IntegrationTestArgs) -> Result<()> {
    let client = &test_args.client;

    // Deploy a new wallet
    let (_, public_shares) = deploy_new_wallet(client).await?;

    let recovered_public_shares =
        client.fetch_public_shares_for_blinder(public_shares.blinder).await?;

    // Check that the recovered public shares are the same as the original ones
    assert_eq_result!(public_shares, recovered_public_shares)
}
integration_test_async!(test_new_wallet);

/// Test submitting a wallet update that succeeds and then recovering its shares
async fn test_update_wallet(test_args: IntegrationTestArgs) -> Result<()> {
    let client = &test_args.client;

    // Update a wallet with a dummy proof bundle
    let mut valid_wallet_update_bundle = dummy_valid_wallet_update_bundle();
    let new_shares = random_wallet_shares();
    valid_wallet_update_bundle.statement.new_public_shares = new_shares.clone();
    valid_wallet_update_bundle.statement.external_transfer = ExternalTransfer::default();

    // Update the wallet
    client
        .update_wallet(
            &valid_wallet_update_bundle,
            vec![], // wallet_commitment_signature
            None,   // transfer_auth
        )
        .await?;

    let recovered_public_shares =
        client.fetch_public_shares_for_blinder(new_shares.blinder).await?;

    // Check that the recovered public shares are the same as the original ones
    assert_eq_result!(new_shares, recovered_public_shares)
}
integration_test_async!(test_update_wallet);

/// Tests submitting a match and then recovering both of the wallets' shares
/// shares from the contract
async fn test_process_match_settle(test_args: IntegrationTestArgs) -> Result<()> {
    let client = &test_args.client;

    // Submit a match between two wallets using dummy proof bundles
    let party_0_validity_proof_bundle = dummy_validity_proof_bundle();
    let party_1_validity_proof_bundle = dummy_validity_proof_bundle();
    let mut valid_match_settle_proof_bundle = dummy_valid_match_settle_bundle();

    let party_0_new_shares = random_wallet_shares();
    valid_match_settle_proof_bundle.statement.party0_modified_shares = party_0_new_shares.clone();

    let party_1_new_shares = random_wallet_shares();
    valid_match_settle_proof_bundle.statement.party1_modified_shares = party_1_new_shares.clone();

    let match_bundle = MatchBundle {
        match_proof: valid_match_settle_proof_bundle.into(),
        commitments_link0: dummy_link_proof(),
        commitments_link1: dummy_link_proof(),
    };

    client
        .process_match_settle(
            &party_0_validity_proof_bundle,
            &party_1_validity_proof_bundle,
            &match_bundle,
        )
        .await?;

    // Recover party 0's public shares
    let recovered_party_0_shares =
        client.fetch_public_shares_for_blinder(party_0_new_shares.blinder).await?;

    // Check that the recovered public shares are the same as the original ones
    assert_eq_result!(party_0_new_shares, recovered_party_0_shares)?;

    // Recover party 1's public shares
    let recovered_party_1_shares =
        client.fetch_public_shares_for_blinder(party_1_new_shares.blinder).await?;

    // Check that the recovered public shares are the same as the original ones
    assert_eq_result!(party_1_new_shares, recovered_party_1_shares)
}
integration_test_async!(test_process_match_settle);

/// Test settling the relayer fee and then recovering the shares of the sender
/// and recipient wallets
async fn test_settle_online_relayer_fee(test_args: IntegrationTestArgs) -> Result<()> {
    let client = &test_args.client;

    // Generate a dummy proof bundle for the relayer fee settlement
    let mut valid_relayer_fee_settlement_bundle = dummy_relayer_fee_settlement_bundle();
    let new_sender_shares = random_wallet_shares();
    let new_recipient_shares = random_wallet_shares();
    valid_relayer_fee_settlement_bundle.statement.sender_updated_public_shares =
        new_sender_shares.clone();
    valid_relayer_fee_settlement_bundle.statement.recipient_updated_public_shares =
        new_recipient_shares.clone();

    // Settle the relayer fee
    client
        .settle_online_relayer_fee(
            &valid_relayer_fee_settlement_bundle,
            vec![], // relayer_wallet_commitment_signature
        )
        .await?;

    let recovered_sender_shares =
        client.fetch_public_shares_for_blinder(new_sender_shares.blinder).await?;

    // Check that the recovered sender public shares are the same as the original
    // ones
    assert_eq_result!(new_sender_shares, recovered_sender_shares)?;

    let recovered_recipient_shares =
        client.fetch_public_shares_for_blinder(new_recipient_shares.blinder).await?;

    // Check that the recovered recipient public shares are the same as the original
    // ones
    assert_eq_result!(new_recipient_shares, recovered_recipient_shares)
}
integration_test_async!(test_settle_online_relayer_fee);
