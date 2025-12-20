//! Integration tests for event indexing client functionality

use circuit_types::merkle::MerkleOpening;
use circuits::zk_circuits::test_helpers::create_multi_opening_with_default_leaf;
use constants::MERKLE_HEIGHT;
use darkpool_client::constants::EMPTY_LEAF_VALUE;
use eyre::Result;
use test_helpers::{assert_eq_result, integration_test_async};

use crate::{IntegrationTestArgs, helpers::setup_pre_allocated_state};

/// Tests finding a Merkle authentication path for a pre-allocated commitment
async fn test_find_merkle_path(test_args: IntegrationTestArgs) -> Result<()> {
    let mut client = test_args.client;
    let state = setup_pre_allocated_state(&mut client).await?;

    // Create Merkle openings to test against
    let (expected_root, expected_paths) = create_multi_opening_with_default_leaf::<MERKLE_HEIGHT>(
        &[state.index0_commitment, state.index1_commitment, state.index2_commitment],
        *EMPTY_LEAF_VALUE,
    );

    // Find Merkle openings via the `DarkpoolClient` and compare them to the
    // expected openings
    for (index, commitment) in
        [state.index0_commitment, state.index1_commitment, state.index2_commitment]
            .into_iter()
            .enumerate()
    {
        let merkle_path: MerkleOpening<MERKLE_HEIGHT> =
            client.find_merkle_authentication_path(commitment).await?.into();

        assert_eq_result!(merkle_path.indices, expected_paths[index].indices)?;
        assert_eq_result!(merkle_path.elems, expected_paths[index].elems)?;
    }

    let final_root =
        client.find_merkle_authentication_path(state.index2_commitment).await?.compute_root();

    assert_eq_result!(final_root, expected_root)
}
integration_test_async!(test_find_merkle_path);

/// Tests looking up a wallet by its public blinder share and parsing the
/// public shares from the calldata
async fn test_parse_public_shares_from_calldata(test_args: IntegrationTestArgs) -> Result<()> {
    let mut client = test_args.client;
    let state = setup_pre_allocated_state(&mut client).await?;

    for expected_public_share in [
        state.index0_public_wallet_shares,
        state.index1_public_wallet_shares,
        state.index2_public_wallet_shares,
    ]
    .into_iter()
    {
        // The public share of the wallet blinder
        let blinder_share = expected_public_share.blinder;

        // Parse the public shares from the calldata
        let public_shares = client.fetch_public_shares_for_blinder(blinder_share).await?;

        // Check that the public shares match the expected public shares
        assert_eq_result!(public_shares, expected_public_share)?;
    }

    Ok(())
}
integration_test_async!(test_parse_public_shares_from_calldata);
