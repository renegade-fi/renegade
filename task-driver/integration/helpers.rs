//! Helpers for `task-driver` integration tests

use arbitrum_client::client::ArbitrumClient;
use circuit_types::{
    native_helpers::create_wallet_shares_from_private, traits::BaseType,
    transfers::ExternalTransfer, SizedWalletShare,
};
use common::types::{
    proof_bundles::mocks::{dummy_valid_wallet_create_bundle, dummy_valid_wallet_update_bundle},
    wallet::Wallet,
    wallet_mocks::mock_empty_wallet,
};
use constants::Scalar;
use ethers::types::Address;
use external_api::types::ApiWallet;
use eyre::{eyre, Result};
use num_bigint::BigUint;
use rand::thread_rng;
use renegade_crypto::hash::{evaluate_hash_chain, PoseidonCSPRNG};
use system_bus::SystemBus;
use task_driver::{
    driver::{TaskDriver, TaskDriverConfig},
    lookup_wallet::LookupWalletTask,
};
use test_helpers::{assert_eq_result, assert_true_result};
use uuid::Uuid;

use crate::IntegrationTestArgs;

/// Parse a biguint from an H160 address
pub fn biguint_from_address(val: Address) -> BigUint {
    BigUint::from_bytes_be(val.as_bytes())
}

// ---------
// | Tasks |
// ---------

/// Lookup a wallet in the contract state and verify that it matches the
/// expected wallet
pub(crate) async fn lookup_wallet_and_check_result(
    expected_wallet: &Wallet,
    blinder_seed: Scalar,
    share_seed: Scalar,
    test_args: IntegrationTestArgs,
) -> Result<()> {
    // Start a lookup task for the new wallet
    let new_wallet_id = Uuid::new_v4();
    let state = test_args.global_state;
    let task = LookupWalletTask::new(
        new_wallet_id,
        blinder_seed,
        share_seed,
        expected_wallet.key_chain.clone(),
        test_args.arbitrum_client,
        test_args.network_sender,
        state.clone(),
        test_args.proof_job_queue,
    );

    let (_task_id, handle) = test_args.driver.start_task(task).await;
    let success = handle.await?;
    assert_true_result!(success)?;

    // Check the global state for the wallet and verify that it was correctly
    // recovered
    let state_wallet = state
        .read_wallet_index()
        .await
        .read_wallet(&new_wallet_id)
        .await
        .ok_or_else(|| eyre!("Wallet not found in global state"))?
        .clone();

    // Compare the secret shares directly
    assert_eq_result!(state_wallet.blinded_public_shares, expected_wallet.blinded_public_shares)?;
    assert_eq_result!(state_wallet.private_shares, expected_wallet.private_shares)
}

// ------------------------
// | Contract Interaction |
// ------------------------

/// Allocate a new empty wallet in the darkpool
///
/// Returns the `blinder_stream_seed` and `share_stream_seed` used to secret
/// share the wallet as well as the wallet itself
pub async fn new_wallet_in_darkpool(client: &ArbitrumClient) -> Result<(Wallet, Scalar, Scalar)> {
    let mut rng = thread_rng();
    let blinder_seed = Scalar::random(&mut rng);
    let share_seed = Scalar::random(&mut rng);

    let mut wallet = empty_wallet_from_seed(blinder_seed, share_seed);
    allocate_wallet_in_darkpool(&mut wallet, client).await?;

    Ok((wallet, blinder_seed, share_seed))
}

/// Create a wallet in the contract state and update the Merkle path on the
/// wallet
pub async fn allocate_wallet_in_darkpool(
    wallet: &mut Wallet,
    client: &ArbitrumClient,
) -> Result<()> {
    let share_comm = wallet.get_private_share_commitment();

    let mut proof = dummy_valid_wallet_create_bundle();
    proof.statement.public_wallet_shares = wallet.blinded_public_shares.clone();
    proof.statement.private_shares_commitment = share_comm;

    client.new_wallet(&proof).await?;

    // Find the Merkle opening for the wallet
    attach_merkle_opening(wallet, client).await
}

/// Find the merkle path of the wallet and attach it
pub async fn attach_merkle_opening(wallet: &mut Wallet, client: &ArbitrumClient) -> Result<()> {
    let comm = wallet.get_wallet_share_commitment();
    let opening = client.find_merkle_authentication_path(comm).await?;

    wallet.merkle_proof = Some(opening);
    Ok(())
}

/// Mock a wallet update by reblinding the shares and sending them to the
/// contract via an `update_wallet` transaction
///
/// Mutates the wallet in place so that the changes in the contract are
/// reflected in the caller's state
pub async fn mock_wallet_update(wallet: &mut Wallet, client: &ArbitrumClient) -> Result<()> {
    wallet.reblind_wallet();

    let mut rng = thread_rng();
    let share_comm = wallet.get_private_share_commitment();
    let nullifier = Scalar::random(&mut rng);

    // Mock a `VALID WALLET UPDATE` proof bundle
    let mut proof = dummy_valid_wallet_update_bundle();
    proof.statement.external_transfer = ExternalTransfer::default();
    proof.statement.old_shares_nullifier = nullifier;
    proof.statement.new_private_shares_commitment = share_comm;
    proof.statement.new_public_shares = wallet.blinded_public_shares.clone();

    client.update_wallet(&proof, vec![] /* statement_sig */).await.map_err(Into::into)
}

// ---------
// | Mocks |
// ---------

/// Create a new mock `TaskDriver`
pub fn new_mock_task_driver() -> TaskDriver {
    let bus = SystemBus::new();
    let config = TaskDriverConfig {
        backoff_amplification_factor: 2,
        backoff_ceiling_ms: 1_000, // 1 second
        initial_backoff_ms: 100,   // 100 milliseconds
        n_retries: 2,
        n_threads: 5,
        system_bus: bus,
    };

    TaskDriver::new(config)
}

// --------------
// | Dummy Data |
// --------------

/// Create a new, empty wallet
pub fn create_empty_api_wallet() -> ApiWallet {
    // Create the wallet secret shares let circuit_wallet = SizedWallet {
    let state_wallet = mock_empty_wallet();
    ApiWallet::from(state_wallet)
}

/// Create a mock wallet and secret share it with a given blinder seed
pub fn empty_wallet_from_seed(blinder_stream_seed: Scalar, secret_share_seed: Scalar) -> Wallet {
    // Create a blank wallet then modify the shares
    let mut wallet = mock_empty_wallet();
    setup_wallet_shares(blinder_stream_seed, secret_share_seed, &mut wallet);

    wallet
}

/// Create shares for a mock wallet given the seeds for the blinder and secret
///
/// Mutates the wallet to set its shares and blinder
pub fn setup_wallet_shares(
    blinder_stream_seed: Scalar,
    secret_share_seed: Scalar,
    wallet: &mut Wallet,
) {
    // Sample the blinder and blinder private share
    let blinder_and_private_share = evaluate_hash_chain(blinder_stream_seed, 2 /* length */);
    let new_blinder = blinder_and_private_share[0];
    let new_blinder_private_share = blinder_and_private_share[1];

    // Sample new secret shares for the wallet
    let mut share_csprng = PoseidonCSPRNG::new(secret_share_seed);
    let mut private_shares = SizedWalletShare::from_scalars(&mut share_csprng);
    private_shares.blinder = new_blinder_private_share;

    // Create the public shares
    let (private_shares, blinded_public_shares) =
        create_wallet_shares_from_private(&wallet.clone().into(), &private_shares, new_blinder);

    wallet.blinded_public_shares = blinded_public_shares;
    wallet.private_shares = private_shares;
    wallet.blinder = new_blinder;
}
