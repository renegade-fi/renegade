//! Helpers for `task-driver` integration tests

use circuit_types::{
    native_helpers::create_wallet_shares_from_private, traits::BaseType, SizedWalletShare,
};
use common::types::{
    proof_bundles::mocks::{dummy_valid_wallet_create_bundle, dummy_valid_wallet_update_bundle},
    wallet::Wallet,
    wallet_mocks::mock_empty_wallet,
};
use external_api::types::Wallet as ApiWallet;
use eyre::Result;
use mpc_stark::algebra::scalar::Scalar;
use rand::thread_rng;
use renegade_crypto::hash::{evaluate_hash_chain, PoseidonCSPRNG};
use starknet_client::client::StarknetClient;
use system_bus::SystemBus;
use task_driver::driver::{TaskDriver, TaskDriverConfig};

// ------------------------
// | Contract Interaction |
// ------------------------

/// Create a wallet in the contract state
pub async fn allocate_wallet_in_darkpool(wallet: &Wallet, client: &StarknetClient) -> Result<()> {
    let share_comm = wallet.get_private_share_commitment();
    let proof = dummy_valid_wallet_create_bundle();

    let tx_hash = client
        .new_wallet(share_comm, wallet.blinded_public_shares.clone(), proof)
        .await?;
    client.poll_transaction_completed(tx_hash).await?;
    Ok(())
}

/// Mock a wallet update by reblinding the shares and sending them to the contract
/// via an `update_wallet` transaction
///
/// Mutates the wallet in place so that the changes in the contract are reflected in the caller's state
pub async fn mock_wallet_update(wallet: &mut Wallet, client: &StarknetClient) -> Result<()> {
    wallet.reblind_wallet();

    let mut rng = thread_rng();
    let share_comm = wallet.get_private_share_commitment();
    let nullifier = Scalar::random(&mut rng);
    let proof = dummy_valid_wallet_update_bundle();

    let tx_hash = client
        .update_wallet(
            share_comm,
            nullifier,
            None, /* external_transfer */
            wallet.blinded_public_shares.clone(),
            proof,
        )
        .await?;
    client.poll_transaction_completed(tx_hash).await?;
    Ok(())
}

// ---------
// | Mocks |
// ---------

/// Create a new mock `TaskDriver`
pub fn new_mock_task_driver() -> TaskDriver {
    let bus = SystemBus::new();
    let config = TaskDriverConfig {
        backoff_amplification_factor: 2,
        backoff_ceiling_ms: 1_000, /* 1 second */
        initial_backoff_ms: 100,   /* 100 milliseconds */
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
    wallet
}
