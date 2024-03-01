//! Helpers for `task-driver` integration tests

use std::str::FromStr;

use alloy_primitives::Address as AlloyAddress;
use arbitrum_client::client::ArbitrumClient;
use circuit_types::transfers::ExternalTransfer;
use common::{
    types::{
        proof_bundles::mocks::dummy_valid_wallet_update_bundle,
        tasks::{LookupWalletTaskDescriptor, TaskDescriptor, TaskIdentifier},
        transfer_auth::ExternalTransferWithAuth,
        wallet::{Wallet, WalletIdentifier},
    },
    worker::Worker,
};
use constants::Scalar;
use ethers::types::Address;
use eyre::Result;
use job_types::{
    network_manager::NetworkManagerQueue,
    proof_manager::ProofManagerQueue,
    task_driver::{new_task_notification, TaskDriverJob, TaskDriverReceiver},
};
use num_bigint::BigUint;
use rand::thread_rng;
use state::State;
use system_bus::SystemBus;
use task_driver::{
    driver::RuntimeArgs,
    worker::{TaskDriver, TaskDriverConfig},
};
use test_helpers::{
    assert_eq_result,
    contract_interaction::{
        allocate_wallet_in_darkpool, setup_wallet_shares, transfer_auth::gen_transfer_with_auth,
    },
};

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
    secret_share_seed: Scalar,
    test_args: IntegrationTestArgs,
) -> Result<()> {
    // Start a lookup task for the new wallet
    let wallet_id = expected_wallet.wallet_id;
    let state = &test_args.state;

    let key_chain = expected_wallet.key_chain.clone();
    let task =
        LookupWalletTaskDescriptor::new(wallet_id, blinder_seed, secret_share_seed, key_chain)
            .unwrap();
    await_task(task.into(), &test_args).await?;

    // Check the global state for the wallet and verify that it was correctly
    // recovered
    let state_wallet = state.get_wallet(&wallet_id)?.unwrap();

    // Compare the secret shares directly
    assert_eq_result!(state_wallet.blinded_public_shares, expected_wallet.blinded_public_shares)?;
    assert_eq_result!(state_wallet.private_shares, expected_wallet.private_shares)
}

/// Await the queueing, execution, and completion of a task
pub(crate) async fn await_task(
    task: TaskDescriptor,
    test_args: &IntegrationTestArgs,
) -> Result<()> {
    // Wait for the task to be queued
    let (task_id, waiter) = test_args.state.append_task(task)?;
    waiter.await?;

    let (rx, job) = new_task_notification(task_id);
    test_args.task_queue.send(job).unwrap();

    rx.await.unwrap().map_err(|e| eyre::eyre!(e))
}

/// Await the execution and completion of a task run immediately
pub(crate) async fn await_immediate_task(
    modified_wallets: Vec<WalletIdentifier>,
    task: TaskDescriptor,
    test_args: &IntegrationTestArgs,
) -> Result<()> {
    let task_id = TaskIdentifier::new_v4();
    let job = TaskDriverJob::RunImmediate { task_id, wallet_ids: modified_wallets, task };
    test_args.task_queue.send(job).unwrap();

    let (rx, job) = new_task_notification(task_id);
    test_args.task_queue.send(job).unwrap();

    rx.await.unwrap().map_err(|e| eyre::eyre!(e))
}

// ------------------------
// | Contract Interaction |
// ------------------------

/// Sets up a new wallet in the system by:
///     1. Generating secret shares for the wallet
///     2. Allocating it in the darkpool directly
///     3. Looking up the wallet in the contract state so that the wallet
///        appears in the global state
pub(crate) async fn setup_initial_wallet(
    blinder_seed: Scalar,
    share_seed: Scalar,
    wallet: &mut Wallet,
    test_args: &IntegrationTestArgs,
) -> Result<()> {
    setup_wallet_shares(blinder_seed, share_seed, wallet);
    allocate_wallet_in_darkpool(wallet, &test_args.arbitrum_client).await?;
    lookup_wallet_and_check_result(wallet, blinder_seed, share_seed, test_args.clone()).await?;

    // Read the wallet from the global state so that order IDs match
    *wallet = test_args.state.get_wallet(&wallet.wallet_id)?.unwrap();
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

    client
        .update_wallet(&proof, vec![] /* statement_sig */, None /* transfer_auth */)
        .await
        .map_err(Into::into)
}

/// Get an authorized external transfer for the wallet
pub async fn authorize_transfer(
    transfer: ExternalTransfer,
    test_args: &IntegrationTestArgs,
) -> Result<ExternalTransferWithAuth> {
    let client = &test_args.arbitrum_client;
    let chain_id = client.chain_id().await.unwrap();
    let permit2_address = AlloyAddress::from_str(&test_args.permit2_addr)?;
    let darkpool_address = AlloyAddress::from_slice(client.darkpool_contract.address().as_bytes());

    let eth_client = client.darkpool_contract.client(); // Assigned to avoid dropping
    let signer = eth_client.signer();

    gen_transfer_with_auth(signer, permit2_address, darkpool_address, chain_id, transfer)
}

// ---------
// | Mocks |
// ---------

/// Create a new mock `TaskDriver`
pub fn new_mock_task_driver(
    task_queue: TaskDriverReceiver,
    arbitrum_client: ArbitrumClient,
    network_queue: NetworkManagerQueue,
    proof_queue: ProofManagerQueue,
    state: State,
) {
    let bus = SystemBus::new();
    // Set a runtime config with fast failure
    let runtime_config = RuntimeArgs {
        backoff_amplification_factor: 2,
        backoff_ceiling_ms: 1_000, // 1 second
        initial_backoff_ms: 100,   // 100 milliseconds
        n_retries: 2,
        n_threads: 5,
    };

    let config = TaskDriverConfig {
        task_queue,
        runtime_config,
        system_bus: bus,
        arbitrum_client,
        network_queue,
        proof_queue,
        state,
    };

    // Start the driver
    let mut driver = TaskDriver::new(config).unwrap();
    driver.start().unwrap();
}
