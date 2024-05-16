//! Setup logic for the node
//!
//! TODO(@joey): This module will eventually become a dedicated task, for now
//! this is sufficient

use std::time::Duration;

use arbitrum_client::client::ArbitrumClient;
use common::types::{
    tasks::{
        LookupWalletTaskDescriptor, NewWalletTaskDescriptor, NodeStartupTaskDescriptor, QueuedTask,
        QueuedTaskState, TaskDescriptor,
    },
    wallet::{
        derivation::{
            derive_blinder_seed, derive_share_seed, derive_wallet_id, derive_wallet_keychain,
        },
        KeyChain, Wallet, WalletIdentifier,
    },
};
use config::RelayerConfig;
use constants::Scalar;
use ethers::signers::LocalWallet;
use job_types::task_driver::{new_task_notification, TaskDriverJob, TaskDriverQueue};
use state::State;
use task_driver::{await_task, tasks::lookup_wallet::ERR_WALLET_NOT_FOUND};
use tracing::info;
use util::{
    arbitrum::{PROTOCOL_FEE, PROTOCOL_PUBKEY},
    err_str, get_current_time_millis,
};

use crate::error::CoordinatorError;

/// An error sending a task to the task driver
const ERR_SENDING_STARTUP_TASK: &str = "error sending startup task to task driver";

/// Run the setup logic for the relayer
pub async fn node_setup(
    config: &RelayerConfig,
    _chain_id: u64,
    task_queue: TaskDriverQueue,
    _client: &ArbitrumClient,
    _state: &State,
) -> Result<(), CoordinatorError> {
    // Start the node setup task and await its completion
    let desc = NodeStartupTaskDescriptor::new(config.gossip_warmup);
    let id = desc.id;
    task_queue
        .send(TaskDriverJob::RunImmediate { task_id: id, wallet_ids: vec![], task: desc.into() })
        .map_err(|_| CoordinatorError::Setup(ERR_SENDING_STARTUP_TASK.to_string()))?;

    // Wait for the task driver to index the task then request a notification
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (recv, job) = new_task_notification(id);
    task_queue
        .send(job)
        .map_err(|_| CoordinatorError::Setup(ERR_SENDING_STARTUP_TASK.to_string()))?;
    recv.await.unwrap().map_err(err_str!(CoordinatorError::Setup))
}

// TODO: Delete the following code once the setup task is complete

/// Parameterize local constants by pulling them from the contract's storage
///
/// Concretely, this is the contract protocol key and the protocol fee
async fn fetch_contract_constants(client: &ArbitrumClient) -> Result<(), CoordinatorError> {
    // Fetch the values from the contract
    let protocol_fee =
        client.get_protocol_fee().await.map_err(err_str!(CoordinatorError::Setup))?;
    let protocol_key =
        client.get_protocol_pubkey().await.map_err(err_str!(CoordinatorError::Setup))?;
    info!("Fetched protocol fee and protocol pubkey");

    // Set the values in their constant refs
    PROTOCOL_FEE.set(protocol_fee).expect("protocol fee already set");
    PROTOCOL_PUBKEY.set(protocol_key).expect("protocol pubkey already set");
    Ok(())
}

/// Lookup the relayer's wallet or create a new one
async fn setup_relayer_wallet(
    key: &LocalWallet,
    chain_id: u64,
    task_queue: TaskDriverQueue,
    state: &State,
) -> Result<(), CoordinatorError> {
    // Derive the keychain, blinder seed, and share seed from the relayer pkey
    let blinder_seed = derive_blinder_seed(key).map_err(err_str!(CoordinatorError::Setup))?;
    let share_seed = derive_share_seed(key).map_err(err_str!(CoordinatorError::Setup))?;
    let keychain =
        derive_wallet_keychain(key, chain_id).map_err(err_str!(CoordinatorError::Setup))?;

    // Set the node metadata entry for the relayer's wallet
    let wallet_id = derive_wallet_id(key).map_err(err_str!(CoordinatorError::Setup))?;
    state
        .set_local_relayer_wallet_id(wallet_id)
        .await
        .map_err(err_str!(CoordinatorError::Setup))?;

    // Attempt to find the wallet on-chain
    if find_wallet_onchain(
        wallet_id,
        blinder_seed,
        share_seed,
        keychain.clone(),
        task_queue.clone(),
        state,
    )
    .await?
    {
        info!("found relayer wallet on-chain");
        return Ok(());
    }

    // Otherwise, create a new wallet
    create_wallet(wallet_id, blinder_seed, share_seed, keychain, task_queue, state).await
}

/// Attempt to fetch a wallet from on-chain
async fn find_wallet_onchain(
    wallet_id: WalletIdentifier,
    blinder_seed: Scalar,
    share_seed: Scalar,
    keychain: KeyChain,
    task_queue: TaskDriverQueue,
    state: &State,
) -> Result<bool, CoordinatorError> {
    info!("Finding relayer wallet on-chain");
    let descriptor = LookupWalletTaskDescriptor::new(wallet_id, blinder_seed, share_seed, keychain)
        .expect("infallible");
    let res = await_task(descriptor.into(), state, task_queue).await;

    match res {
        Ok(_) => Ok(true),
        Err(e) => {
            // If the error is that the wallet was not found, return false and create a new
            // wallet. Otherwise, propagate the error
            if e.contains(ERR_WALLET_NOT_FOUND) {
                Ok(false)
            } else {
                Err(CoordinatorError::Setup(e))
            }
        },
    }
}

/// Create a new wallet for the relayer
async fn create_wallet(
    wallet_id: WalletIdentifier,
    blinder_seed: Scalar,
    share_seed: Scalar,
    keychain: KeyChain,
    task_queue: TaskDriverQueue,
    state: &State,
) -> Result<(), CoordinatorError> {
    info!("Creating new relayer wallet");
    let wallet = Wallet::new_empty_wallet(wallet_id, blinder_seed, share_seed, keychain);
    let descriptor =
        NewWalletTaskDescriptor::new(wallet).map_err(err_str!(CoordinatorError::Setup))?;

    await_task(descriptor.into(), state, task_queue)
        .await
        .map_err(err_str!(CoordinatorError::Setup))
}
