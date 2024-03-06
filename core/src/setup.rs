//! Setup logic for the node
//!
//! TODO(@joey): This module will eventually become a dedicated task, for now
//! this is sufficient

use std::time::Duration;

use common::types::{
    tasks::{LookupWalletTaskDescriptor, NewWalletTaskDescriptor},
    wallet::{
        keychain::{
            derive_blinder_seed, derive_share_seed, derive_wallet_id, derive_wallet_keychain,
        },
        KeyChain, Wallet, WalletIdentifier,
    },
};
use constants::Scalar;
use ethers::signers::LocalWallet;
use job_types::task_driver::TaskDriverQueue;
use state::State;
use task_driver::{await_task, tasks::lookup_wallet::ERR_WALLET_NOT_FOUND};
use tracing::info;
use util::err_str;

use crate::error::CoordinatorError;

/// Run the setup logic for the relayer
pub async fn node_setup(
    key: &LocalWallet,
    chain_id: u64,
    task_queue: TaskDriverQueue,
    state: &State,
) -> Result<(), CoordinatorError> {
    // Wait a small amount of time for raft to stabilize
    // TODO: remove this once we have a more fleshed out startup flow
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Setup the local node's wallet
    setup_relayer_wallet(key, chain_id, task_queue, state).await
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

    let wallet_id = derive_wallet_id(key).map_err(err_str!(CoordinatorError::Setup))?;

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
