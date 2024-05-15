//! Helpers for the handshake manager tests

use common::types::{tasks::LookupWalletTaskDescriptor, wallet::Wallet};
use constants::Scalar;
use eyre::{eyre, Result};
use job_types::task_driver::new_task_notification;
use rand::thread_rng;
use test_helpers::contract_interaction::{allocate_wallet_in_darkpool, setup_wallet_shares};

use crate::IntegrationTestArgs;

/// Allocate a wallet in the darkpool and add it to global state
pub(crate) async fn allocate_wallet(wallet: &mut Wallet, args: &IntegrationTestArgs) -> Result<()> {
    let mut rng = thread_rng();
    let state = args.mock_node.state();
    let client = args.mock_node.arbitrum_client();

    // Generate wallet shares so we can find the wallet on-chain
    let blinder_seed = Scalar::random(&mut rng);
    let share_seed = Scalar::random(&mut rng);
    setup_wallet_shares(blinder_seed, share_seed, wallet);

    // Allocate the wallet directly then look it up
    allocate_wallet_in_darkpool(wallet, &client).await?;
    lookup_wallet(blinder_seed, share_seed, wallet, args).await?;

    // Finally read the wallet from state into the mutable reference
    *wallet = state.get_wallet(&wallet.wallet_id).await?.unwrap();
    Ok(())
}

/// Lookup the wallet so that it is setup correctly in global state
pub(crate) async fn lookup_wallet(
    blinder_seed: Scalar,
    share_seed: Scalar,
    wallet: &Wallet,
    args: &IntegrationTestArgs,
) -> Result<()> {
    let state = args.mock_node.state();
    let node = &args.mock_node;

    let task = LookupWalletTaskDescriptor {
        wallet_id: wallet.wallet_id,
        secret_share_seed: share_seed,
        blinder_seed,
        key_chain: wallet.key_chain.clone(),
    };
    let (id, waiter) = state.append_task(task.into()).await?;
    waiter.await?;

    // Enqueue a notification with the driver
    let (recv, job) = new_task_notification(id);
    node.send_task_job(job).unwrap();
    recv.await?.map_err(|e| eyre!(e))?;

    Ok(())
}
