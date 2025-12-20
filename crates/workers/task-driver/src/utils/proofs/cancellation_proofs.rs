//! Utils for precomputing cancellation proofs for orders

use common::types::{
    proof_bundles::ValidWalletUpdateBundle,
    wallet::{OrderIdentifier, Wallet},
};
use job_types::proof_manager::ProofJob;
use tracing::{error, info};
use util::raw_err_str;

use crate::{
    tasks::update_wallet::UpdateWalletTask,
    traits::TaskContext,
    utils::{enqueue_proof_job, proofs::map_proof_result},
};

/// Precompute cancellation proofs for a wallet
pub(crate) async fn precompute_cancellation_proofs(
    wallet: &Wallet,
    ctx: &TaskContext,
) -> Result<(), String> {
    // Spawn a task for each order that requires a cancellation proof
    let mut handles = Vec::new();
    for (id, order) in wallet.orders.iter() {
        if !order.precompute_cancellation_proof {
            continue;
        }

        let oid = *id;
        let wallet_clone = wallet.clone();
        let ctx_clone = ctx.clone();
        let handle = tokio::spawn(async move {
            precompute_cancellation_proof_for_order(oid, wallet_clone, &ctx_clone).await
        });
        handles.push(handle);
    }

    // Await the tasks
    let mut proofs = Vec::new();
    for handle in handles {
        // Do not fail the whole operation if one proof fails
        match map_proof_result(handle.await) {
            Ok((oid, proof)) => proofs.push((oid, proof)),
            Err(e) => error!("Failed to precompute cancellation proof: {e}"),
        }
    }

    // Store the proofs in the state
    let waiter = ctx.state.add_local_order_cancellation_proofs(proofs).await?;
    waiter.await?;
    Ok(())
}

/// Precompute a cancellation proof for a given order
async fn precompute_cancellation_proof_for_order(
    order_id: OrderIdentifier,
    old_wallet: Wallet,
    ctx: &TaskContext,
) -> Result<(OrderIdentifier, ValidWalletUpdateBundle), String> {
    info!("Precomputing cancellation proof for order: {order_id}");
    let mut new_wallet = old_wallet.clone();
    new_wallet.remove_order(&order_id);
    new_wallet.reblind_wallet();

    let (witness, statement) =
        UpdateWalletTask::construct_witness_statement(&old_wallet, &new_wallet).map_err(
            raw_err_str!("Failed to construct witness statement for cancellation proof: {}"),
        )?;

    // Forward a job to the proof manager
    let job = ProofJob::ValidWalletUpdate { witness, statement };
    let recv =
        enqueue_proof_job(job, ctx).map_err(raw_err_str!("Failed to enqueue proof job: {}"))?;

    // Await the proof
    let bundle = recv.await.map_err(raw_err_str!("Failed to await proof: {}"))?;
    Ok((order_id, bundle.into()))
}
