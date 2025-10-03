//! Proof utils for the task driver
pub(crate) mod cancellation_proofs;
pub(crate) mod validity_proofs;

use cancellation_proofs::precompute_cancellation_proofs;
use common::types::wallet::Wallet;
use tokio::task::JoinError;
use validity_proofs::update_wallet_validity_proofs;

use crate::traits::TaskContext;

/// Update all precomputed proofs for a wallet
pub(crate) async fn update_wallet_proofs(
    new_wallet: &Wallet,
    task_ctx: &TaskContext,
) -> Result<(), String> {
    // 1. Update the validity proofs for the wallet, that is the proofs of `VALID
    //    COMMITMENTS` and `VALID REBLIND`
    let ctx = task_ctx.clone();
    let wallet = new_wallet.clone();
    let validity_jh =
        tokio::spawn(async move { update_wallet_validity_proofs(&wallet, &ctx).await });

    // 2. Precompute cancellation proofs for each order that requires one
    let ctx = task_ctx.clone();
    let wallet = new_wallet.clone();
    let cancellation_jh =
        tokio::spawn(async move { precompute_cancellation_proofs(&wallet, &ctx).await });

    // Join both threads and handle errors
    let (validity_res, cancellation_res) = tokio::join!(validity_jh, cancellation_jh);
    map_proof_result(validity_res)?;
    map_proof_result(cancellation_res)
}

/// Map a proof result to a string error
#[inline]
fn map_proof_result<T>(result: Result<Result<T, String>, JoinError>) -> Result<T, String> {
    result.map_err(|e| e.to_string())?
}
