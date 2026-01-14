//! Helpers for the task driver

use alloy::primitives::Address;
use job_types::proof_manager::{ProofJob, ProofManagerJob, ProofManagerResponse};
use tokio::sync::oneshot::{self, Receiver as TokioReceiver};

use crate::traits::TaskContext;

pub(crate) mod merkle_path;

/// Error message emitted when enqueuing a job with the proof manager fails
const ERR_ENQUEUING_JOB: &str = "error enqueuing job with proof manager";
/// Error message emitted when a balance cannot be found for an order
const ERR_BALANCE_NOT_FOUND: &str = "cannot find balance for order";
/// Error message emitted when a wallet is given missing an authentication path
const ERR_MISSING_AUTHENTICATION_PATH: &str = "wallet missing authentication path";
/// Error message emitted when an order cannot be found in a wallet
const ERR_ORDER_NOT_FOUND: &str = "cannot find order in wallet";
/// Error message emitted when proving VALID COMMITMENTS fails
const ERR_PROVE_COMMITMENTS_FAILED: &str = "failed to prove valid commitments";
/// Error message emitted when proving VALID REBLIND fails
const ERR_PROVE_REBLIND_FAILED: &str = "failed to prove valid reblind";
/// The error thrown when the wallet cannot be found in tx history
pub const ERR_WALLET_NOT_FOUND: &str = "wallet not found in wallet_last_updated map";
/// Error message emitted when relayer fee address is not configured
const ERR_RELAYER_FEE_ADDR_NOT_CONFIGURED: &str = "relayer fee address not configured";

/// Get the relayer fee address from state
///
/// Returns an error if the relayer fee address is not configured
pub(crate) fn get_relayer_fee_addr(ctx: &TaskContext) -> Result<Address, String> {
    ctx.state
        .get_relayer_fee_addr()
        .map_err(|e| e.to_string())?
        .ok_or_else(|| ERR_RELAYER_FEE_ADDR_NOT_CONFIGURED.to_string())
}

/// Enqueue a job with the proof manager
///
/// Returns a channel on which the proof manager will send the response
pub(crate) fn enqueue_proof_job(
    job: ProofJob,
    ctx: &TaskContext,
) -> Result<TokioReceiver<ProofManagerResponse>, String> {
    let (response_sender, response_receiver) = oneshot::channel();
    ctx.proof_queue
        .send(ProofManagerJob { type_: job, response_channel: response_sender })
        .map_err(|_| ERR_ENQUEUING_JOB.to_string())?;

    Ok(response_receiver)
}
