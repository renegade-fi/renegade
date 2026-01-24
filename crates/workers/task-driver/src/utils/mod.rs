//! Helpers for the task driver

use alloy::primitives::Address;
use job_types::proof_manager::{ProofJob, ProofManagerJob, ProofManagerResponse};
use tokio::sync::oneshot::{self, Receiver as TokioReceiver};

use crate::traits::TaskContext;

pub(crate) mod merkle_path;

/// Error message emitted when enqueuing a job with the proof manager fails
const ERR_ENQUEUING_JOB: &str = "error enqueuing job with proof manager";

/// Get the relayer fee address from state
///
/// Returns an error if the relayer fee address is not configured
pub(crate) fn get_relayer_fee_addr(ctx: &TaskContext) -> Result<Address, String> {
    ctx.state.get_relayer_fee_addr().map_err(|e| e.to_string())
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
