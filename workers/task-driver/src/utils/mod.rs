//! Helpers for the task driver

use circuit_types::note::Note;
use common::types::{proof_bundles::ProofBundle, tasks::RedeemFeeTaskDescriptor};
use job_types::proof_manager::{ProofJob, ProofManagerJob};
use state::State;
use tokio::sync::oneshot::{self, Receiver as TokioReceiver};

use crate::traits::TaskContext;

pub mod find_wallet;
pub(crate) mod merkle_path;
pub mod order_states;
pub mod validity_proofs;

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
/// The error message emitted by the task when the fee decryption key is missing
const ERR_FEE_KEY_MISSING: &str = "fee decryption key is missing";
/// The error message emitted by the task when the relayer wallet is missing
const ERR_RELAYER_WALLET_MISSING: &str = "relayer wallet is missing";

/// Enqueue a job with the proof manager
///
/// Returns a channel on which the proof manager will send the response
pub(crate) fn enqueue_proof_job(
    job: ProofJob,
    ctx: &TaskContext,
) -> Result<TokioReceiver<ProofBundle>, String> {
    let (response_sender, response_receiver) = oneshot::channel();
    ctx.proof_queue
        .send(ProofManagerJob { type_: job, response_channel: response_sender })
        .map_err(|_| ERR_ENQUEUING_JOB.to_string())?;

    Ok(response_receiver)
}

/// Enqueue a job to redeem a relayer fee into the relayer's wallet
pub(crate) async fn enqueue_relayer_redeem_job(note: Note, state: &State) -> Result<(), String> {
    let relayer_wallet_id =
        state.get_relayer_wallet_id()?.ok_or_else(|| ERR_RELAYER_WALLET_MISSING.to_string())?;
    let decryption_key =
        state.get_fee_key()?.secret_key().ok_or_else(|| ERR_FEE_KEY_MISSING.to_string())?;
    let descriptor = RedeemFeeTaskDescriptor::new(relayer_wallet_id, note, decryption_key);

    state.append_task(descriptor.into()).await.map_err(|e| e.to_string()).map(|_| ())
}
