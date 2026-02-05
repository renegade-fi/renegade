//! Helpers for the task driver

use std::cmp;

use alloy::primitives::{Address, U256};
use circuit_types::{Amount, schnorr::SchnorrPublicKey};
use constants::Scalar;
use darkpool_types::{balance::DarkpoolBalance, state_wrapper::StateWrapper};
use job_types::proof_manager::{ProofJob, ProofManagerJob, ProofManagerResponse};
use renegade_solidity_abi::v2::relayer_types::u256_to_u128;
use tokio::sync::oneshot::{self, Receiver as TokioReceiver};
use tracing::info;
use types_account::balance::Balance;

use crate::traits::TaskContext;

pub mod indexer_client;
pub(crate) mod merkle_path;

/// Error message emitted when enqueuing a job with the proof manager fails
const ERR_ENQUEUING_JOB: &str = "error enqueuing job with proof manager";

/// Get the relayer fee address from state
///
/// Returns an error if the relayer fee address is not configured
pub(crate) fn get_relayer_fee_addr(ctx: &TaskContext) -> eyre::Result<Address> {
    ctx.state.get_relayer_fee_addr().map_err(|e| eyre::eyre!(e))
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

/// Fetch a ring 0 balance from on-chain data
///
/// Queries the ERC20 balance and permit2 allowance for the given token and
/// owner, returning a Balance if there is usable liquidity.
pub(crate) async fn fetch_ring0_balance(
    ctx: &TaskContext,
    token: Address,
    owner: Address,
) -> eyre::Result<Option<Balance>> {
    info!("Checking for balance of {token} for owner {owner}");
    let darkpool_client = &ctx.darkpool_client;
    let erc20_bal = darkpool_client.get_erc20_balance(token, owner).await?;
    let permit_allowance = darkpool_client.get_darkpool_allowance(owner, token).await?;
    let usable_balance = cmp::min(erc20_bal, permit_allowance);
    if usable_balance == U256::ZERO {
        info!(
            "No usable balance found for token {token} [balance = {}, permit = {}]",
            erc20_bal, permit_allowance
        );
        return Ok(None);
    }

    let amt = u256_to_u128(usable_balance);
    info!("Found usable balance of {amt} for token {token}");

    let relayer_fee_addr = get_relayer_fee_addr(ctx)?;
    let balance = create_ring0_balance(token, owner, relayer_fee_addr, amt);
    Ok(Some(balance))
}

/// Create a ring 0 balance from the given parameters
pub(crate) fn create_ring0_balance(
    mint: Address,
    owner: Address,
    relayer_fee_recipient: Address,
    amount: Amount,
) -> Balance {
    let mock_authority = SchnorrPublicKey::default();
    let bal = DarkpoolBalance::new(mint, owner, relayer_fee_recipient, mock_authority)
        .with_amount(amount);

    // Ring 0 balances don't have share or recovery streams, so we mock them
    let share_stream_seed = Scalar::zero();
    let recovery_stream_seed = Scalar::zero();
    let state_wrapper = StateWrapper::new(bal, share_stream_seed, recovery_stream_seed);
    Balance::new_eoa(state_wrapper)
}
