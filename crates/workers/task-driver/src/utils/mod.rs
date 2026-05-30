//! Helpers for the task driver

use alloy::primitives::{Address, U256};
use circuit_types::{Amount, schnorr::SchnorrPublicKey};
use constants::Scalar;
use darkpool_types::{balance::DarkpoolBalance, state_wrapper::StateWrapper};
use job_types::proof_manager::{ProofJob, ProofManagerJob, ProofManagerResponse};
use renegade_solidity_abi::v2::relayer_types::u256_to_u128;
use tokio::sync::oneshot::{self, Receiver as TokioReceiver};
use types_account::balance::Balance;
use types_core::Token;
use util::log_task;
use util::logging::Outcome;

use crate::logging::Task;
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
pub(crate) async fn fetch_eoa_balance(
    ctx: &TaskContext,
    token: Address,
    owner: Address,
) -> eyre::Result<Option<Balance>> {
    let ticker = Token::from_alloy_address(&token).ticker_or_addr();
    log_task!(
        Task::LookupBalance,
        Outcome::Started,
        subject = %owner,
        token = %token,
        ticker = %ticker,
        "checking balance for {ticker}"
    );
    let darkpool_client = &ctx.darkpool_client;
    let usable_balance = darkpool_client.get_erc20_usable_balance(token, owner).await?;
    if usable_balance == U256::ZERO {
        log_task!(
            Task::LookupBalance,
            Outcome::Skipped,
            subject = %owner,
            token = %token,
            ticker = %ticker,
            "no usable balance found for {ticker}"
        );
        return Ok(None);
    }

    let amt = u256_to_u128(usable_balance);
    log_task!(
        Task::LookupBalance,
        Outcome::Ok,
        subject = %owner,
        token = %token,
        ticker = %ticker,
        amount = %amt,
        "found usable balance for {ticker}"
    );

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
