//! Helpers for calculating and recording metrics

use circuit_types::{r#match::MatchResult, transfers::ExternalTransferDirection};
use common::types::{token::Token, transfer_auth::ExternalTransferWithAuth};
use num_bigint::BigUint;
use util::hex::biguint_to_hex_string;

use crate::labels::{
    ASSET_METRIC_TAG, DEPOSIT_VOLUME_METRIC, FEES_COLLECTED_METRIC, MATCH_BASE_VOLUME_METRIC,
    MATCH_QUOTE_VOLUME_METRIC, NUM_COMPLETED_PROOFS_METRIC, NUM_COMPLETED_TASKS_METRIC,
    NUM_DEPOSITS_METRICS, NUM_STARTED_PROOFS_METRIC, NUM_STARTED_TASKS_METRIC,
    NUM_STOPPED_TASKS_METRIC, NUM_WITHDRAWALS_METRICS, WITHDRAWAL_VOLUME_METRIC,
};

/// Get the human-readable asset and volume of
/// the given mint and amount.
/// The asset is the token ticker, if it is found, otherwise
/// the token's address.
/// The amount is the decimal amount of the transfer, going through
/// lossy f64 conversion via the associated number of decimals
fn get_asset_and_volume(mint: &BigUint, amount: u128) -> (String, f64) {
    let token = Token::from_addr_biguint(mint);
    let asset = token.get_ticker().unwrap_or(&biguint_to_hex_string(mint)).to_string();
    let volume = token.convert_to_decimal(amount);

    (asset, volume)
}

/// Record a volume metric (e.g. deposit, withdrawal, trade)
fn record_volume(mint: &BigUint, amount: u128, volume_metric_name: &'static str) {
    let (asset, volume) = get_asset_and_volume(mint, amount);

    // We use a gauge metric here to be able to capture a float value
    // for the volume
    metrics::gauge!(volume_metric_name, ASSET_METRIC_TAG => asset).set(volume);
}

/// If an external transfer is present, record the count and volume metrics for
/// it
pub fn maybe_record_transfer_metrics(transfer: &Option<ExternalTransferWithAuth>) {
    if let Some(transfer) = transfer.as_ref() {
        let (count_metric, volume_metric) = match transfer.external_transfer.direction {
            ExternalTransferDirection::Deposit => (NUM_DEPOSITS_METRICS, DEPOSIT_VOLUME_METRIC),
            ExternalTransferDirection::Withdrawal => {
                (NUM_WITHDRAWALS_METRICS, WITHDRAWAL_VOLUME_METRIC)
            },
        };
        metrics::counter!(count_metric).increment(1);

        record_volume(
            &transfer.external_transfer.mint,
            transfer.external_transfer.amount,
            volume_metric,
        );
    }
}

/// Record the volume of base/quote assets moved in a match
pub fn record_match_volume(match_result: &MatchResult) {
    record_volume(&match_result.base_mint, match_result.base_amount, MATCH_BASE_VOLUME_METRIC);
    record_volume(&match_result.quote_mint, match_result.quote_amount, MATCH_QUOTE_VOLUME_METRIC);
}

/// Record the volume of a fee settlement into the relayer's wallet
pub fn record_relayer_fee_settlement(mint: &BigUint, amount: u128) {
    record_volume(mint, amount, FEES_COLLECTED_METRIC);
}

/// Increment the number of started tasks
#[inline]
pub fn incr_started_tasks() {
    #[cfg(feature = "task-metrics")]
    metrics::counter!(NUM_STARTED_TASKS_METRIC).increment(1);
}

/// Increment the number of stopped tasks by the given number of tasks
#[inline]
pub fn incr_stopped_tasks(num_tasks: usize) {
    #[cfg(feature = "task-metrics")]
    metrics::counter!(NUM_STOPPED_TASKS_METRIC).increment(num_tasks as u64);
}

/// Increment the number of completed tasks
#[inline]
pub fn incr_completed_tasks() {
    #[cfg(feature = "task-metrics")]
    metrics::counter!(NUM_COMPLETED_TASKS_METRIC).increment(1);
}

/// Increment the number of started proofs
#[inline]
pub fn incr_started_proofs() {
    #[cfg(feature = "proof-metrics")]
    metrics::counter!(NUM_STARTED_PROOFS_METRIC).increment(1);
}

/// Increment the number of completed proofs
#[inline]
pub fn incr_completed_proofs() {
    #[cfg(feature = "proof-metrics")]
    metrics::counter!(NUM_COMPLETED_PROOFS_METRIC).increment(1);
}
