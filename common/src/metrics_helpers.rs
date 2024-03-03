//! Helper functions and constants for recording metrics throughout the relayer

use circuit_types::{r#match::MatchResult, transfers::ExternalTransferDirection};
use num_bigint::BigUint;
use util::hex::biguint_to_hex_string;

use crate::types::{token::Token, transfer_auth::ExternalTransferWithAuth};

/// Metric describing the number of deposits made
const NUM_DEPOSITS_METRICS: &str = "num_deposits";
/// Metric describing the volume of deposits made
const DEPOSIT_VOLUME_METRIC: &str = "deposit_volume";
/// Metric describing the number of withdrawals made
const NUM_WITHDRAWALS_METRICS: &str = "num_withdrawals";
/// Metric describing the volume of withdrawals made
const WITHDRAWAL_VOLUME_METRIC: &str = "withdrawal_volume";
/// Metric describing the volume of the base asset in a match
const MATCH_BASE_VOLUME_METRIC: &str = "match_base_volume";
/// Metric describing the volume of the quote asset in a match
const MATCH_QUOTE_VOLUME_METRIC: &str = "match_quote_volume";
/// Metric label for the asset of a deposit/withdrawal
const ASSET_METRIC_LABEL: &str = "asset";

/// Get the human-readable asset and volume of
/// the given mint and amount.
/// The asset is the token ticker, if it is found, otherwise
/// the token's address.
/// The amount is the decimal amount of the transfer, going through
/// lossy f64 conversion via the associated number of decimals
fn get_asset_and_volume(mint: &BigUint, amount: u128) -> Result<(String, f64), String> {
    let token = Token::from_addr_biguint(mint);
    let asset = token.get_ticker().unwrap_or(&biguint_to_hex_string(mint)).to_string();
    let volume = token.get_amount_f64(amount)?;

    Ok((asset, volume))
}

/// Record the volume of an asset movement (e.g. deposit, withdrawal, trade)
/// if the asset and volume can be parsed
fn maybe_record_volume(mint: &BigUint, amount: u128, volume_metric_name: &'static str) {
    // Record the volume metrics only if we successfully parse the asset and volume,
    // to ensure metrics recording is infallible
    if let Ok((asset, volume)) = get_asset_and_volume(mint, amount) {
        // We use a gauge metric here to be able to capture a float value
        // for the volume
        metrics::gauge!(volume_metric_name, ASSET_METRIC_LABEL => asset).increment(volume);
    }
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

        maybe_record_volume(
            &transfer.external_transfer.mint,
            transfer.external_transfer.amount,
            volume_metric,
        );
    }
}

/// Record the volume of base/quote assets moved in a match
pub fn maybe_record_match_volume(match_result: &MatchResult) {
    maybe_record_volume(
        &match_result.base_mint,
        match_result.base_amount,
        MATCH_BASE_VOLUME_METRIC,
    );
    maybe_record_volume(
        &match_result.quote_mint,
        match_result.quote_amount,
        MATCH_QUOTE_VOLUME_METRIC,
    );
}
