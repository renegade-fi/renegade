//! Helpers for calculating and recording metrics

use circuit_types::{r#match::MatchResult, transfers::ExternalTransferDirection};
use common::types::{
    token::Token, transfer_auth::ExternalTransferWithAuth, wallet::WalletIdentifier,
};
use num_bigint::BigUint;
use util::hex::biguint_to_hex_addr;

use crate::labels::{
    wallet_id_tag, ASSET_METRIC_TAG, BASE_ASSET_METRIC_TAG, DEPOSIT_VOLUME_METRIC,
    EXTERNAL_MATCH_METRIC_TAG, FEES_COLLECTED_METRIC, MATCH_BASE_VOLUME_METRIC,
    MATCH_QUOTE_VOLUME_METRIC, NUM_DEPOSITS_METRICS, NUM_WITHDRAWALS_METRICS,
    WITHDRAWAL_VOLUME_METRIC,
};

/// Get the human-readable asset and volume of
/// the given mint and amount.
/// The asset is the token ticker, if it is found, otherwise
/// the token's address.
/// The amount is the decimal amount of the transfer, going through
/// lossy f64 conversion via the associated number of decimals
fn get_asset_and_volume(mint: &BigUint, amount: u128) -> (String, f64) {
    let token = Token::from_addr_biguint(mint);
    let asset = token.get_ticker().unwrap_or(biguint_to_hex_addr(mint));
    let volume = token.convert_to_decimal(amount);

    (asset, volume)
}

/// Record a volume metric (e.g. deposit, withdrawal, trade)
fn record_volume(mint: &BigUint, amount: u128, volume_metric_name: &'static str) {
    record_volume_with_tags(mint, amount, volume_metric_name, &[] /* extra_labels */);
}

/// Record a volume metric with the given extra tags
fn record_volume_with_tags(
    mint: &BigUint,
    amount: u128,
    volume_metric_name: &'static str,
    extra_labels: &[(String, String)],
) {
    let (asset, volume) = get_asset_and_volume(mint, amount);
    let mut labels = vec![(ASSET_METRIC_TAG.to_string(), asset)];
    let extra_labels = extra_labels.iter().map(|(k, v)| (k.clone(), v.clone()));
    labels.extend(extra_labels);

    // We use a gauge metric here to be able to capture a float value
    // for the volume
    metrics::gauge!(volume_metric_name, labels.as_slice()).set(volume);
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
pub fn record_match_volume(
    res: &MatchResult,
    is_external_match: bool,
    wallet_ids: &[WalletIdentifier],
) {
    // Tag with wallet IDs if provided
    let mut labels: Vec<_> = wallet_ids
        .iter()
        .enumerate()
        .map(|(i, wallet_id)| (wallet_id_tag(i + 1), wallet_id.to_string()))
        .collect();

    // Label the match as external in the metric
    if is_external_match {
        labels.push((EXTERNAL_MATCH_METRIC_TAG.to_string(), "true".to_string()));
    }

    record_volume_with_tags(&res.base_mint, res.base_amount, MATCH_BASE_VOLUME_METRIC, &labels);

    // Tag the base asset of the match
    let (base_asset, _) = get_asset_and_volume(&res.base_mint, res.base_amount);
    labels.push((BASE_ASSET_METRIC_TAG.to_string(), base_asset));
    record_volume_with_tags(&res.quote_mint, res.quote_amount, MATCH_QUOTE_VOLUME_METRIC, &labels);
}

/// Record the volume of a fee settlement into the relayer's wallet
pub fn record_relayer_fee_settlement(mint: &BigUint, amount: u128) {
    record_volume(mint, amount, FEES_COLLECTED_METRIC);
}
