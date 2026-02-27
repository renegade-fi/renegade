//! Helpers for calculating and recording metrics

use alloy_primitives::Address;
use darkpool_types::settlement_obligation::SettlementObligation;
use types_core::{AccountId, MatchResult, Token};
use util::hex::address_to_hex_string;

use crate::labels::{
    ASSET_METRIC_TAG, BASE_ASSET_METRIC_TAG, EXTERNAL_MATCH_METRIC_TAG, FEES_COLLECTED_METRIC,
    MATCH_BASE_VOLUME_METRIC, MATCH_QUOTE_VOLUME_METRIC, wallet_id_tag,
};

/// Get the human-readable asset and volume of
/// the given mint and amount.
/// The asset is the token ticker, if it is found, otherwise
/// the token's address.
/// The amount is the decimal amount of the transfer, going through
/// lossy f64 conversion via the associated number of decimals
fn get_asset_and_volume(mint: &Address, amount: u128) -> (String, f64) {
    let token = Token::from_alloy_address(mint);
    let asset = token.get_ticker().unwrap_or(address_to_hex_string(mint));
    let volume = token.convert_to_decimal(amount);

    (asset, volume)
}

/// Record a volume metric (e.g. deposit, withdrawal, trade)
fn record_volume(mint: &Address, amount: u128, volume_metric_name: &'static str) {
    record_volume_with_tags(mint, amount, volume_metric_name, &[] /* extra_labels */);
}

/// Record a volume metric with the given extra tags
fn record_volume_with_tags(
    mint: &Address,
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

/// Record the volume of base/quote assets moved in a match
pub fn record_match_volume(res: &MatchResult, is_external_match: bool, account_ids: &[AccountId]) {
    // A match result contains one obligation per party; either obligation has
    // enough information to derive base/quote volumes for USDC-quoted pairs.
    record_match_volume_from_obligation(&res.party0_obligation, is_external_match, account_ids);
}

/// Record the volume of base/quote assets moved by a settlement obligation
///
/// This helper assumes USDC-quoted pairs and emits no metrics when neither side
/// of the obligation is USDC.
pub fn record_match_volume_from_obligation(
    obligation: &SettlementObligation,
    is_external_match: bool,
    account_ids: &[AccountId],
) {
    let usdc = Token::usdc().get_alloy_address();
    let Some((base_mint, base_amount, quote_mint, quote_amount)) =
        derive_match_volumes(obligation, usdc)
    else {
        return;
    };

    let mut labels = build_match_labels(account_ids, is_external_match);

    record_volume_with_tags(&base_mint, base_amount, MATCH_BASE_VOLUME_METRIC, &labels);

    let (base_asset, _) = get_asset_and_volume(&base_mint, base_amount);
    labels.push((BASE_ASSET_METRIC_TAG.to_string(), base_asset));
    record_volume_with_tags(&quote_mint, quote_amount, MATCH_QUOTE_VOLUME_METRIC, &labels);
}

/// Record the volume of a fee settlement into the relayer's wallet
pub fn record_relayer_fee_settlement(mint: &Address, amount: u128) {
    record_volume(mint, amount, FEES_COLLECTED_METRIC);
}

/// Derive (base_mint, base_amount, quote_mint, quote_amount) from an
/// obligation.
fn derive_match_volumes(
    obligation: &SettlementObligation,
    usdc: Address,
) -> Option<(Address, u128, Address, u128)> {
    if obligation.input_token == usdc {
        // Buy order: input is quote (USDC), output is base.
        Some((
            obligation.output_token,
            obligation.amount_out,
            obligation.input_token,
            obligation.amount_in,
        ))
    } else if obligation.output_token == usdc {
        // Sell order: input is base, output is quote (USDC).
        Some((
            obligation.input_token,
            obligation.amount_in,
            obligation.output_token,
            obligation.amount_out,
        ))
    } else {
        None
    }
}

/// Build labels shared by match metrics.
fn build_match_labels(account_ids: &[AccountId], is_external_match: bool) -> Vec<(String, String)> {
    let mut labels: Vec<_> = account_ids
        .iter()
        .enumerate()
        .map(|(i, account_id)| (wallet_id_tag(i + 1), account_id.to_string()))
        .collect();

    if is_external_match {
        labels.push((EXTERNAL_MATCH_METRIC_TAG.to_string(), "true".to_string()));
    }

    labels
}
