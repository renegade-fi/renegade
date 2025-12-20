//! Tests external matches on native ETH

use circuit_types::order::OrderSide;
use constants::NATIVE_ASSET_ADDRESS;
use external_api::http::external_match::ExternalOrder;
use eyre::Result;
use test_helpers::{assert_eq_result, integration_test_async};
use util::hex::biguint_from_hex_string;

use crate::ctx::IntegrationTestCtx;

/// Tests a match on native ETH
async fn test_native_eth_match(ctx: IntegrationTestCtx) -> Result<()> {
    // Base mint here is ETH, we'll setup a matching order then replace the address
    // with the native ETH address
    let base_amount = ctx.base_token().convert_from_decimal(1.);
    let mut external_order = ExternalOrder {
        base_mint: ctx.base_mint(),
        quote_mint: ctx.quote_mint(),
        side: OrderSide::Sell,
        base_amount,
        ..Default::default()
    };

    // Setup a matching order, then request a quote
    ctx.setup_crossing_wallet(&external_order).await?;
    let native_eth = biguint_from_hex_string(NATIVE_ASSET_ADDRESS).unwrap();
    external_order.base_mint = native_eth;
    let resp = ctx.request_external_quote(&external_order).await?;

    let quote = resp.signed_quote.quote;
    let send_mint = quote.send.mint;
    let send_amt = quote.send.amount;
    assert_eq_result!(send_mint, NATIVE_ASSET_ADDRESS.to_lowercase())?;
    assert_eq_result!(send_amt, base_amount)
}
integration_test_async!(test_native_eth_match);
