//! Integration tests for the min fill size parameter

use circuit_types::order::OrderSide;
use external_api::http::external_match::ExternalOrder;
use eyre::Result;
use hyper::StatusCode;
use test_helpers::{assert_eq_result, integration_test_async};

use crate::ctx::IntegrationTestCtx;

/// Test a base denominated min fill size, with no quote
#[allow(non_snake_case)]
async fn test_min_fill_size__base_denominated__no_quote(mut ctx: IntegrationTestCtx) -> Result<()> {
    // Clear the state
    ctx.clear_state().await?;

    // Create an external order with a min fill size
    let base_amount = ctx.base_token().convert_from_decimal(1.); // 1 WETH
    let external_order = ExternalOrder {
        base_mint: ctx.base_mint(),
        quote_mint: ctx.quote_mint(),
        side: OrderSide::Buy,
        base_amount,
        min_fill_size: base_amount,
        ..Default::default()
    };

    // Setup an order which is too small to match
    let order = ctx.build_matching_order_with_amount(&external_order, base_amount - 1)?;
    ctx.setup_wallet_with_order(order).await?;

    // Fetch a quote, it should return no content
    let resp = ctx.send_external_quote_req(&external_order).await?;
    assert_eq_result!(resp.status(), StatusCode::NO_CONTENT)
}
integration_test_async!(test_min_fill_size__base_denominated__no_quote);

/// Test a quote denominated min fill size, with no quote
#[allow(non_snake_case)]
async fn test_min_fill_size__quote_denominated__no_quote(
    mut ctx: IntegrationTestCtx,
) -> Result<()> {
    // Clear the state
    ctx.clear_state().await?;

    // Create an external order with a min fill size
    let quote_amount = ctx.quote_token().convert_from_decimal(100.); // 100 USDC
    let base_amount = ctx.expected_base_amount(quote_amount);
    let external_order = ExternalOrder {
        base_mint: ctx.base_mint(),
        quote_mint: ctx.quote_mint(),
        side: OrderSide::Sell,
        quote_amount,
        min_fill_size: quote_amount,
        ..Default::default()
    };

    // Setup an order which is too small to match
    let order = ctx.build_matching_order_with_amount(&external_order, base_amount - 1)?;
    ctx.setup_wallet_with_order(order).await?;

    // Fetch a quote, it should return no content
    let resp = ctx.send_external_quote_req(&external_order).await?;
    assert_eq_result!(resp.status(), StatusCode::NO_CONTENT)
}
integration_test_async!(test_min_fill_size__quote_denominated__no_quote);
