//! Integration tests for the min fill size parameter

use circuit_types::{order::OrderSide, Amount};
use external_api::http::external_match::ExternalOrder;
use eyre::Result;
use hyper::StatusCode;
use test_helpers::{assert_eq_result, assert_true_result, integration_test_async};

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
    let amt = base_amount as f64 * 0.99;
    let order = ctx.build_matching_order_with_amount(&external_order, amt as Amount)?;
    ctx.setup_wallet_with_order(order).await?;

    // Fetch a quote, it should return no content
    let resp = ctx.send_external_quote_req(&external_order).await?;
    let status = resp.status();
    assert_eq_result!(status, StatusCode::NO_CONTENT)
}
integration_test_async!(test_min_fill_size__quote_denominated__no_quote);

/// Test a base denominated min fill size, on the buy side
#[allow(non_snake_case)]
async fn test_min_fill_size__base_denominated__buy_side(mut ctx: IntegrationTestCtx) -> Result<()> {
    // Clear the state
    ctx.clear_state().await?;

    // Create an external order with a min fill size
    let base_amount = ctx.base_token().convert_from_decimal(1.); // 1 WETH
    let min_fill_size = base_amount / 2;
    let external_order = ExternalOrder {
        base_mint: ctx.base_mint(),
        quote_mint: ctx.quote_mint(),
        side: OrderSide::Buy,
        base_amount,
        min_fill_size,
        ..Default::default()
    };

    // Setup an order to match against, then fetch a quote
    let order = ctx.build_matching_order_with_amount(&external_order, base_amount)?;
    ctx.setup_wallet_with_order(order).await?;
    let resp = ctx.request_external_quote(&external_order).await?;

    // Check that the size bounds are respected
    let quote = resp.signed_quote.quote;
    let recv_amount = quote.receive.amount;
    assert_true_result!(recv_amount >= min_fill_size)?;
    assert_true_result!(recv_amount <= base_amount)
}
integration_test_async!(test_min_fill_size__base_denominated__buy_side);

/// Test a base denominated min fill size, on the sell side
#[allow(non_snake_case)]
async fn test_min_fill_size__base_denominated__sell_side(
    mut ctx: IntegrationTestCtx,
) -> Result<()> {
    // Clear the state
    ctx.clear_state().await?;

    // Create an external order with a min fill size
    let base_amount = ctx.base_token().convert_from_decimal(1.); // 1 WETH
    let min_fill_size = base_amount / 2;
    let external_order = ExternalOrder {
        base_mint: ctx.base_mint(),
        quote_mint: ctx.quote_mint(),
        side: OrderSide::Sell,
        base_amount,
        min_fill_size,
        ..Default::default()
    };

    // Setup an order to match against, then fetch a quote
    let order = ctx.build_matching_order_with_amount(&external_order, base_amount)?;
    ctx.setup_wallet_with_order(order).await?;
    let resp = ctx.request_external_quote(&external_order).await?;

    // Check that the size bounds are respected
    let quote = resp.signed_quote.quote;
    let send_amount = quote.send.amount;
    assert_true_result!(send_amount >= min_fill_size)?;
    assert_true_result!(send_amount <= base_amount)
}
integration_test_async!(test_min_fill_size__base_denominated__sell_side);

/// Test a quote denominated min fill size, on the sell side
#[allow(non_snake_case)]
async fn test_min_fill_size__quote_denominated__sell_side(
    mut ctx: IntegrationTestCtx,
) -> Result<()> {
    // Clear the state
    ctx.clear_state().await?;

    // Create an external order with a min fill size
    let quote_amount = ctx.quote_token().convert_from_decimal(100.); // 100 USDC
    let base_amount = ctx.expected_base_amount(quote_amount);
    let min_fill_size = quote_amount / 2;
    let external_order = ExternalOrder {
        base_mint: ctx.base_mint(),
        quote_mint: ctx.quote_mint(),
        side: OrderSide::Sell,
        quote_amount,
        min_fill_size,
        ..Default::default()
    };

    // Setup an order to match against, then fetch a quote
    let order = ctx.build_matching_order_with_amount(&external_order, base_amount)?;
    ctx.setup_wallet_with_order(order).await?;
    let resp = ctx.request_external_quote(&external_order).await?;

    // Check that the size bounds are respected
    let recv_amount = resp.signed_quote.quote.receive.amount;
    assert_true_result!(recv_amount >= min_fill_size)?;
    assert_true_result!(recv_amount <= quote_amount)
}
integration_test_async!(test_min_fill_size__quote_denominated__sell_side);

/// Test a quote denominated min fill size, on the buy side
#[allow(non_snake_case)]
async fn test_min_fill_size__quote_denominated__buy_side(
    mut ctx: IntegrationTestCtx,
) -> Result<()> {
    // Clear the state
    ctx.clear_state().await?;

    // Create an external order with a min fill size
    let quote_amount = ctx.quote_token().convert_from_decimal(100.); // 100 USDC
    let base_amount = ctx.expected_base_amount(quote_amount);
    let min_fill_size = quote_amount / 2;
    let external_order = ExternalOrder {
        base_mint: ctx.base_mint(),
        quote_mint: ctx.quote_mint(),
        side: OrderSide::Buy,
        quote_amount,
        min_fill_size,
        ..Default::default()
    };

    // Setup an order to match against, then fetch a quote
    let order = ctx.build_matching_order_with_amount(&external_order, base_amount)?;
    ctx.setup_wallet_with_order(order).await?;
    let resp = ctx.request_external_quote(&external_order).await?;

    // Check that the size bounds are respected
    let send_amount = resp.signed_quote.quote.send.amount;
    assert_true_result!(send_amount >= min_fill_size)?;
    assert_true_result!(send_amount <= quote_amount)
}
integration_test_async!(test_min_fill_size__quote_denominated__buy_side);

/// Test a base denominated min fill size when `min_fill_size` equals the base
/// amount
#[allow(non_snake_case)]
async fn test_min_fill_size__base_denominated__equal_to_base_amount(
    mut ctx: IntegrationTestCtx,
) -> Result<()> {
    // Clear the state
    ctx.clear_state().await?;

    // Create an external order with a min fill size
    let base_amount = ctx.base_token().convert_from_decimal(1.); // 1 WETH
    let min_fill_size = base_amount;
    let external_order = ExternalOrder {
        base_mint: ctx.base_mint(),
        quote_mint: ctx.quote_mint(),
        side: OrderSide::Buy,
        base_amount,
        min_fill_size,
        ..Default::default()
    };

    // Setup an order to match against, then fetch a quote
    let order = ctx.build_matching_order_with_amount(&external_order, base_amount)?;
    ctx.setup_wallet_with_order(order).await?;
    let resp = ctx.request_external_quote(&external_order).await?;

    // Check that the size bounds are respected
    let quote = resp.signed_quote.quote;
    let recv_amount = quote.receive.amount;
    let total_fees = quote.fees.total();
    assert_eq_result!(recv_amount + total_fees, base_amount)
}
integration_test_async!(test_min_fill_size__base_denominated__equal_to_base_amount);

/// Test a quote denominated min fill size when `min_fill_size` equals the quote
/// amount
#[allow(non_snake_case)]
async fn test_min_fill_size__quote_denominated__equal_to_quote_amount(
    mut ctx: IntegrationTestCtx,
) -> Result<()> {
    // Clear the state
    ctx.clear_state().await?;

    // Create an external order with a min fill size
    let quote_amount = ctx.quote_token().convert_from_decimal(100.); // 100 USDC
    let base_amount = ctx.expected_base_amount(quote_amount);
    let min_fill_size = quote_amount;
    let external_order = ExternalOrder {
        base_mint: ctx.base_mint(),
        quote_mint: ctx.quote_mint(),
        side: OrderSide::Sell,
        quote_amount,
        min_fill_size,
        ..Default::default()
    };

    // Setup an order to match against, then fetch a quote
    let order = ctx.build_matching_order_with_amount(&external_order, base_amount + 1)?;
    ctx.setup_wallet_with_order(order).await?;
    let resp = ctx.request_external_quote(&external_order).await?;

    // Check that the size bounds are respected
    let quote = resp.signed_quote.quote;
    let recv_amount = quote.receive.amount;
    let total_fees = quote.fees.total();
    assert_eq_result!(recv_amount + total_fees, quote_amount)
}
integration_test_async!(test_min_fill_size__quote_denominated__equal_to_quote_amount);
