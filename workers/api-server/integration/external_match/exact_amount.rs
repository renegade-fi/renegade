//! Integration tests for specifying exact output amounts

use circuit_types::{Amount, order::OrderSide};
use external_api::http::external_match::ExternalOrder;
use eyre::Result;
use hyper::StatusCode;
use test_helpers::{assert_eq_result, integration_test_async};

use crate::ctx::IntegrationTestCtx;

/// Test specifying an exact quote amount which cannot be matched
#[allow(non_snake_case)]
async fn test_exact_quote_amount__no_quote(mut ctx: IntegrationTestCtx) -> Result<()> {
    // Clear the state
    ctx.clear_state().await?;

    // Create an external order with an exact quote amount
    let exact_quote_output = ctx.quote_token().convert_from_decimal(1000.);
    let base_amount = ctx.expected_base_amount(exact_quote_output);
    let external_order = ExternalOrder {
        base_mint: ctx.base_mint(),
        quote_mint: ctx.quote_mint(),
        side: OrderSide::Sell,
        exact_quote_output,
        ..Default::default()
    };

    // Setup a matching order, then request a quote
    let amt = base_amount as f64 * 0.99;
    let order = ctx.build_matching_order_with_amount(&external_order, amt as Amount)?;
    ctx.setup_wallet_with_order(order).await?;

    // Fetch a quote, it should return no content
    let resp = ctx.send_external_quote_req(&external_order).await?;
    assert_eq_result!(resp.status(), StatusCode::NO_CONTENT)
}
integration_test_async!(test_exact_quote_amount__no_quote);

/// Test specifying an exact base amount which cannot be matched
#[allow(non_snake_case)]
async fn test_exact_base_amount__no_quote(mut ctx: IntegrationTestCtx) -> Result<()> {
    // Clear the state
    ctx.clear_state().await?;

    // Create an external order with an exact base amount
    let exact_base_output = ctx.base_token().convert_from_decimal(1.);
    let external_order = ExternalOrder {
        base_mint: ctx.base_mint(),
        quote_mint: ctx.quote_mint(),
        side: OrderSide::Buy,
        exact_base_output,
        ..Default::default()
    };

    // Setup a matching order, then request a quote
    let order = ctx.build_matching_order_with_amount(&external_order, exact_base_output - 1)?;
    ctx.setup_wallet_with_order(order).await?;

    // Fetch a quote, it should return no content
    let resp = ctx.send_external_quote_req(&external_order).await?;
    assert_eq_result!(resp.status(), StatusCode::NO_CONTENT)
}
integration_test_async!(test_exact_base_amount__no_quote);

/// Test specifying an exact quote amount on the buy side
#[allow(non_snake_case)]
async fn test_exact_quote_amount__buy_side(mut ctx: IntegrationTestCtx) -> Result<()> {
    // Clear the state
    ctx.clear_state().await?;

    // Create an external order with an exact quote amount
    let exact_quote_output = ctx.quote_token().convert_from_decimal(1000.);
    let external_order = ExternalOrder {
        base_mint: ctx.base_mint(),
        quote_mint: ctx.quote_mint(),
        side: OrderSide::Buy,
        exact_quote_output,
        ..Default::default()
    };

    // Setup a matching order, then request a quote
    ctx.setup_crossing_wallet(&external_order).await?;

    // Fetch a quote, then assemble the quote into a match bundle
    let resp = ctx.request_external_quote(&external_order).await?;
    let quote = resp.signed_quote.quote;
    let send_amount = quote.send.amount;
    assert_eq_result!(send_amount, exact_quote_output)
}
integration_test_async!(test_exact_quote_amount__buy_side);

/// Test specifying an exact quote amount on the sell side
#[allow(non_snake_case)]
async fn test_exact_quote_amount__sell_side(mut ctx: IntegrationTestCtx) -> Result<()> {
    // Clear the state
    ctx.clear_state().await?;

    // Create an external order with an exact quote amount
    let exact_quote_output = ctx.quote_token().convert_from_decimal(1000.);
    let external_order = ExternalOrder {
        base_mint: ctx.base_mint(),
        quote_mint: ctx.quote_mint(),
        side: OrderSide::Sell,
        exact_quote_output,
        ..Default::default()
    };

    // Setup a matching order, then request a quote
    ctx.setup_crossing_wallet(&external_order).await?;

    // Fetch a quote, then assemble the quote into a match bundle
    let resp = ctx.request_external_quote(&external_order).await?;
    let quote = resp.signed_quote.quote;

    // The API should account for fees in the match amount, so we should get exactly
    // the specified amount back
    let recv_amount = quote.receive.amount;
    assert_eq_result!(recv_amount, exact_quote_output)
}
integration_test_async!(test_exact_quote_amount__sell_side);

/// Test specifying an exact base amount on the buy side
#[allow(non_snake_case)]
async fn test_exact_base_amount__buy_side(mut ctx: IntegrationTestCtx) -> Result<()> {
    // Clear the state
    ctx.clear_state().await?;

    // Create an external order with an exact base amount
    let exact_base_output = ctx.base_token().convert_from_decimal(1.);
    let external_order = ExternalOrder {
        base_mint: ctx.base_mint(),
        quote_mint: ctx.quote_mint(),
        side: OrderSide::Buy,
        exact_base_output,
        ..Default::default()
    };

    // Setup a matching order, then request a quote
    ctx.setup_crossing_wallet(&external_order).await?;

    // Fetch a quote, then assemble the quote into a match bundle
    let resp = ctx.request_external_quote(&external_order).await?;
    let quote = resp.signed_quote.quote;
    let recv_amount = quote.receive.amount;
    assert_eq_result!(recv_amount, exact_base_output)
}
integration_test_async!(test_exact_base_amount__buy_side);

/// Test specifying an exact base amount on the sell side
#[allow(non_snake_case)]
async fn test_exact_base_amount__sell_side(mut ctx: IntegrationTestCtx) -> Result<()> {
    // Clear the state
    ctx.clear_state().await?;

    // Create an external order with an exact base amount
    let exact_base_output = ctx.base_token().convert_from_decimal(1.);
    let external_order = ExternalOrder {
        base_mint: ctx.base_mint(),
        quote_mint: ctx.quote_mint(),
        side: OrderSide::Sell,
        exact_base_output,
        ..Default::default()
    };

    // Setup a matching order, then request a quote
    ctx.setup_crossing_wallet(&external_order).await?;

    // Fetch a quote, then assemble the quote into a match bundle
    let resp = ctx.request_external_quote(&external_order).await?;
    let quote = resp.signed_quote.quote;
    let send_amount = quote.send.amount;
    assert_eq_result!(send_amount, exact_base_output)
}
integration_test_async!(test_exact_base_amount__sell_side);
