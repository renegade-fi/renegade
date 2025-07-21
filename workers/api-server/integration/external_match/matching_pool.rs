//! Integration tests for external matching in a matching pool

use circuit_types::order::OrderSide;
use external_api::http::external_match::ExternalOrder;
use eyre::Result;
use hyper::StatusCode;
use state::storage::tx::matching_pools::GLOBAL_MATCHING_POOL;
use test_helpers::{assert_eq_result, integration_test_async};

use crate::ctx::IntegrationTestCtx;

/// The matching pool to use for testing
const TEST_POOL: &str = "test-pool";

/// Tests matching against an order in a matching pool when the request
/// specifies no pool
#[allow(non_snake_case)]
async fn test_external_match__matching_pool__no_pool_specified(
    mut ctx: IntegrationTestCtx,
) -> Result<()> {
    ctx.clear_state().await?;

    // Create an order
    let quote_amount = ctx.quote_token().convert_from_decimal(1000.);
    let external_order = ExternalOrder {
        base_mint: ctx.base_mint(),
        quote_mint: ctx.quote_mint(),
        side: OrderSide::Buy,
        quote_amount,
        min_fill_size: quote_amount,
        ..Default::default()
    };

    // Create a counterparty order in a non-global matching pool
    let wallet = ctx.setup_crossing_wallet(&external_order).await?;
    let (oid, _) = wallet.orders.first().cloned().unwrap();
    ctx.move_order_into_pool(oid, TEST_POOL.into()).await?;

    // Request a quote with no pool specified, this should allow all pools, and we
    // should receive a quote
    let resp = ctx.request_external_quote(&external_order).await?;
    let quote = resp.signed_quote.quote;
    assert_eq_result!(quote.send.mint, ctx.quote_token().get_addr())?;
    assert_eq_result!(quote.send.amount, quote_amount)
}
integration_test_async!(test_external_match__matching_pool__no_pool_specified);

/// Test matching against an order in a matching pool
#[allow(non_snake_case)]
async fn test_external_match__matching_pool(mut ctx: IntegrationTestCtx) -> Result<()> {
    ctx.clear_state().await?;

    // Create an order
    let quote_amount = ctx.quote_token().convert_from_decimal(1000.);
    let external_order = ExternalOrder {
        base_mint: ctx.base_mint(),
        quote_mint: ctx.quote_mint(),
        side: OrderSide::Buy,
        quote_amount,
        min_fill_size: quote_amount,
        ..Default::default()
    };

    // 1. Create a counterparty order and move it into a non-global matching pool
    let wallet = ctx.setup_crossing_wallet(&external_order).await?;
    let (oid, _) = wallet.orders.first().cloned().unwrap();
    ctx.move_order_into_pool(oid, TEST_POOL.into()).await?;

    // 2. Attempt to match against the global pool, no quote should be found
    let pool = GLOBAL_MATCHING_POOL.to_string();
    let relayer_fee_rate = 0.0;
    let resp = ctx.send_external_quote_req_in_pool(&external_order, pool, relayer_fee_rate).await?;
    assert_eq_result!(resp.status(), StatusCode::NO_CONTENT)?;

    // 3. Attempt to match against the testing pool, a quote should be found
    let pool = TEST_POOL.to_string();
    let resp = ctx.request_external_quote_in_pool(&external_order, pool).await?;
    let quote = resp.signed_quote.quote;
    assert_eq_result!(quote.send.mint, ctx.quote_token().get_addr())?;
    assert_eq_result!(quote.send.amount, quote_amount)
}
integration_test_async!(test_external_match__matching_pool);
