//! Tests for the external match API

use circuit_types::order::OrderSide;
use common::types::token::Token;
use external_api::http::external_match::ExternalOrder;
use eyre::Result;
use reqwest::StatusCode;
use test_helpers::{assert_eq_result, integration_test_async};

use crate::ctx::IntegrationTestCtx;

/// Test a basic external match with no quote found
#[allow(non_snake_case)]
async fn test_basic_external_match__no_quote_found(ctx: IntegrationTestCtx) -> Result<()> {
    // Use a non-standard quote and base mint so that the order is not matched
    // with an order created by another test
    let base_mint = Token::from_ticker("UNI").get_addr_biguint();
    let quote_mint = Token::from_ticker("USDC").get_addr_biguint();
    let quote_amount = ctx.quote_token().convert_from_decimal(1000.);

    let external_order = ExternalOrder {
        base_mint,
        quote_mint,
        side: OrderSide::Buy,
        quote_amount,
        ..Default::default()
    };

    // Request an external match
    let res = ctx.send_external_quote_req(&external_order).await?;
    assert_eq_result!(res.status(), StatusCode::NO_CONTENT)
}
integration_test_async!(test_basic_external_match__no_quote_found);

/// Test a basic external match
#[allow(non_snake_case)]
async fn test_basic_external_match__buy_side__send_amount_specified(
    ctx: IntegrationTestCtx,
) -> Result<()> {
    let quote_amount = ctx.quote_token().convert_from_decimal(1000.);
    let external_order = ExternalOrder {
        base_mint: ctx.base_mint(),
        quote_mint: ctx.quote_mint(),
        side: OrderSide::Buy,
        quote_amount,
        ..Default::default()
    };

    // TODO: Complete the test
    Ok(())
}
integration_test_async!(test_basic_external_match__buy_side__send_amount_specified);
