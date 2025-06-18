//! Tests for the external match API

use circuit_types::order::OrderSide;
use common::types::token::Token;
use external_api::http::external_match::ExternalOrder;
use eyre::Result;
use reqwest::StatusCode;
use test_helpers::{assert_eq_result, integration_test_async};

use crate::{ctx::IntegrationTestCtx, helpers::assert_approx_eq};

/// The tolerance used for approximate equality checks
const DIFF_TOLERANCE: f64 = 0.000001;

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

/// Test a basic external match on the buy side with a send amount specified
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

    // Setup a matching order, then request a quote
    ctx.setup_wallet_for_order(&external_order).await?;
    let resp = ctx.request_external_quote(&external_order).await?;
    let quote = resp.signed_quote.quote;

    // Verify the response contents
    let base_mint = ctx.base_token().get_addr();
    let quote_mint = ctx.quote_token().get_addr();
    let send_mint = quote.send.mint;
    let send_amount = quote.send.amount;
    assert_eq_result!(send_mint, quote_mint)?;
    assert_eq_result!(send_amount, quote_amount)?;

    let recv_mint = quote.receive.mint;
    let recv_amount = quote.receive.amount;
    let total_fees = quote.fees.total();
    let expected_base_amt = ctx.expected_base_amount(quote_amount);
    assert_eq_result!(recv_mint, base_mint)?;
    assert_approx_eq(recv_amount + total_fees, expected_base_amt, DIFF_TOLERANCE)?;

    // Verify the match result
    let match_res = quote.match_result;
    assert_eq_result!(match_res.base_mint, base_mint)?;
    assert_eq_result!(match_res.quote_mint, quote_mint)?;
    assert_eq_result!(match_res.quote_amount, send_amount)?;
    assert_eq_result!(match_res.base_amount, recv_amount + total_fees)?;
    assert_eq_result!(match_res.direction, OrderSide::Buy)
}
integration_test_async!(test_basic_external_match__buy_side__send_amount_specified);

/// Test a basic external match on the sell side with a send amount specified
#[allow(non_snake_case)]
async fn test_basic_external_match__sell_side__send_amount_specified(
    ctx: IntegrationTestCtx,
) -> Result<()> {
    let base_amount = ctx.base_token().convert_from_decimal(1.); // 1 WETH
    let external_order = ExternalOrder {
        base_mint: ctx.base_mint(),
        quote_mint: ctx.quote_mint(),
        side: OrderSide::Sell,
        base_amount,
        ..Default::default()
    };

    // Setup a matching order, then request a quote
    ctx.setup_wallet_for_order(&external_order).await?;
    let resp = ctx.request_external_quote(&external_order).await?;
    let quote = resp.signed_quote.quote;

    // Verify the response contents
    let base_mint = ctx.base_token().get_addr();
    let quote_mint = ctx.quote_token().get_addr();
    let send_mint = quote.send.mint;
    let send_amount = quote.send.amount;
    assert_eq_result!(send_mint, base_mint)?;
    assert_eq_result!(send_amount, base_amount)?;

    let recv_mint = quote.receive.mint;
    let recv_amount = quote.receive.amount;
    let total_fees = quote.fees.total();
    let expected_quote_amt = ctx.expected_quote_amount(base_amount);
    assert_eq_result!(recv_mint, quote_mint)?;
    assert_approx_eq(recv_amount + total_fees, expected_quote_amt, DIFF_TOLERANCE)?;

    // Verify the match result
    let match_res = quote.match_result;
    assert_eq_result!(match_res.base_mint, base_mint)?;
    assert_eq_result!(match_res.quote_mint, quote_mint)?;
    assert_eq_result!(match_res.quote_amount, recv_amount + total_fees)?;
    assert_eq_result!(match_res.base_amount, send_amount)?;
    assert_eq_result!(match_res.direction, OrderSide::Sell)
}
integration_test_async!(test_basic_external_match__sell_side__send_amount_specified);

/// Tests a basic external match on the buy side with a receive amount specified
#[allow(non_snake_case)]
async fn test_basic_external_match__buy_side__receive_amount_specified(
    ctx: IntegrationTestCtx,
) -> Result<()> {
    let base_amount = ctx.base_token().convert_from_decimal(1.); // 1 WETH
    let external_order = ExternalOrder {
        base_mint: ctx.base_mint(),
        quote_mint: ctx.quote_mint(),
        side: OrderSide::Buy,
        base_amount,
        ..Default::default()
    };

    // Setup a matching order, then request a quote
    ctx.setup_wallet_for_order(&external_order).await?;
    let resp = ctx.request_external_quote(&external_order).await?;
    let quote = resp.signed_quote.quote;

    // Verify the response contents
    let base_mint = ctx.base_token().get_addr();
    let quote_mint = ctx.quote_token().get_addr();
    let send_mint = quote.send.mint;
    let send_amount = quote.send.amount;
    let expected_quote_amt = ctx.expected_quote_amount(base_amount);
    assert_eq_result!(send_mint, quote_mint)?;
    assert_approx_eq(send_amount, expected_quote_amt, DIFF_TOLERANCE)?;

    let recv_mint = quote.receive.mint;
    let recv_amount = quote.receive.amount;
    let total_fees = quote.fees.total();
    assert_eq_result!(recv_mint, base_mint)?;
    assert_eq_result!(recv_amount + total_fees, base_amount)?;

    // Verify the match result
    let match_res = quote.match_result;
    assert_eq_result!(match_res.base_mint, base_mint)?;
    assert_eq_result!(match_res.quote_mint, quote_mint)?;
    assert_eq_result!(match_res.quote_amount, send_amount)?;
    assert_eq_result!(match_res.base_amount, recv_amount + total_fees)?;
    assert_eq_result!(match_res.direction, OrderSide::Buy)
}
integration_test_async!(test_basic_external_match__buy_side__receive_amount_specified);

/// Tests a basic external match on the sell side with a receive amount
/// specified
#[allow(non_snake_case)]
async fn test_basic_external_match__sell_side__receive_amount_specified(
    ctx: IntegrationTestCtx,
) -> Result<()> {
    let quote_amount = ctx.quote_token().convert_from_decimal(1000.);
    let external_order = ExternalOrder {
        base_mint: ctx.base_mint(),
        quote_mint: ctx.quote_mint(),
        side: OrderSide::Sell,
        quote_amount,
        ..Default::default()
    };

    // Setup a matching order, then request a quote
    ctx.setup_wallet_for_order(&external_order).await?;
    let resp = ctx.request_external_quote(&external_order).await?;
    let quote = resp.signed_quote.quote;

    // Verify the response contents
    let base_mint = ctx.base_token().get_addr();
    let quote_mint = ctx.quote_token().get_addr();
    let send_mint = quote.send.mint;
    let send_amount = quote.send.amount;
    let expected_base_amt = ctx.expected_base_amount(quote_amount);
    assert_eq_result!(send_mint, base_mint)?;
    assert_approx_eq(send_amount, expected_base_amt, DIFF_TOLERANCE)?;

    let recv_mint = quote.receive.mint;
    let recv_amount = quote.receive.amount;
    let total_fees = quote.fees.total();
    assert_eq_result!(recv_mint, quote_mint)?;
    assert_eq_result!(recv_amount + total_fees, quote_amount)?;

    // Verify the match result
    let match_res = quote.match_result;
    assert_eq_result!(match_res.base_mint, base_mint)?;
    assert_eq_result!(match_res.quote_mint, quote_mint)?;
    assert_eq_result!(match_res.quote_amount, recv_amount + total_fees)?;
    assert_eq_result!(match_res.base_amount, send_amount)?;
    assert_eq_result!(match_res.direction, OrderSide::Sell)
}
integration_test_async!(test_basic_external_match__sell_side__receive_amount_specified);
