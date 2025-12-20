//! Integration tests setting relayer fee rates

use circuit_types::order::OrderSide;
use external_api::http::external_match::ExternalOrder;
use eyre::Result;
use rand::{Rng, thread_rng};
use test_helpers::{assert_eq_result, assert_true_result, integration_test_async};

use crate::{ctx::IntegrationTestCtx, helpers::assert_approx_eq};

/// The tolerance in which to assert relayer fee equality
const RELAYER_FEE_TOLERANCE: f64 = 0.000001;

/// Test requesting an external match with a non-zero relayer fee rate
#[allow(non_snake_case)]
async fn test_relayer_fee_rate__non_zero(mut ctx: IntegrationTestCtx) -> Result<()> {
    // Clear the state
    ctx.clear_state().await?;

    let mut rng = thread_rng();
    let relayer_fee_rate: f64 = rng.gen_range(0.0..0.01);

    // Create an external order
    let external_order = ExternalOrder {
        base_mint: ctx.base_mint(),
        quote_mint: ctx.quote_mint(),
        side: OrderSide::Buy,
        quote_amount: ctx.quote_token().convert_from_decimal(1000.),
        ..Default::default()
    };

    // Setup a matching order
    ctx.setup_crossing_wallet(&external_order).await?;

    // Request an external quote
    let resp =
        ctx.request_external_quote_with_relayer_fee(&external_order, relayer_fee_rate).await?;
    let quote_receive_amt = resp.signed_quote.receive_amount().amount;
    let buy_amount = resp.signed_quote.match_result().base_amount;

    // Compute expected fees and verify the fee take
    let fee_take = resp.signed_quote.fees();
    let relayer_fee = fee_take.relayer_fee;
    let total_fee = fee_take.total();
    let expected_relayer_fee = (buy_amount as f64 * relayer_fee_rate).floor() as u128;
    assert_approx_eq(relayer_fee, expected_relayer_fee, RELAYER_FEE_TOLERANCE)?;
    assert_approx_eq(buy_amount - quote_receive_amt, total_fee, RELAYER_FEE_TOLERANCE)?;

    // Assemble the quote into an external match, the fee should be reflected
    let assemble_resp =
        ctx.request_assemble_quote_with_relayer_fee(&resp.signed_quote, relayer_fee_rate).await?;
    let bundle = assemble_resp.match_bundle;
    let fees = bundle.fees;
    let expected_relayer_fee = (buy_amount as f64 * relayer_fee_rate).floor() as u128;
    assert_approx_eq(fees.relayer_fee, expected_relayer_fee, RELAYER_FEE_TOLERANCE)?;
    assert_eq_result!(bundle.receive.amount, quote_receive_amt)
}
integration_test_async!(test_relayer_fee_rate__non_zero);

/// Test requesting an external match with a relayer fee rate that is too high
#[allow(non_snake_case)]
async fn test_relayer_fee_rate__too_high(mut ctx: IntegrationTestCtx) -> Result<()> {
    // Clear the state
    ctx.clear_state().await?;
    let relayer_fee_rate = 0.011; // 1.1%

    // Build an order
    let external_order = ExternalOrder {
        base_mint: ctx.base_mint(),
        quote_mint: ctx.quote_mint(),
        side: OrderSide::Buy,
        quote_amount: ctx.quote_token().convert_from_decimal(1000.),
        ..Default::default()
    };

    // Request an external quote
    let resp = ctx.request_external_quote_with_relayer_fee(&external_order, relayer_fee_rate).await;
    assert_true_result!(resp.is_err())?;
    let err = resp.err().unwrap().to_string();
    assert_true_result!(err.contains("relayer fee rate must be between 0 and 1%"))
}
integration_test_async!(test_relayer_fee_rate__too_high);
