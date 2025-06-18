//! Integration tests for the min fill size parameter

use circuit_types::order::OrderSide;
use external_api::http::external_match::ExternalOrder;
use eyre::Result;
use test_helpers::integration_test_async;

use crate::ctx::IntegrationTestCtx;

/// Test a base denominated min fill size
#[allow(non_snake_case)]
async fn test_min_fill_size__no_quote(mut ctx: IntegrationTestCtx) -> Result<()> {
    // Clear the state
    ctx.clear_state().await?;

    // Create an external order with a min fill size
    let base_amount = ctx.base_token().convert_from_decimal(1.); // 1 WETH
    let external_order = ExternalOrder {
        base_mint: ctx.base_mint(),
        quote_mint: ctx.quote_mint(),
        side: OrderSide::Buy,
        base_amount,
        // min_fill_size: base_amount,
        ..Default::default()
    };

    // Setup a matching order, then request a quote
    let wallet = ctx.setup_wallet_for_order(&external_order).await?;
    let state_wallet =
        ctx.mock_node.state().get_wallet(&wallet.wallet_id).await?.expect("wallet not found");

    let resp = ctx.request_external_quote(&external_order).await?;
    let quote = resp.signed_quote.quote;

    Ok(())
}
integration_test_async!(test_min_fill_size__no_quote);
