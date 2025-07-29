//! Benchmark the quote endpoint
#![allow(missing_docs)]
use std::{
    process,
    time::{Duration, Instant},
};

use api_server_bench_util::{
    base_mint, quote_mint, send_admin_post_req, setup_internal_order, setup_mock_node,
};
use circuit_types::{Amount, order::OrderSide};
use common::types::hmac::HmacKey;
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use external_api::http::external_match::{
    ExternalOrder, ExternalQuoteRequest, ExternalQuoteResponse, REQUEST_EXTERNAL_QUOTE_ROUTE,
};
use eyre::Result;
use mock_node::MockNodeController;
use tokio::runtime::Runtime;

/// The amount to cross
const MATCH_AMOUNT: Amount = 1_000_000;

// --------------
// | Benchmarks |
// --------------

/// Benchmark the quote endpoint
pub fn bench_quote_endpoint(c: &mut Criterion) {
    let rt = Runtime::new().expect("failed to create runtime");
    let (mock_node, admin_key) = rt.block_on(async move { setup_benchmark().await.unwrap() });

    // Benchmark the quote endpoint
    c.bench_function(REQUEST_EXTERNAL_QUOTE_ROUTE, |b| {
        b.iter_custom(|iters| {
            let node_clone = mock_node.clone();
            rt.block_on(run_benchmark_iters(iters, node_clone, admin_key))
        })
    });

    // Dropping the mock node causes the test to hang, just force an exit
    process::exit(0);
}

/// Run the benchmark for the given number of iterations
async fn run_benchmark_iters(
    iters: u64,
    mock_node: MockNodeController,
    admin_key: HmacKey,
) -> Duration {
    let mut total = Duration::from_secs(0);
    for _ in 0..iters {
        let start = Instant::now();
        request_quote(&admin_key, &mock_node).await.unwrap();
        let elapsed = start.elapsed();
        total += elapsed;
    }
    total
}

/// Request a quote from the api server
async fn request_quote(admin_key: &HmacKey, mock_node: &MockNodeController) -> Result<()> {
    let order = api_user_order();
    let path = REQUEST_EXTERNAL_QUOTE_ROUTE;
    let body = ExternalQuoteRequest {
        external_order: order.clone(),
        matching_pool: None,
        relayer_fee_rate: 0.,
    };

    let resp: ExternalQuoteResponse = send_admin_post_req(mock_node, path, body, admin_key).await?;
    black_box(resp);
    Ok(())
}

// -----------
// | Helpers |
// -----------

/// Setup the benchmark
async fn setup_benchmark() -> Result<(MockNodeController, HmacKey)> {
    let (mock_node, cfg) = setup_mock_node().await?;
    setup_internal_order(OrderSide::Sell, &mock_node).await?;
    Ok((mock_node, cfg.admin_api_key.unwrap()))
}

// --- Match Setup --- //

/// Get the API user order
fn api_user_order() -> ExternalOrder {
    ExternalOrder {
        quote_mint: quote_mint(),
        base_mint: base_mint(),
        side: OrderSide::Buy,
        base_amount: MATCH_AMOUNT,
        ..Default::default()
    }
}

// -------------------
// | Criterion Setup |
// -------------------

criterion_group! {
    name = quote_endpoint;
    config = Criterion::default().sample_size(10);
    targets = bench_quote_endpoint
}
criterion_main!(quote_endpoint);
