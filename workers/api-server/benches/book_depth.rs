//! Benchmark the book depth endpoint
#![allow(missing_docs)]
use std::{
    process,
    time::{Duration, Instant},
};

use api_server_bench_util::{send_admin_get_req, setup_internal_order_on_token, setup_mock_node};
use circuit_types::order::OrderSide;
use common::types::{hmac::HmacKey, token::get_all_tokens};
use config::RelayerConfig;
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use external_api::http::order_book::{GET_DEPTH_FOR_ALL_PAIRS_ROUTE, GetDepthForAllPairsResponse};
use eyre::Result;
use mock_node::MockNodeController;
use tokio::runtime::Runtime;

// --------------
// | Benchmarks |
// --------------

/// Benchmark the book depth endpoint
pub fn bench_book_depth(c: &mut Criterion) {
    let rt = Runtime::new().expect("failed to create runtime");
    let (mock_node, cfg) = rt.block_on(async move { setup_benchmark().await.unwrap() });

    // Benchmark the quote endpoint
    c.bench_function(GET_DEPTH_FOR_ALL_PAIRS_ROUTE, |b| {
        b.iter_custom(|iters| {
            let node_clone = mock_node.clone();
            rt.block_on(run_benchmark_iters(iters, node_clone, cfg.admin_api_key.unwrap()))
        })
    });

    // Dropping the mock node causes the test to hang, just force an exit
    process::exit(0);
}

/// Setup the benchmark
async fn setup_benchmark() -> Result<(MockNodeController, RelayerConfig)> {
    let (mock_node, cfg) = setup_mock_node().await?;
    fill_book(&mock_node).await?;

    Ok((mock_node, cfg))
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
        request_depth(&admin_key, &mock_node).await.unwrap();
        let elapsed = start.elapsed();
        total += elapsed;
    }
    total
}

// -----------
// | Helpers |
// -----------

/// Add orders on both sides of the book for all pairs
async fn fill_book(mock_node: &MockNodeController) -> Result<()> {
    let all_tokens = get_all_tokens();
    for token in all_tokens {
        // Create a buy order and a sell order in the book
        setup_internal_order_on_token(token.clone(), OrderSide::Buy, mock_node).await?;
        setup_internal_order_on_token(token, OrderSide::Sell, mock_node).await?;
    }

    Ok(())
}

/// Request the "all pairs" depth endpoint
async fn request_depth(admin_key: &HmacKey, mock_node: &MockNodeController) -> Result<()> {
    let path = GET_DEPTH_FOR_ALL_PAIRS_ROUTE;
    let resp: GetDepthForAllPairsResponse = send_admin_get_req(mock_node, path, admin_key).await?;
    black_box(resp);
    Ok(())
}

// -------------------
// | Criterion Setup |
// -------------------

criterion_group! {
    name = book_depth;
    config = Criterion::default().sample_size(10);
    targets = bench_book_depth
}
criterion_main!(book_depth);
