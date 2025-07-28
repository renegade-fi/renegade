use std::{process, time::Duration};

use api_server_bench_util::setup_mock_node;
use circuit_types::Amount;
use config::RelayerConfig;
use criterion::{Criterion, criterion_group, criterion_main};
use eyre::Result;
use mock_node::MockNodeController;
use tokio::runtime::Runtime;

/// The amount to cross
const MATCH_AMOUNT: Amount = 1_000_000;

// --------------
// | Benchmarks |
// --------------

/// Benchmark the book depth endpoint
pub fn bench_book_depth(c: &mut Criterion) {
    let rt = Runtime::new().expect("failed to create runtime");
    let (mock_node, admin_key) = rt.block_on(async move { setup_benchmark().await.unwrap() });

    // Benchmark the quote endpoint
    c.bench_function(REQUEST_EXTERNAL_QUOTE_ROUTE, |b| {
        b.iter_custom(|iters| {
            let node_clone = mock_node.clone();
            // rt.block_on(run_benchmark_iters(iters, node_clone, admin_key))
        })
    });

    // Dropping the mock node causes the test to hang, just force an exit
    process::exit(0);
}

async fn setup_benchmark() -> Result<(MockNodeController, RelayerConfig)> {
    let (mock_node, cfg) = setup_mock_node().await?;
    Ok((mock_node, cfg))
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
