use std::{
    process,
    sync::Arc,
    time::{Duration, Instant},
};

use alloy::primitives::Address;
use circuit_types::{Amount, balance::Balance, fixed_point::FixedPoint, order::OrderSide};
use common::types::{
    chain::Chain,
    hmac::HmacKey,
    proof_bundles::mocks::{dummy_validity_proof_bundle, dummy_validity_witness_bundle},
    token::Token,
    wallet::{Order, OrderIdentifier},
    wallet_mocks::mock_empty_wallet,
};
use config::{RelayerConfig, setup_token_remaps};
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use darkpool_client::conversion::address_to_biguint;
use external_api::{
    auth::add_expiring_auth_to_headers,
    http::external_match::{
        ExternalOrder, ExternalQuoteRequest, ExternalQuoteResponse, REQUEST_EXTERNAL_QUOTE_ROUTE,
    },
};
use eyre::Result;
use hyper::{Method, header::HeaderMap};
use mock_node::MockNodeController;
use num_bigint::BigUint;
use state::test_helpers::tmp_db_path;
use tokio::runtime::Runtime;
use util::on_chain::PROTOCOL_FEE;

/// The amount to cross
const MATCH_AMOUNT: Amount = 1_000_000;
/// The duration of the request auth token
const REQUEST_AUTH_DURATION: Duration = Duration::from_secs(10);

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

/// Setup the benchmark
///
/// Returns the mock node and the admin key
async fn setup_benchmark() -> Result<(MockNodeController, HmacKey)> {
    let (cfg, mock_node) = tokio::task::spawn_blocking(setup_mock_node).await.unwrap();
    let admin_key = cfg.admin_api_key.unwrap();
    setup_state(&mock_node).await?;

    setup_matching_order(&mock_node).await.unwrap();
    Ok((mock_node, admin_key))
}

/// Request a quote from the api server
async fn request_quote(admin_key: &HmacKey, mock_node: &MockNodeController) -> Result<()> {
    let order = api_user_order();
    let path = REQUEST_EXTERNAL_QUOTE_ROUTE;
    let mut headers = HeaderMap::new();
    let body = ExternalQuoteRequest {
        external_order: order.clone(),
        matching_pool: None,
        relayer_fee_rate: 0.,
    };
    let body_bytes = serde_json::to_vec(&body).expect("failed to serialize request");

    add_expiring_auth_to_headers(path, &mut headers, &body_bytes, admin_key, REQUEST_AUTH_DURATION);
    let resp: ExternalQuoteResponse =
        mock_node.send_api_req(path, Method::POST, headers, body).await?;
    black_box(resp);
    Ok(())
}

// -----------
// | Helpers |
// -----------

// --- Mock Node Config --- //

/// Setup a mock node for the benchmarks
fn setup_mock_node() -> (RelayerConfig, MockNodeController) {
    // Set the protocol fee and token remaps
    PROTOCOL_FEE.set(FixedPoint::from_f64_round_down(0.0001)).expect("failed to set protocol fee");
    setup_token_remaps(None /* remap_file */, Chain::ArbitrumSepolia).unwrap();

    // Build the mock node
    let cfg = build_relayer_config();
    let mock_node = MockNodeController::new(cfg.clone())
        .with_darkpool_client()
        .with_state()
        .with_handshake_manager()
        .with_mock_price_reporter(0.0001 /* price */)
        .with_task_driver()
        .with_mock_proof_generation(true /* skip_constraints */)
        .with_api_server();

    (cfg, mock_node)
}

/// Setup the state for the mock node
async fn setup_state(mock_node: &MockNodeController) -> Result<()> {
    let state = mock_node.state();
    let this_peer = state.get_peer_id().await?;
    state.initialize_raft(vec![this_peer] /* this_peer */).await?;
    Ok(())
}

/// Build a relayer config for the benchmarks
fn build_relayer_config() -> RelayerConfig {
    let raft_snapshot_path = tmp_db_path();
    let db_path = tmp_db_path();
    let external_fee_addr = address_to_biguint(&Address::ZERO).unwrap();
    let admin_api_key = HmacKey::random();
    let rpc_url = "https://dummy-rpc-url.com".to_string();
    RelayerConfig {
        admin_api_key: Some(admin_api_key),
        raft_snapshot_path,
        db_path,
        external_fee_addr: Some(external_fee_addr),
        rpc_url: Some(rpc_url),
        ..Default::default()
    }
}

// --- Match Setup --- //

/// Get the base mint for the benchmarks
fn base_mint() -> BigUint {
    Token::from_ticker("WETH").get_addr_biguint()
}

/// Get the quote mint for the benchmarks
fn quote_mint() -> BigUint {
    Token::from_ticker("USDC").get_addr_biguint()
}

/// Setup a matching order
async fn setup_matching_order(mock_node: &MockNodeController) -> Result<()> {
    // Setup an internal party wallet
    let oid = OrderIdentifier::new_v4();
    let order = internal_party_order();
    let bal = internal_party_balance();
    let mut wallet = mock_empty_wallet();
    wallet.add_balance(bal).unwrap();
    wallet.add_order(oid, order.clone()).unwrap();

    // Add the wallet to the state
    let waiter = mock_node.state().update_wallet(wallet).await?;
    waiter.await?;

    // Add a validity proof bundle to the state for the order
    add_validity_proof_bundle(mock_node, oid, order).await?;
    Ok(())
}

/// Add a validity proof bundle to the state for the given order
async fn add_validity_proof_bundle(
    mock_node: &MockNodeController,
    oid: OrderIdentifier,
    order: Order,
) -> Result<()> {
    let bundle = dummy_validity_proof_bundle();
    let mut witness = dummy_validity_witness_bundle();
    Arc::make_mut(&mut witness.commitment_witness).order = order.into();
    let waiter = mock_node.state().add_local_order_validity_bundle(oid, bundle, witness).await?;
    waiter.await?;

    Ok(())
}

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

/// The internal party's order
fn internal_party_order() -> Order {
    Order {
        quote_mint: quote_mint(),
        base_mint: base_mint(),
        side: OrderSide::Sell,
        amount: MATCH_AMOUNT,
        worst_case_price: FixedPoint::zero(),
        min_fill_size: 0,
        allow_external_matches: true,
    }
}

/// The internal party's balance
fn internal_party_balance() -> Balance {
    Balance::new_from_mint_and_amount(base_mint(), MATCH_AMOUNT)
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
