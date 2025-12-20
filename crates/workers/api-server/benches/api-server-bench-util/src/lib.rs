//! Utilities for benchmarking the API server

use std::{sync::Arc, time::Duration};

use alloy::primitives::Address;
use circuit_types::{
    Amount, balance::Balance, fixed_point::FixedPoint, max_amount, order::OrderSide,
};
use common::types::{
    chain::Chain,
    hmac::HmacKey,
    proof_bundles::mocks::{dummy_validity_proof_bundle, dummy_validity_witness_bundle},
    token::Token,
    wallet::{Order, OrderIdentifier},
    wallet_mocks::mock_empty_wallet,
};
use config::{RelayerConfig, setup_token_remaps};
use darkpool_client::conversion::address_to_biguint;
use external_api::auth::add_expiring_auth_to_headers;
use eyre::Result;
use mock_node::MockNodeController;
use num_bigint::BigUint;
use reqwest::{Method, header::HeaderMap};
use serde::{Serialize, de::DeserializeOwned};
use state::test_helpers::tmp_db_path;
use util::on_chain::set_protocol_fee;

/// The duration of the request auth token
const REQUEST_AUTH_DURATION: Duration = Duration::from_secs(10);
/// The amount to allocate into a balance
const BALANCE_AMOUNT: Amount = 1_000_000_000_000_000_000; // 10^18
/// The ticker for the base token
const BASE_TICKER: &str = "WETH";
/// The ticker for the quote token
const QUOTE_TICKER: &str = "USDC";

// ---------------------
// | Orderbook Helpers |
// ---------------------

/// Get the base mint for the benchmarks
pub fn base_mint() -> BigUint {
    Token::from_ticker(BASE_TICKER).get_addr_biguint()
}

/// Get the base token for the benchmarks
pub fn base_token() -> Token {
    Token::from_ticker(BASE_TICKER)
}

/// Get the quote mint for the benchmarks
pub fn quote_mint() -> BigUint {
    Token::from_ticker(QUOTE_TICKER).get_addr_biguint()
}

/// Setup a wallet with a balance and order on the default base token
pub async fn setup_internal_order(side: OrderSide, mock_node: &MockNodeController) -> Result<()> {
    setup_internal_order_on_token(base_token(), side, mock_node).await
}

/// Setup a wallet with a balance and an order on the given side of the book
pub async fn setup_internal_order_on_token(
    base: Token,
    side: OrderSide,
    mock_node: &MockNodeController,
) -> Result<()> {
    // Setup an internal party wallet
    let oid = OrderIdentifier::new_v4();
    let order = internal_party_order(&base, side);
    let bal = internal_party_balance(&base, side);
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

/// The internal party's order
fn internal_party_order(base: &Token, side: OrderSide) -> Order {
    Order {
        quote_mint: quote_mint(),
        base_mint: base.get_addr_biguint(),
        side,
        amount: max_amount(),
        worst_case_price: FixedPoint::zero(),
        min_fill_size: 0,
        allow_external_matches: true,
        precompute_cancellation_proof: false,
    }
}

/// The internal party's balance
fn internal_party_balance(base: &Token, side: OrderSide) -> Balance {
    let mint = match side {
        OrderSide::Buy => quote_mint(),
        OrderSide::Sell => base.get_addr_biguint(),
    };

    Balance::new_from_mint_and_amount(mint, BALANCE_AMOUNT)
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

// ----------------
// | HTTP Helpers |
// ----------------

/// Send an admin GET request and deserialize the response into the given type
pub async fn send_admin_get_req<Res: DeserializeOwned>(
    mock_node: &MockNodeController,
    path: &str,
    admin_key: &HmacKey,
) -> Result<Res> {
    let mut headers = HeaderMap::new();
    add_expiring_auth_to_headers(
        path,
        &mut headers,
        &[], // body
        admin_key,
        REQUEST_AUTH_DURATION,
    );

    let resp: Res = mock_node.send_api_req(path, Method::GET, headers, ()).await?;
    Ok(resp)
}

/// Send an admin API request and deserialize the response into the given type
pub async fn send_admin_post_req<Req: Serialize, Res: DeserializeOwned>(
    mock_node: &MockNodeController,
    path: &str,
    body: Req,
    admin_key: &HmacKey,
) -> Result<Res> {
    let mut headers = HeaderMap::new();
    let body_bytes = serde_json::to_vec(&body)?;
    add_expiring_auth_to_headers(path, &mut headers, &body_bytes, admin_key, REQUEST_AUTH_DURATION);

    let resp: Res = mock_node.send_api_req(path, Method::POST, headers, body).await?;
    Ok(resp)
}

// -------------------
// | Mock Node Setup |
// -------------------

/// Setup the benchmark
///
/// Returns the mock node and the admin key
pub async fn setup_mock_node() -> Result<(MockNodeController, RelayerConfig)> {
    let (cfg, mock_node) = tokio::task::spawn_blocking(setup_node_controller).await.unwrap();
    setup_state(&mock_node).await?;

    Ok((mock_node, cfg))
}

/// Setup a mock node for the benchmarks
fn setup_node_controller() -> (RelayerConfig, MockNodeController) {
    // Set the protocol fee and token remaps
    let fee = FixedPoint::from_f64_round_down(0.0001);
    set_protocol_fee(fee);
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
    let this_peer = state.get_peer_id()?;
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
