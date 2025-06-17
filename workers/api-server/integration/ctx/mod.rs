//! Context struct for the integration tests
//!
//! This module's definitions provide helpers for interacting with the mock
//! and setting up tests.

use std::env::temp_dir;

use common::types::{hmac::HmacKey, token::Token};
use config::RelayerConfig;
use eyre::Result;
use mock_node::MockNodeController;
use num_bigint::BigUint;
use reqwest::{header::HeaderMap, Method, Response};
use serde::{de::DeserializeOwned, Serialize};
use state::test_helpers::tmp_db_path;

mod external_match;
mod wallet_setup;

/// The arguments used for the integration tests
#[derive(Clone)]
pub struct IntegrationTestCtx {
    /// The mock node controller
    pub mock_node: MockNodeController,
    /// The admin API key for the integration tests
    pub admin_api_key: HmacKey,
}

impl IntegrationTestCtx {
    /// Get the relayer config for the integration tests
    pub fn relayer_config(admin_key: HmacKey) -> RelayerConfig {
        let raft_snapshot_path = temp_dir().to_str().unwrap().to_string();
        let db_path = tmp_db_path();

        RelayerConfig {
            raft_snapshot_path,
            db_path,
            admin_api_key: Some(admin_key),
            ..Default::default()
        }
    }

    /// Get the base token used for testing
    pub fn base_token(&self) -> Token {
        Token::from_ticker("WETH")
    }

    /// Get the quote token used for testing
    pub fn quote_token(&self) -> Token {
        Token::from_ticker("USDC")
    }

    /// Get the base mint used for testing
    pub fn base_mint(&self) -> BigUint {
        self.base_token().get_addr_biguint()
    }

    /// Get the quote mint used for testing
    pub fn quote_mint(&self) -> BigUint {
        Token::from_ticker("USDC").get_addr_biguint()
    }

    // --- HTTP Helpers --- //

    /// Send an http request to the mock API server
    pub async fn send_req<Req: Serialize, Resp: DeserializeOwned>(
        &self,
        route: &str,
        method: Method,
        body: Req,
    ) -> Result<Resp> {
        self.send_req_with_headers(route, method, HeaderMap::default(), body).await
    }

    /// Send an http request to the mock API server
    pub async fn send_req_with_headers<Req: Serialize, Resp: DeserializeOwned>(
        &self,
        route: &str,
        method: Method,
        headers: HeaderMap,
        body: Req,
    ) -> Result<Resp> {
        self.mock_node.send_api_req(route, method, headers, body).await
    }

    /// Send an http request to the mock API server and return the raw response
    pub async fn send_req_raw<Req: Serialize>(
        &self,
        route: &str,
        method: Method,
        headers: HeaderMap,
        body: Req,
    ) -> Result<Response> {
        self.mock_node.send_api_req_raw(route, method, headers, body).await
    }
}
