//! Context struct for the integration tests
//!
//! This module's definitions provide helpers for interacting with the mock
//! and setting up tests.

use alloy::primitives::Address;
use circuit_types::{fixed_point::FixedPoint, Amount};
use common::types::{hmac::HmacKey, token::Token, TimestampedPrice};
use config::RelayerConfig;
use constants::Scalar;
use darkpool_client::conversion::address_to_biguint;
use mock_node::MockNodeController;
use num_bigint::BigUint;
use renegade_crypto::fields::scalar_to_u128;
use state::test_helpers::tmp_db_path;

mod external_match;
mod http;
mod node_state;
mod wallet_setup;

/// A dummy RPC url for the integration tests
const DUMMY_RPC_URL: &str = "https://dummy-rpc-url.com";

/// The arguments used for the integration tests
#[derive(Clone)]
pub struct IntegrationTestCtx {
    /// The mock price used for the integration tests
    pub mock_price: f64,
    /// The admin API key for the integration tests
    pub admin_api_key: HmacKey,
    /// The mock node controller
    pub mock_node: MockNodeController,
}

impl IntegrationTestCtx {
    /// Get the relayer config for the integration tests
    pub fn relayer_config(admin_key: HmacKey) -> RelayerConfig {
        // Get two temp dirs for the DB and raft snapshots
        let raft_snapshot_path = tmp_db_path();
        let db_path = tmp_db_path();
        let external_fee_addr = address_to_biguint(&Address::ZERO).unwrap();

        RelayerConfig {
            raft_snapshot_path,
            db_path,
            admin_api_key: Some(admin_key),
            rpc_url: Some(DUMMY_RPC_URL.to_string()),
            // External matches are disabled if this value is unset
            external_fee_addr: Some(external_fee_addr),
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

    /// Get the decimal corrected price for the canonical token pair
    pub fn decimal_corrected_price(&self) -> FixedPoint {
        let price = TimestampedPrice::new(self.mock_price);
        let base_token = self.base_token();
        let quote_token = self.quote_token();
        let decimal_corrected = price
            .get_decimal_corrected_price(&base_token, &quote_token)
            .expect("error decimal correcting price");

        decimal_corrected.as_fixed_point()
    }

    /// Get the expected base amount for the given quote amount
    pub fn expected_base_amount(&self, quote_amount: Amount) -> Amount {
        // quote_amount / price
        let price = self.decimal_corrected_price();
        let quote_scalar = FixedPoint::floor_div_int(quote_amount, price);
        scalar_to_u128(&quote_scalar)
    }

    /// Get the expected quote amount for the given base amount
    pub fn expected_quote_amount(&self, base_amount: Amount) -> Amount {
        // base_amount * price
        let price = self.decimal_corrected_price();
        let base = Scalar::from(base_amount);
        let quote_scalar = (price * base).floor();
        scalar_to_u128(&quote_scalar)
    }
}
