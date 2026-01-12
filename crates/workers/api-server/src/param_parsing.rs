//! Helpers for parsing parameters from URL and query params

// ----------------
// | URL Captures |
// ----------------

use alloy::primitives::Address;
use circuit_types::Amount;
use num_bigint::BigUint;
use num_traits::Num;
use types_account::MatchingPoolName;
use types_core::{AccountId, Token};
use types_gossip::{ClusterId, WrappedPeerId};
use types_tasks::TaskIdentifier;
use util::hex::address_from_hex_string;
use uuid::Uuid;

use crate::{
    error::{ApiServerError, bad_request, not_found},
    router::{QueryParams, UrlParams},
};

// ------------------
// | Error Messages |
// ------------------

/// Error message displayed when a mint cannot be parsed from URL
const ERR_MINT_PARSE: &str = "could not parse mint";
/// Error message displayed when a given order ID is not parsable
const ERR_ORDER_ID_PARSE: &str = "could not parse order id";
/// Error message displayed when a given wallet ID is not parsable
const ERR_WALLET_ID_PARSE: &str = "could not parse wallet id";
/// Error message displayed when a given cluster ID is not parsable
const ERR_CLUSTER_ID_PARSE: &str = "could not parse cluster id";
/// Error message displayed when a given peer ID is not parsable
const ERR_PEER_ID_PARSE: &str = "could not parse peer id";
/// Error message displayed when parsing a task ID from URL fails
const ERR_TASK_ID_PARSE: &str = "could not parse task id";
/// Error message displayed when parsing a matching pool name from URL fails
const ERR_MATCHING_POOL_PARSE: &str = "could not parse matching pool name";
/// Error message displayed when an invalid token is parsed from a URL param
const ERR_INVALID_TOKEN_PARSE: &str = "invalid token";
/// Error message displayed when parsing a list of tickers from a query string
const ERR_TICKERS_PARSE: &str = "could not parse tickers";

// ----------------
// | URL Captures |
// ----------------

/// The :mint param in a URL
const MINT_URL_PARAM: &str = "mint";
/// The :wallet_id param in a URL
pub(super) const ACCOUNT_ID_URL_PARAM: &str = "account_id";
/// The :order_id param in a URL
const ORDER_ID_URL_PARAM: &str = "order_id";
/// The :cluster_id param in a URL
const CLUSTER_ID_URL_PARAM: &str = "cluster_id";
/// The :peer_id param in a URL
const PEER_ID_URL_PARAM: &str = "peer_id";
/// The :task_id param in a URL
const TASK_ID_URL_PARAM: &str = "task_id";
/// The :matching_pool param in a URL / query string
const MATCHING_POOL_PARAM: &str = "matching_pool";
/// The tickers param in a query string
const TICKERS_PARAM: &str = "tickers";

// -----------
// | Parsing |
// -----------

// --- Primitive Type Parsing --- //

/// Parse an address from a hex string
pub(crate) fn parse_address_from_hex_string(hex: &str) -> Result<Address, ApiServerError> {
    address_from_hex_string(hex).map_err(|e| bad_request(format!("invalid address: {e}")))
}

/// Parse an amount from a string
pub(crate) fn parse_amount_from_string(amount: &str) -> Result<Amount, ApiServerError> {
    amount.parse().map_err(|e| bad_request(format!("invalid amount: {e}")))
}

// --- Url Params --- //

/// A helper to parse out a mint from a URL param
pub(super) fn parse_mint_from_params(params: &UrlParams) -> Result<Address, ApiServerError> {
    // Try to parse as a hex string, then fall back to decimal
    let mint_str = params.get(MINT_URL_PARAM).ok_or_else(|| not_found(ERR_MINT_PARSE))?;
    address_from_hex_string(mint_str).map_err(|e| bad_request(format!("invalid mint: {e}")))
}

/// A helper to parse a token (":mint") from a URL param
pub(super) fn parse_token_from_params(params: &UrlParams) -> Result<Token, ApiServerError> {
    let mint_str = params.get(MINT_URL_PARAM).ok_or_else(|| not_found(ERR_MINT_PARSE))?;
    let token = Token::from_addr(mint_str);
    if !token.is_named() {
        return Err(bad_request(ERR_INVALID_TOKEN_PARSE));
    }

    Ok(token)
}

/// A helper to parse out a wallet ID from a URL param
pub(super) fn parse_account_id_from_params(
    params: &UrlParams,
) -> Result<AccountId, ApiServerError> {
    params
        .get(ACCOUNT_ID_URL_PARAM)
        .ok_or_else(|| bad_request(ERR_WALLET_ID_PARSE))?
        .parse()
        .map_err(|_| bad_request(ERR_WALLET_ID_PARSE))
}

/// A helper to parse out an order ID from a URL param
pub(super) fn parse_order_id_from_params(params: &UrlParams) -> Result<Uuid, ApiServerError> {
    params
        .get(ORDER_ID_URL_PARAM)
        .ok_or_else(|| bad_request(ERR_ORDER_ID_PARSE))?
        .parse()
        .map_err(|_| bad_request(ERR_ORDER_ID_PARSE))
}

/// A helper to parse out a cluster ID from a URL param
pub(super) fn parse_cluster_id_from_params(
    params: &UrlParams,
) -> Result<ClusterId, ApiServerError> {
    params
        .get(CLUSTER_ID_URL_PARAM)
        .ok_or_else(|| bad_request(ERR_CLUSTER_ID_PARSE))?
        .parse()
        .map_err(|_| bad_request(ERR_CLUSTER_ID_PARSE))
}

/// A helper to parse out a peer ID from a URL param
pub(super) fn parse_peer_id_from_params(
    params: &UrlParams,
) -> Result<WrappedPeerId, ApiServerError> {
    params
        .get(PEER_ID_URL_PARAM)
        .ok_or_else(|| bad_request(ERR_PEER_ID_PARSE))?
        .parse()
        .map_err(|_| bad_request(ERR_PEER_ID_PARSE))
}

/// A helper to parse out a task ID from a URL param
pub(super) fn parse_task_id_from_params(
    params: &UrlParams,
) -> Result<TaskIdentifier, ApiServerError> {
    params
        .get(TASK_ID_URL_PARAM)
        .ok_or_else(|| bad_request(ERR_TASK_ID_PARSE))?
        .parse()
        .map_err(|_| bad_request(ERR_TASK_ID_PARSE))
}

/// A helper to parse out a matching pool name from a URL param
pub(super) fn parse_matching_pool_from_url_params(
    params: &UrlParams,
) -> Result<MatchingPoolName, ApiServerError> {
    params.get(MATCHING_POOL_PARAM).ok_or_else(|| bad_request(ERR_MATCHING_POOL_PARSE)).cloned()
}

// --- Query Params --- //

/// A helper to parse out a matching pool name from a query string
pub(super) fn parse_matching_pool_from_query_params(
    params: &QueryParams,
) -> Option<MatchingPoolName> {
    params.get(MATCHING_POOL_PARAM).cloned()
}

/// A helper to parse a list of tickers form the query params
pub(super) fn parse_tickers_from_query_params(
    params: &QueryParams,
) -> Result<Vec<String>, ApiServerError> {
    let tickers_param = params.get(TICKERS_PARAM).ok_or_else(|| bad_request(ERR_TICKERS_PARSE))?;
    let tickers = tickers_param.split(',').map(|t| t.to_string()).collect();
    Ok(tickers)
}
