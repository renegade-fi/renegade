//! Route handlers for the admin API

// ------------------------
// | Admin Route Handlers |
// ------------------------

use std::iter;

use async_trait::async_trait;
use circuit_types::{Amount, fixed_point::FixedPoint};
use common::types::{
    chain::Chain,
    price::Price,
    tasks::UpdateWalletTaskDescriptor,
    token::{Token, get_all_tokens},
    wallet::{Order, WalletIdentifier, order_metadata::OrderMetadata},
};
use config::setup_token_remaps;
use constants::NATIVE_ASSET_ADDRESS;
use darkpool_client::DarkpoolClient;
use external_api::{
    EmptyRequestResponse,
    http::{
        admin::{
            AdminGetOrderMatchingPoolResponse, AdminOrderMetadataResponse,
            AdminWalletMatchableOrderIdsResponse, CreateOrderInMatchingPoolRequest,
            IsLeaderResponse, OpenOrdersResponse,
        },
        wallet::CreateOrderResponse,
    },
    types::AdminOrderMetadata,
};
use hyper::HeaderMap;
use job_types::{
    handshake_manager::{HandshakeManagerJob, HandshakeManagerQueue},
    price_reporter::PriceReporterQueue,
};
use state::State;
use tracing::info;
use util::{matching_engine::compute_max_amount, on_chain::set_external_match_fee};

use crate::{
    error::{ApiServerError, bad_request, internal_error, not_found},
    router::{ERR_WALLET_NOT_FOUND, QueryParams, TypedHandler, UrlParams},
};

use super::{
    parse_matching_pool_from_query_params, parse_matching_pool_from_url_params,
    parse_order_id_from_params, parse_wallet_id_from_params,
    wallet::{
        ERR_ORDER_NOT_FOUND, append_task_and_await, find_wallet_for_update, maybe_rotate_root_key,
    },
};

// -------------
// | Constants |
// -------------

/// Query parameter indicating whether or not to calculate fillable values for
/// open orders
const INCLUDE_FILLABLE_PARAM: &str = "include_fillable";

/// The matching pool already exists
const ERR_MATCHING_POOL_EXISTS: &str = "matching pool already exists";
/// The matching pool for the order does not exist
const ERR_NO_MATCHING_POOL: &str = "matching pool does not exist";
/// The order already exists
const ERR_ORDER_ALREADY_EXISTS: &str = "order id already exists";
/// The balance for an order does not exist in its wallet
const ERR_BALANCE_NOT_FOUND: &str = "balance not found in wallet";
/// Error message emitted when price data cannot be found for a token pair
const ERR_NO_PRICE_DATA: &str = "no price data found for token pair";

// -----------------------
// | Raft Route Handlers |
// -----------------------

/// Handler for the GET /v0/admin/is-leader route
pub struct IsLeaderHandler {
    /// A handle to the relayer state
    state: State,
}

impl IsLeaderHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[async_trait]
impl TypedHandler for IsLeaderHandler {
    type Request = EmptyRequestResponse;
    type Response = IsLeaderResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        _params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let leader = self.state.is_leader();
        Ok(IsLeaderResponse { leader })
    }
}

/// Handler for the POST /v0/admin/trigger-snapshot route
pub struct AdminTriggerSnapshotHandler {
    /// A handle to the relayer state
    state: State,
}

impl AdminTriggerSnapshotHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[async_trait]
impl TypedHandler for AdminTriggerSnapshotHandler {
    type Request = EmptyRequestResponse;
    type Response = EmptyRequestResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        _params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        self.state.trigger_snapshot().await?;
        Ok(EmptyRequestResponse {})
    }
}

// ------------------
// | Order Handlers |
// ------------------

/// Handler for the GET /v0/admin/open-orders route
pub struct AdminOpenOrdersHandler {
    /// A handle to the relayer state
    state: State,
}

impl AdminOpenOrdersHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[async_trait]
impl TypedHandler for AdminOpenOrdersHandler {
    type Request = EmptyRequestResponse;
    type Response = OpenOrdersResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        _params: UrlParams,
        query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let order_ids =
            if let Some(matching_pool) = parse_matching_pool_from_query_params(&query_params) {
                // Check that the matching pool exists
                if !self.state.matching_pool_exists(matching_pool.clone()).await? {
                    return Err(not_found(ERR_NO_MATCHING_POOL));
                }

                self.state.get_all_orders_in_matching_pool(matching_pool).await?
            } else {
                self.state.get_all_matchable_orders().await?
            };

        Ok(OpenOrdersResponse { orders: order_ids })
    }
}

/// Handler for the GET /v0/admin/orders/:id/metadata route
pub struct AdminOrderMetadataHandler {
    /// A handle to the relayer state
    state: State,
    /// A handle to the price reporter's job queue
    price_reporter_job_queue: PriceReporterQueue,
}

impl AdminOrderMetadataHandler {
    /// Constructor
    pub fn new(state: State, price_reporter_job_queue: PriceReporterQueue) -> Self {
        Self { state, price_reporter_job_queue }
    }
}

#[async_trait]
impl TypedHandler for AdminOrderMetadataHandler {
    type Request = EmptyRequestResponse;
    type Response = AdminOrderMetadataResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
        query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let order_id = parse_order_id_from_params(&params)?;
        let order_metadata = self
            .state
            .get_order_metadata(&order_id)
            .await?
            .ok_or(not_found(ERR_ORDER_NOT_FOUND))?;

        let wallet_id = self
            .state
            .get_wallet_id_for_order(&order_id)
            .await?
            .ok_or(not_found(ERR_WALLET_NOT_FOUND))?;

        let mut order = AdminOrderMetadata {
            order: order_metadata.clone(),
            wallet_id,
            fillable: None,
            price: None,
        };

        let include_fillable = parse_include_fillable_from_query_params(&query_params)?;
        if include_fillable {
            let (fillable, price) = get_fillable_amount_and_price(
                &order_metadata,
                &wallet_id,
                &self.state,
                &self.price_reporter_job_queue,
            )
            .await?;

            order.fillable = Some(fillable);
            order.price = Some(price);
        }

        Ok(AdminOrderMetadataResponse { order })
    }
}

// -------------------
// | Wallet Handlers |
// -------------------

/// Handler for the GET /v0/admin/wallet/:id/matchable-order-ids route
pub struct AdminWalletMatchableOrderIdsHandler {
    /// A handle to the relayer state
    state: State,
}

impl AdminWalletMatchableOrderIdsHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[async_trait]
impl TypedHandler for AdminWalletMatchableOrderIdsHandler {
    type Request = EmptyRequestResponse;
    type Response = AdminWalletMatchableOrderIdsResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let wallet_id = parse_wallet_id_from_params(&params)?;
        let wallet =
            self.state.get_wallet(&wallet_id).await?.ok_or(not_found(ERR_WALLET_NOT_FOUND))?;

        let order_ids = wallet.get_matchable_orders().into_iter().map(|(id, _order)| id).collect();

        Ok(AdminWalletMatchableOrderIdsResponse { order_ids })
    }
}

// --------------------------
// | Matching Pool Handlers |
// --------------------------

/// Handler for the POST /v0/admin/matching_pools/:matching_pool route
pub struct AdminCreateMatchingPoolHandler {
    /// A handle to the relayer state
    state: State,
}

impl AdminCreateMatchingPoolHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[async_trait]
impl TypedHandler for AdminCreateMatchingPoolHandler {
    type Request = EmptyRequestResponse;
    type Response = EmptyRequestResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let matching_pool = parse_matching_pool_from_url_params(&params)?;

        // Check that the matching pool does not already exist
        if self.state.matching_pool_exists(matching_pool.clone()).await? {
            return Err(bad_request(ERR_MATCHING_POOL_EXISTS));
        }

        let waiter = self.state.create_matching_pool(matching_pool).await?;

        waiter.await?;
        Ok(EmptyRequestResponse {})
    }
}

/// Handler for the POST /v0/admin/matching_pools/:matching_pool/destroy route
pub struct AdminDestroyMatchingPoolHandler {
    /// A handle to the relayer state
    state: State,
}

impl AdminDestroyMatchingPoolHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[async_trait]
impl TypedHandler for AdminDestroyMatchingPoolHandler {
    type Request = EmptyRequestResponse;
    type Response = EmptyRequestResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let matching_pool = parse_matching_pool_from_url_params(&params)?;

        let waiter = self.state.destroy_matching_pool(matching_pool).await?;

        waiter.await?;
        Ok(EmptyRequestResponse {})
    }
}

/// Handler for the POST /v0/admin/wallet/:id/order-in-pool route
pub struct AdminCreateOrderInMatchingPoolHandler {
    /// A handle to the relayer state
    state: State,
}

impl AdminCreateOrderInMatchingPoolHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[async_trait]
impl TypedHandler for AdminCreateOrderInMatchingPoolHandler {
    type Request = CreateOrderInMatchingPoolRequest;
    type Response = CreateOrderResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        req: Self::Request,
        params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let wallet_id = parse_wallet_id_from_params(&params)?;
        let matching_pool = req.matching_pool;

        // Check that the matching pool exists
        if !self.state.matching_pool_exists(matching_pool.clone()).await? {
            return Err(not_found(ERR_NO_MATCHING_POOL));
        }

        // Check that an order with the given ID does not exist
        let oid = req.order.id;
        if self.state.contains_order(&oid).await? {
            return Err(bad_request(ERR_ORDER_ALREADY_EXISTS));
        }

        // Lookup the wallet in the global state
        let old_wallet = find_wallet_for_update(wallet_id, &self.state).await?;
        let mut new_wallet = old_wallet.clone();
        maybe_rotate_root_key(&req.update_auth, &mut new_wallet)?;

        let new_order: Order = req.order.try_into().map_err(bad_request)?;
        new_wallet.add_order(oid, new_order.clone()).map_err(bad_request)?;
        new_wallet.reblind_wallet();

        let task = UpdateWalletTaskDescriptor::new_order_with_maybe_pool(
            oid,
            new_order,
            old_wallet,
            new_wallet,
            req.update_auth.statement_sig,
            Some(matching_pool),
        )
        .map_err(bad_request)?;

        // Propose the task and await for it to be enqueued
        let task_id = append_task_and_await(task.into(), &self.state).await?;
        Ok(CreateOrderResponse { id: oid, task_id })
    }
}

/// Handler for the POST /v0/admin/orders/:id/assign-pool/:matching_pool route
pub struct AdminAssignOrderToMatchingPoolHandler {
    /// A handle to the relayer state
    state: State,
    /// A handle to send jobs to the relayer's handshake manager
    handshake_manager_queue: HandshakeManagerQueue,
}

impl AdminAssignOrderToMatchingPoolHandler {
    /// Constructor
    pub fn new(state: State, handshake_manager_queue: HandshakeManagerQueue) -> Self {
        Self { state, handshake_manager_queue }
    }
}

#[async_trait]
impl TypedHandler for AdminAssignOrderToMatchingPoolHandler {
    type Request = EmptyRequestResponse;
    type Response = EmptyRequestResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let order_id = parse_order_id_from_params(&params)?;
        let matching_pool = parse_matching_pool_from_url_params(&params)?;

        // Check that the matching pool exists
        if !self.state.matching_pool_exists(matching_pool.clone()).await? {
            return Err(not_found(ERR_NO_MATCHING_POOL));
        }

        // Assign the order to the matching pool
        let waiter = self.state.assign_order_to_matching_pool(order_id, matching_pool).await?;
        waiter.await?;

        // Run the matching engine on the order
        let job = HandshakeManagerJob::InternalMatchingEngine { order: order_id };
        self.handshake_manager_queue.send(job).map_err(internal_error)?;

        Ok(EmptyRequestResponse {})
    }
}

/// Handler for the GET /v0/admin/orders/:order_id/matching-pool route
pub struct AdminGetOrderMatchingPoolHandler {
    /// A handle to the relayer state
    state: State,
}

impl AdminGetOrderMatchingPoolHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[async_trait]
impl TypedHandler for AdminGetOrderMatchingPoolHandler {
    type Request = EmptyRequestResponse;
    type Response = AdminGetOrderMatchingPoolResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let order_id = parse_order_id_from_params(&params)?;
        let matching_pool = self.state.get_matching_pool_for_order(&order_id).await?;

        Ok(AdminGetOrderMatchingPoolResponse { matching_pool })
    }
}

/// Handler for the POST /v0/admin/refresh-token-mapping route
pub struct AdminRefreshTokenMappingHandler {
    /// The chain to fetch a token mapping for
    chain: Chain,
}

impl AdminRefreshTokenMappingHandler {
    /// Constructor
    pub fn new(chain: Chain) -> Self {
        Self { chain }
    }
}

#[async_trait]
impl TypedHandler for AdminRefreshTokenMappingHandler {
    type Request = EmptyRequestResponse;
    type Response = EmptyRequestResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        _params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        info!("Refreshing token mapping from repo");

        let chain = self.chain;
        tokio::task::spawn_blocking(move || setup_token_remaps(None /* remap_file */, chain))
            .await
            .map_err(internal_error) // Tokio join error
            .and_then(|r| r.map_err(internal_error))?; // Token remap setup error

        Ok(EmptyRequestResponse {})
    }
}

/// Handler for the POST /v0/admin/refresh-external-match-fees route
pub struct AdminRefreshExternalMatchFeesHandler {
    /// A handle to the relayer state
    darkpool_client: DarkpoolClient,
}

impl AdminRefreshExternalMatchFeesHandler {
    /// Constructor
    pub fn new(darkpool_client: DarkpoolClient) -> Self {
        Self { darkpool_client }
    }
}

#[async_trait]
impl TypedHandler for AdminRefreshExternalMatchFeesHandler {
    type Request = EmptyRequestResponse;
    type Response = EmptyRequestResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        _params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        info!("Refreshing external match fees from contract");

        let tokens: Vec<Token> = get_all_tokens()
            .into_iter()
            .chain(iter::once(Token::from_addr(NATIVE_ASSET_ADDRESS)))
            .collect();

        for token in tokens {
            let addr = token.get_alloy_address();
            let fee = self.darkpool_client.get_external_match_fee(addr).await?;

            set_external_match_fee(&token.get_addr_biguint(), fee);
        }

        Ok(EmptyRequestResponse {})
    }
}

// -----------
// | Helpers |
// -----------

/// A helper to parse out a matching pool name from a query string
fn parse_include_fillable_from_query_params(params: &QueryParams) -> Result<bool, ApiServerError> {
    params.get(INCLUDE_FILLABLE_PARAM).map_or(Ok(false), |s| s.parse().map_err(bad_request))
}

/// Get the fillable amount of an order using the underlying wallet's balances,
/// & potentially the price of the base asset
async fn get_fillable_amount_and_price(
    meta: &OrderMetadata,
    wallet_id: &WalletIdentifier,
    state: &State,
    price_reporter_job_queue: &PriceReporterQueue,
) -> Result<(Amount, Price), ApiServerError> {
    let wallet = state.get_wallet(wallet_id).await?.ok_or(not_found(ERR_WALLET_NOT_FOUND))?;

    // Get an up-to-date order & balance.
    // The order stored on the `OrderMetadata` does not have the order amount
    // updated to account for fills, which will lead to an incorrect calculation
    // of the fillable amount.
    let order = wallet.get_order(&meta.id).ok_or(not_found(ERR_ORDER_NOT_FOUND))?;
    let balance = wallet.get_balance_for_order(order).ok_or(not_found(ERR_BALANCE_NOT_FOUND))?;

    // Buy orders are capitalized by the quote token, so we may need the price of
    // the base token to calculate how capitalized the order is
    let base_token = Token::from_addr_biguint(&order.base_mint);
    let quote_token = Token::from_addr_biguint(&order.quote_mint);
    let base_addr = base_token.get_addr().to_string();
    let quote_addr = quote_token.get_addr().to_string();

    let ts_price = price_reporter_job_queue
        .peek_price(base_token.clone(), quote_token.clone())
        .await
        .map_err(|e| {
            internal_error(format!("{ERR_NO_PRICE_DATA}: {base_addr} / {quote_addr} {e}"))
        })?;

    let original_price = ts_price.price;
    let corrected_price =
        ts_price.get_decimal_corrected_price(&base_token, &quote_token).map_err(internal_error)?;

    let price_fp = FixedPoint::from_f64_round_down(corrected_price.price);

    // NOTE: While we need to use the decimal-corrected price to compute the
    // fillable amount, we return the original price to the client, as this is
    // simpler to interpret
    Ok((compute_max_amount(&price_fp, &order.clone().into(), &balance), original_price))
}
