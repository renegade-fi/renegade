//! Groups wallet API handlers and definitions

use async_trait::async_trait;
use hyper::StatusCode;
use uuid::Uuid;

use crate::{
    api_server::{
        error::ApiServerError,
        router::{TypedHandler, UrlParams},
    },
    external_api::{
        http::wallet::{GetOrderByIdResponse, GetOrdersResponse, GetWalletResponse},
        types::Wallet,
        EmptyRequestResponse,
    },
    state::RelayerState,
};

// ----------------
// | URL Captures |
// ----------------

/// The :wallet_id param in a URL
const WALLET_ID_URL_PARAM: &str = "wallet_id";
/// The :order_id param in a URL
const ORDER_ID_URL_PARAM: &str = "order_id";

// ---------------
// | HTTP Routes |
// ---------------

/// Returns the wallet information for the given id
pub(super) const GET_WALLET_ROUTE: &str = "/v0/wallet/:wallet_id";
/// Returns the orders within a given wallet
pub(super) const GET_ORDERS_ROUTE: &str = "/v0/wallet/:wallet_id/orders";
/// Returns a single order by the given identifier
pub(super) const GET_ORDER_BY_ID_ROUTE: &str = "/v0/wallet/:wallet_id/orders/:order_id";

// ------------------
// | Error Messages |
// ------------------

/// Error message displayed when a given order ID is not parsable
const ERR_ORDER_ID_PARSE: &str = "could not parse order id";
/// Error message displayed when a given wallet ID is not parsable
const ERR_WALLET_ID_PARSE: &str = "could not parse wallet id";
/// Error message displayed when a given order cannot be found
const ERR_ORDER_NOT_FOUND: &str = "order not found";
/// The error message to display when a wallet cannot be found
const ERR_WALLET_NOT_FOUND: &str = "wallet not found";

// ------------------
// | Route Handlers |
// ------------------

/// Handler for the GET /wallet/:id route
#[derive(Debug)]
pub struct GetWalletHandler {
    /// A copy of the relayer-global state
    global_state: RelayerState,
}

impl GetWalletHandler {
    /// Create a new handler for the /v0/wallet/:id route
    pub fn new(global_state: RelayerState) -> Self {
        Self { global_state }
    }
}

#[async_trait]
impl TypedHandler for GetWalletHandler {
    type Request = EmptyRequestResponse;
    type Response = GetWalletResponse;

    async fn handle_typed(
        &self,
        _req: Self::Request,
        params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        let wallet_id: Uuid = params
            .get(WALLET_ID_URL_PARAM)
            .unwrap()
            .parse()
            .map_err(|_| {
                ApiServerError::HttpStatusCode(
                    StatusCode::BAD_REQUEST,
                    ERR_WALLET_ID_PARSE.to_string(),
                )
            })?;

        if let Some(wallet) = self
            .global_state
            .read_wallet_index()
            .await
            .get_wallet(&wallet_id)
            .await
        {
            Ok(GetWalletResponse {
                wallet: wallet.into(),
            })
        } else {
            Err(ApiServerError::HttpStatusCode(
                StatusCode::NOT_FOUND,
                ERR_WALLET_NOT_FOUND.to_string(),
            ))
        }
    }
}

/// Handler for the GET /wallet/:id/orders route
#[derive(Clone, Debug)]
pub struct GetOrdersHandler {
    /// A copy of the relayer-global state
    pub global_state: RelayerState,
}

impl GetOrdersHandler {
    /// Create a new handler for the /wallet/:id/orders route
    pub fn new(global_state: RelayerState) -> Self {
        Self { global_state }
    }
}

#[async_trait]
impl TypedHandler for GetOrdersHandler {
    type Request = EmptyRequestResponse;
    type Response = GetOrdersResponse;

    async fn handle_typed(
        &self,
        _req: Self::Request,
        params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        let wallet_id: Uuid = params
            .get(WALLET_ID_URL_PARAM)
            .unwrap()
            .parse()
            .map_err(|_| {
                ApiServerError::HttpStatusCode(
                    StatusCode::BAD_REQUEST,
                    ERR_WALLET_NOT_FOUND.to_string(),
                )
            })?;

        if let Some(wallet) = self
            .global_state
            .read_wallet_index()
            .await
            .get_wallet(&wallet_id)
            .await
        {
            let wallet: Wallet = wallet.into();
            Ok(GetOrdersResponse {
                orders: wallet.orders,
            })
        } else {
            Err(ApiServerError::HttpStatusCode(
                StatusCode::NOT_FOUND,
                ERR_WALLET_NOT_FOUND.to_string(),
            ))
        }
    }
}

/// Handler for the GET /wallet/:id/orders/:id route
#[derive(Clone, Debug)]
pub struct GetOrderByIdHandler {
    /// A copy of the relayer-global state
    pub global_state: RelayerState,
}

impl GetOrderByIdHandler {
    /// Constructor
    pub fn new(global_state: RelayerState) -> Self {
        Self { global_state }
    }
}

#[async_trait]
impl TypedHandler for GetOrderByIdHandler {
    type Request = EmptyRequestResponse;
    type Response = GetOrderByIdResponse;

    async fn handle_typed(
        &self,
        _req: Self::Request,
        params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        let wallet_id: Uuid = params
            .get(WALLET_ID_URL_PARAM)
            .unwrap()
            .parse()
            .map_err(|_| {
                ApiServerError::HttpStatusCode(
                    StatusCode::BAD_REQUEST,
                    ERR_WALLET_ID_PARSE.to_string(),
                )
            })?;
        let order_id: Uuid = params
            .get(ORDER_ID_URL_PARAM)
            .unwrap()
            .parse()
            .map_err(|_| {
                ApiServerError::HttpStatusCode(
                    StatusCode::BAD_REQUEST,
                    ERR_ORDER_ID_PARSE.to_string(),
                )
            })?;

        if let Some(order) = (|| async {
            self.global_state
                .read_wallet_index()
                .await
                .get_wallet(&wallet_id)
                .await?
                .orders
                .get(&order_id)
                .cloned()
        })()
        .await
        {
            Ok(GetOrderByIdResponse {
                order: (order_id, order).into(),
            })
        } else {
            Err(ApiServerError::HttpStatusCode(
                StatusCode::NOT_FOUND,
                ERR_ORDER_NOT_FOUND.to_string(),
            ))
        }
    }
}
