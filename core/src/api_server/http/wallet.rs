//! Groups wallet API handlers and definitions

use async_trait::async_trait;
use hyper::StatusCode;
use num_bigint::BigUint;
use uuid::Uuid;

use crate::{
    api_server::{
        error::ApiServerError,
        router::{TypedHandler, UrlParams},
    },
    external_api::{
        http::wallet::{
            GetBalanceByMintResponse, GetBalancesResponse, GetOrderByIdResponse, GetOrdersResponse,
            GetWalletResponse,
        },
        types::{Balance, Wallet},
        EmptyRequestResponse,
    },
    state::RelayerState,
};

// ----------------
// | URL Captures |
// ----------------

/// The :mint param in a URL
const MINT_URL_PARAM: &str = "mint";
/// The :wallet_id param in a URL
const WALLET_ID_URL_PARAM: &str = "wallet_id";
/// The :order_id param in a URL
const ORDER_ID_URL_PARAM: &str = "order_id";

/// A helper to parse out a mint from a URL param
fn parse_mint_from_params(params: &UrlParams) -> Result<BigUint, ApiServerError> {
    params.get(MINT_URL_PARAM).unwrap().parse().map_err(|_| {
        ApiServerError::HttpStatusCode(StatusCode::BAD_REQUEST, ERR_MINT_PARSE.to_string())
    })
}

/// A helper to parse out a wallet ID from a URL param
fn parse_wallet_id_from_params(params: &UrlParams) -> Result<Uuid, ApiServerError> {
    params
        .get(WALLET_ID_URL_PARAM)
        .unwrap()
        .parse()
        .map_err(|_| {
            ApiServerError::HttpStatusCode(StatusCode::BAD_REQUEST, ERR_WALLET_ID_PARSE.to_string())
        })
}

/// A helper to parse out an order ID from a URL param
fn parse_order_id_from_params(params: &UrlParams) -> Result<Uuid, ApiServerError> {
    params
        .get(ORDER_ID_URL_PARAM)
        .unwrap()
        .parse()
        .map_err(|_| {
            ApiServerError::HttpStatusCode(StatusCode::BAD_REQUEST, ERR_ORDER_ID_PARSE.to_string())
        })
}

// ---------------
// | HTTP Routes |
// ---------------

/// Returns the wallet information for the given id
pub(super) const GET_WALLET_ROUTE: &str = "/v0/wallet/:wallet_id";
/// Returns the orders within a given wallet
pub(super) const GET_ORDERS_ROUTE: &str = "/v0/wallet/:wallet_id/orders";
/// Returns a single order by the given identifier
pub(super) const GET_ORDER_BY_ID_ROUTE: &str = "/v0/wallet/:wallet_id/orders/:order_id";
/// Returns the balances within a given wallet
pub(super) const GET_BALANCES_ROUTE: &str = "/v0/wallet/:wallet_id/balances";
/// Returns the balance associated with the given mint
pub(super) const GET_BALANCE_BY_MINT_ROUTE: &str = "/v0/wallet/:wallet_id/balances/:mint";

// ------------------
// | Error Messages |
// ------------------

/// Error message displayed when a mint cannot be parsed from URL
const ERR_MINT_PARSE: &str = "could not parse mint";
/// Error message displayed when a given order ID is not parsable
const ERR_ORDER_ID_PARSE: &str = "could not parse order id";
/// Error message displayed when a given wallet ID is not parsable
const ERR_WALLET_ID_PARSE: &str = "could not parse wallet id";
/// Error message displayed when a given order cannot be found
const ERR_ORDER_NOT_FOUND: &str = "order not found";
/// The error message to display when a wallet cannot be found
const ERR_WALLET_NOT_FOUND: &str = "wallet not found";

// -------------------------
// | Wallet Route Handlers |
// -------------------------

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
        let wallet_id = parse_wallet_id_from_params(&params)?;
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

// -------------------------
// | Orders Route Handlers |
// -------------------------

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
        let wallet_id = parse_wallet_id_from_params(&params)?;
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
        let wallet_id = parse_wallet_id_from_params(&params)?;
        let order_id = parse_order_id_from_params(&params)?;
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

// --------------------------
// | Balance Route Handlers |
// --------------------------

/// Handler for the GET /wallet/:id/balances route
#[derive(Clone, Debug)]
pub struct GetBalancesHandler {
    /// A copy of the relayer-global state
    pub global_state: RelayerState,
}

impl GetBalancesHandler {
    /// Constructor
    pub fn new(global_state: RelayerState) -> Self {
        Self { global_state }
    }
}

#[async_trait]
impl TypedHandler for GetBalancesHandler {
    type Request = EmptyRequestResponse;
    type Response = GetBalancesResponse;

    async fn handle_typed(
        &self,
        _req: Self::Request,
        params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        let wallet_id = parse_wallet_id_from_params(&params)?;
        if let Some(wallet) = self
            .global_state
            .read_wallet_index()
            .await
            .get_wallet(&wallet_id)
            .await
        {
            let wallet: Wallet = wallet.into();
            Ok(GetBalancesResponse {
                balances: wallet.balances,
            })
        } else {
            Err(ApiServerError::HttpStatusCode(
                StatusCode::NOT_FOUND,
                ERR_WALLET_NOT_FOUND.to_string(),
            ))
        }
    }
}

/// Handler for the GET /wallet/:wallet_id/balances/:mint route
#[derive(Clone, Debug)]
pub struct GetBalanceByMintHandler {
    /// A copy of the relayer-global state
    pub global_state: RelayerState,
}

impl GetBalanceByMintHandler {
    /// Constructor
    pub fn new(global_state: RelayerState) -> Self {
        Self { global_state }
    }
}

#[async_trait]
impl TypedHandler for GetBalanceByMintHandler {
    type Request = EmptyRequestResponse;
    type Response = GetBalanceByMintResponse;

    async fn handle_typed(
        &self,
        _req: Self::Request,
        params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        let wallet_id = parse_wallet_id_from_params(&params)?;
        let mint = parse_mint_from_params(&params)?;

        if let Some(wallet) = self
            .global_state
            .read_wallet_index()
            .await
            .get_wallet(&wallet_id)
            .await
        {
            let balance = wallet
                .balances
                .get(&mint)
                .cloned()
                .map(|balance| balance.into())
                .unwrap_or_else(|| Balance {
                    mint,
                    amount: 0u8.into(),
                });

            Ok(GetBalanceByMintResponse { balance })
        } else {
            Err(ApiServerError::HttpStatusCode(
                StatusCode::NOT_FOUND,
                ERR_WALLET_NOT_FOUND.to_string(),
            ))
        }
    }
}
