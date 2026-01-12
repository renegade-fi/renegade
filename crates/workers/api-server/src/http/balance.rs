//! Route handlers for balance operations

use async_trait::async_trait;
use external_api::{
    EmptyRequestResponse,
    http::balance::{
        DepositBalanceRequest, DepositBalanceResponse, GetBalanceByMintResponse,
        GetBalancesResponse, WithdrawBalanceRequest, WithdrawBalanceResponse,
    },
};
use hyper::HeaderMap;
use state::State;

use crate::{
    error::ApiServerError,
    router::{QueryParams, TypedHandler, UrlParams},
};

// ------------------
// | Error Messages |
// ------------------

/// Error message for not implemented
const ERR_NOT_IMPLEMENTED: &str = "not implemented";

// ---------------------
// | Balance Handlers  |
// ---------------------

/// Handler for GET /v2/account/:account_id/balances
pub struct GetBalancesHandler;

impl GetBalancesHandler {
    /// Constructor
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl TypedHandler for GetBalancesHandler {
    type Request = EmptyRequestResponse;
    type Response = GetBalancesResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        _params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        Err(ApiServerError::not_implemented(ERR_NOT_IMPLEMENTED))
    }
}

/// Handler for GET /v2/account/:account_id/balances/:mint
pub struct GetBalanceByMintHandler;

impl GetBalanceByMintHandler {
    /// Constructor
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl TypedHandler for GetBalanceByMintHandler {
    type Request = EmptyRequestResponse;
    type Response = GetBalanceByMintResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        _params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        Err(ApiServerError::not_implemented(ERR_NOT_IMPLEMENTED))
    }
}

/// Handler for POST /v2/account/:account_id/balances/:mint/deposit
pub struct DepositBalanceHandler {
    /// The global state
    state: State,
}

impl DepositBalanceHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[async_trait]
impl TypedHandler for DepositBalanceHandler {
    type Request = DepositBalanceRequest;
    type Response = DepositBalanceResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        req: Self::Request,
        params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        unimplemented!("DepositBalanceHandler");
    }
}

/// Handler for POST /v2/account/:account_id/balances/:mint/withdraw
pub struct WithdrawBalanceHandler;

impl WithdrawBalanceHandler {
    /// Constructor
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl TypedHandler for WithdrawBalanceHandler {
    type Request = WithdrawBalanceRequest;
    type Response = WithdrawBalanceResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        _params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        Err(ApiServerError::not_implemented(ERR_NOT_IMPLEMENTED))
    }
}
