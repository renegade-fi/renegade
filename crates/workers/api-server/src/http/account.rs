//! Route handlers for account operations

use async_trait::async_trait;
use external_api::{
    EmptyRequestResponse,
    http::account::{
        CreateAccountRequest, GetAccountResponse, GetAccountSeedsResponse, SyncAccountRequest,
        SyncAccountResponse,
    },
};
use hyper::HeaderMap;
use state::State;

use crate::{
    error::{ApiServerError, not_found},
    param_parsing::parse_account_id_from_params,
    router::{QueryParams, TypedHandler, UrlParams},
};

// ------------------
// | Error Messages |
// ------------------

/// Error message for not implemented
const ERR_NOT_IMPLEMENTED: &str = "not implemented";
/// Error message for account not found
const ERR_ACCOUNT_NOT_FOUND: &str = "account not found";

// --------------------
// | Account Handlers |
// --------------------

/// Handler for GET /v2/account/:account_id
pub struct GetAccountByIdHandler {
    /// A handle to the relayer's state
    state: State,
}

impl GetAccountByIdHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[async_trait]
impl TypedHandler for GetAccountByIdHandler {
    type Request = EmptyRequestResponse;
    type Response = GetAccountResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let account_id = parse_account_id_from_params(&params)?;
        let acct =
            self.state.get_account(&account_id).await?.ok_or(not_found(ERR_ACCOUNT_NOT_FOUND))?;

        Ok(GetAccountResponse { account: acct.into() })
    }
}

/// Handler for POST /v2/account
pub struct CreateAccountHandler;

impl CreateAccountHandler {
    /// Constructor
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl TypedHandler for CreateAccountHandler {
    type Request = CreateAccountRequest;
    type Response = EmptyRequestResponse;

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

/// Handler for GET /v2/account/:account_id/seeds
pub struct GetAccountSeedsHandler;

impl GetAccountSeedsHandler {
    /// Constructor
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl TypedHandler for GetAccountSeedsHandler {
    type Request = EmptyRequestResponse;
    type Response = GetAccountSeedsResponse;

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

/// Handler for POST /v2/account/:account_id/sync
pub struct SyncAccountHandler;

impl SyncAccountHandler {
    /// Constructor
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl TypedHandler for SyncAccountHandler {
    type Request = SyncAccountRequest;
    type Response = SyncAccountResponse;

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
