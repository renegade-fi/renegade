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
use job_types::task_driver::TaskDriverQueue;
use state::State;
use types_account::keychain::{KeyChain, PrivateKeyChain};
use types_core::HmacKey;
use types_tasks::{NewAccountTaskDescriptor, RefreshAccountTaskDescriptor};

use crate::{
    error::{ApiServerError, bad_request, not_found},
    http::helpers::append_task,
    param_parsing::{parse_account_id_from_params, should_block_on_task},
    router::{QueryParams, TypedHandler, UrlParams},
};

// ------------------
// | Error Messages |
// ------------------

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
pub struct CreateAccountHandler {
    /// A handle to the state
    state: State,
    /// The task driver queue
    task_queue: TaskDriverQueue,
}

impl CreateAccountHandler {
    /// Constructor
    pub fn new(state: State, task_queue: TaskDriverQueue) -> Self {
        Self { state, task_queue }
    }
}

#[async_trait]
impl TypedHandler for CreateAccountHandler {
    type Request = CreateAccountRequest;
    type Response = EmptyRequestResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        req: Self::Request,
        _params: UrlParams,
        query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let blocking = should_block_on_task(&query_params);
        let auth_key = HmacKey::from_bytes(&req.auth_hmac_key).map_err(bad_request)?;
        let keychain = KeyChain::new(PrivateKeyChain::new(auth_key, req.master_view_seed));
        let task = NewAccountTaskDescriptor::new(req.account_id, keychain, req.address);
        append_task(task.into(), blocking, &self.state, &self.task_queue).await?;

        Ok(EmptyRequestResponse {})
    }
}

/// Handler for GET /v2/account/:account_id/seeds
pub struct GetAccountSeedsHandler {
    /// A handle to the relayer's state
    state: State,
}

impl GetAccountSeedsHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
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
        params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let account_id = parse_account_id_from_params(&params)?;
        let acct =
            self.state.get_account(&account_id).await?.ok_or(not_found(ERR_ACCOUNT_NOT_FOUND))?;

        let secret_keys = acct.keychain.secret_keys;
        Ok(GetAccountSeedsResponse {
            recovery_seed_csprng: secret_keys.master_recovery_seed_csprng.into(),
            share_seed_csprng: secret_keys.master_share_seed_csprng.into(),
        })
    }
}

/// Handler for POST /v2/account/:account_id/sync
pub struct SyncAccountHandler {
    /// A handle to the state
    state: State,
    /// The task driver queue
    task_queue: TaskDriverQueue,
}

impl SyncAccountHandler {
    /// Constructor
    pub fn new(state: State, task_queue: TaskDriverQueue) -> Self {
        Self { state, task_queue }
    }
}

#[async_trait]
impl TypedHandler for SyncAccountHandler {
    type Request = SyncAccountRequest;
    type Response = SyncAccountResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        req: Self::Request,
        params: UrlParams,
        query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let blocking = should_block_on_task(&query_params);

        // Parse account_id from URL params
        let account_id = parse_account_id_from_params(&params)?;

        // Build keychain from request
        let auth_key = HmacKey::from_bytes(&req.auth_hmac_key).map_err(bad_request)?;
        let master_view_seed = req.master_view_seed;
        let keychain = KeyChain::new(PrivateKeyChain::new(auth_key, master_view_seed));

        // Create and append the task
        let descriptor = RefreshAccountTaskDescriptor::new(account_id, keychain);
        let task_id =
            append_task(descriptor.into(), blocking, &self.state, &self.task_queue).await?;

        Ok(SyncAccountResponse { task_id, completed: true })
    }
}
