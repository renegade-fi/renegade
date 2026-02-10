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
use types_tasks::{NewAccountTaskDescriptor, RefreshAccountTaskDescriptor};

use crate::{
    error::{ApiServerError, conflict, not_found},
    http::helpers::append_task,
    param_parsing::{parse_account_id_from_params, should_block_on_task},
    router::{QueryParams, TypedHandler, UrlParams},
};

// ------------------
// | Error Messages |
// ------------------

/// Create an account not found error
pub(crate) fn account_not_found() -> ApiServerError {
    not_found("account not found")
}

/// Create an account already exists error
pub(crate) fn account_already_exists() -> ApiServerError {
    conflict("account already exists")
}

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
        let acct = self.state.get_account(&account_id).await?.ok_or_else(account_not_found)?;

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
        // Check if account already exists
        if self.state.get_account(&req.account_id).await?.is_some() {
            return Err(account_already_exists());
        }

        let blocking = should_block_on_task(&query_params);
        let private_keys = PrivateKeyChain::new(req.auth_hmac_key, req.master_view_seed);
        let keychain = KeyChain::new(private_keys, req.schnorr_public_key);
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
        let acct = self.state.get_account(&account_id).await?.ok_or_else(account_not_found)?;

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
        let private_keys = PrivateKeyChain::new(req.auth_hmac_key, req.master_view_seed);
        let keychain = KeyChain::new(private_keys, req.schnorr_public_key);

        // Create and append the task
        let descriptor = RefreshAccountTaskDescriptor::new(account_id, keychain);
        let task_id =
            append_task(descriptor.into(), blocking, &self.state, &self.task_queue).await?;

        Ok(SyncAccountResponse { task_id, completed: true })
    }
}
