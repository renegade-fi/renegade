//! Groups wallet API handlers and definitions

use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use circuit_types::{
    balance::Balance as StateBalance,
    order::Order,
    transfers::{ExternalTransfer, ExternalTransferDirection},
};
use common::types::{
    tasks::TaskIdentifier,
    tasks::{
        LookupWalletTaskDescriptor, NewWalletTaskDescriptor, TaskDescriptor,
        UpdateWalletTaskDescriptor,
    },
    wallet::{KeyChain, Wallet, WalletIdentifier},
};
use constants::MAX_FEES;
use external_api::{
    http::wallet::{
        AddFeeRequest, AddFeeResponse, CancelOrderRequest, CancelOrderResponse, CreateOrderRequest,
        CreateOrderResponse, CreateWalletRequest, CreateWalletResponse, DepositBalanceRequest,
        DepositBalanceResponse, FindWalletRequest, FindWalletResponse, GetBalanceByMintResponse,
        GetBalancesResponse, GetFeesResponse, GetOrderByIdResponse, GetOrdersResponse,
        GetWalletResponse, RemoveFeeRequest, RemoveFeeResponse, UpdateOrderRequest,
        UpdateOrderResponse, WithdrawBalanceRequest, WithdrawBalanceResponse,
    },
    types::{ApiBalance, ApiFee, ApiOrder},
    EmptyRequestResponse,
};
use hyper::{HeaderMap, StatusCode};
use num_traits::ToPrimitive;
use renegade_crypto::fields::biguint_to_scalar;
use state::State;
use util::err_str;

use crate::{
    error::{bad_request, internal_error, not_found, ApiServerError},
    router::{TypedHandler, UrlParams, ERR_WALLET_NOT_FOUND},
};

use super::{
    parse_index_from_params, parse_mint_from_params, parse_order_id_from_params,
    parse_wallet_id_from_params,
};

/// The maximum staleness of a timestamp on an order between a request and when
/// it is processed by the API server
const MAX_TIMESTAMP_STALENESS_MS: u64 = 5_000; // 5 seconds

// -----------
// | Helpers |
// -----------

/// Get the current timestamp in milliseconds since the epoch
pub(super) fn get_current_timestamp() -> u64 {
    let now = SystemTime::now();
    now.duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

/// Check that a timestamp given by an API request is within the last
/// `MAX_TIMESTAMP_STALENESS_MS` ms
///
/// Assumes the given timestamp is in milliseconds since the epoch
fn check_timestamp_staleness(timestamp: u64) -> Result<(), ApiServerError> {
    let now = get_current_timestamp();
    if now > timestamp && now - timestamp < MAX_TIMESTAMP_STALENESS_MS {
        Ok(())
    } else {
        Err(bad_request(format!(
            "{ERR_STALE_TIMESTAMP} (current time = {now}, timestamp = {timestamp})"
        )))
    }
}

/// Find the wallet for the given id in the global state
///
/// Attempts to acquire the lock for an update on the wallet
fn find_wallet_for_update(
    wallet_id: WalletIdentifier,
    state: &State,
) -> Result<Wallet, ApiServerError> {
    // Find the wallet in global state and use its keys to authenticate the request
    let wallet =
        state.get_wallet(&wallet_id)?.ok_or_else(|| not_found(ERR_WALLET_NOT_FOUND.to_string()))?;

    // Acquire the lock for the wallet
    if wallet.is_locked() {
        return Err(ApiServerError::HttpStatusCode(
            StatusCode::LOCKED,
            ERR_UPDATE_IN_PROGRESS.to_string(),
        ));
    }

    Ok(wallet)
}

/// Append a task to a task queue and await consensus on this queue update
async fn append_task_and_await(
    wallet: &WalletIdentifier,
    task: TaskDescriptor,
    state: &State,
) -> Result<TaskIdentifier, ApiServerError> {
    let (task_id, waiter) = state.append_wallet_task(wallet, task)?;
    waiter.await.map_err(err_str!(internal_error))?;

    Ok(task_id)
}

// ---------------
// | HTTP Routes |
// ---------------

/// Create a new wallet
pub(super) const CREATE_WALLET_ROUTE: &str = "/v0/wallet";
/// Find a wallet in contract storage
pub(super) const FIND_WALLET_ROUTE: &str = "/v0/wallet/lookup";
/// Returns the wallet information for the given id
pub(super) const GET_WALLET_ROUTE: &str = "/v0/wallet/:wallet_id";
/// Route to the orders of a given wallet
pub(super) const WALLET_ORDERS_ROUTE: &str = "/v0/wallet/:wallet_id/orders";
/// Returns a single order by the given identifier
pub(super) const GET_ORDER_BY_ID_ROUTE: &str = "/v0/wallet/:wallet_id/orders/:order_id";
/// Updates a given order
pub(super) const UPDATE_ORDER_ROUTE: &str = "/v0/wallet/:wallet_id/orders/:order_id/update";
/// Cancels a given order
pub(super) const CANCEL_ORDER_ROUTE: &str = "/v0/wallet/:wallet_id/orders/:order_id/cancel";
/// Returns the balances within a given wallet
pub(super) const GET_BALANCES_ROUTE: &str = "/v0/wallet/:wallet_id/balances";
/// Returns the balance associated with the given mint
pub(super) const GET_BALANCE_BY_MINT_ROUTE: &str = "/v0/wallet/:wallet_id/balances/:mint";
/// Deposits an ERC-20 token into the darkpool
pub(super) const DEPOSIT_BALANCE_ROUTE: &str = "/v0/wallet/:wallet_id/balances/deposit";
/// Withdraws an ERC-20 token from the darkpool
pub(super) const WITHDRAW_BALANCE_ROUTE: &str = "/v0/wallet/:wallet_id/balances/:mint/withdraw";
/// Returns the fees within a given wallet
pub(super) const FEES_ROUTE: &str = "/v0/wallet/:wallet_id/fees";
/// Removes a fee from the given wallet
pub(super) const REMOVE_FEE_ROUTE: &str = "/v0/wallet/:wallet_id/fees/:index/remove";

// ------------------
// | Error Messages |
// ------------------

/// Error message displayed when a balance is insufficient to transfer the
/// requested amount
const ERR_INSUFFICIENT_BALANCE: &str = "insufficient balance";
/// Error message displayed when a given order cannot be found
const ERR_ORDER_NOT_FOUND: &str = "order not found";
/// The error message to display when a fee list is full
const ERR_FEES_FULL: &str = "wallet's fee list is full";
/// The error message to display when a fee index is out of range
const ERR_FEE_OUT_OF_RANGE: &str = "fee index out of range";
/// Error message displayed when an update is already in progress on a wallet
const ERR_UPDATE_IN_PROGRESS: &str = "wallet update already in progress";
/// The error message emitted when a timestamp is too stale
const ERR_STALE_TIMESTAMP: &str = "timestamp is too stale";

// -------------------------
// | Wallet Route Handlers |
// -------------------------

/// Handler for the GET /wallet/:id route
pub struct GetWalletHandler {
    /// A copy of the relayer-global state
    global_state: State,
}

impl GetWalletHandler {
    /// Create a new handler for the /v0/wallet/:id route
    pub fn new(global_state: State) -> Self {
        Self { global_state }
    }
}

#[async_trait]
impl TypedHandler for GetWalletHandler {
    type Request = EmptyRequestResponse;
    type Response = GetWalletResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        let wallet_id = parse_wallet_id_from_params(&params)?;
        let mut wallet = self
            .global_state
            .get_wallet(&wallet_id)?
            .ok_or_else(|| not_found(ERR_WALLET_NOT_FOUND.to_string()))?;

        // Filter out empty orders, balances, and fees
        wallet.remove_default_elements();
        Ok(GetWalletResponse { wallet: wallet.into() })
    }
}

/// Handler for the POST /wallet route
pub struct CreateWalletHandler {
    /// A copy of the relayer-global state
    global_state: State,
}

impl CreateWalletHandler {
    /// Constructor
    pub fn new(global_state: State) -> Self {
        Self { global_state }
    }
}

#[async_trait]
impl TypedHandler for CreateWalletHandler {
    type Request = CreateWalletRequest;
    type Response = CreateWalletResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        req: Self::Request,
        _params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        // Create an async task to drive this new wallet into the on-chain state
        // and create proofs of validity
        let wallet_id = req.wallet.id;
        let wallet: Wallet = req.wallet.try_into().map_err(|e: String| bad_request(e))?;
        let task = NewWalletTaskDescriptor { wallet };

        // Propose the task and await for it to be enqueued
        let task_id = append_task_and_await(&wallet_id, task.into(), &self.global_state).await?;
        Ok(CreateWalletResponse { wallet_id, task_id })
    }
}

/// Handler for the POST /wallet route
pub struct FindWalletHandler {
    /// A copy of the relayer-global state
    global_state: State,
}

impl FindWalletHandler {
    /// Constructor
    pub fn new(global_state: State) -> Self {
        Self { global_state }
    }
}

#[async_trait]
impl TypedHandler for FindWalletHandler {
    type Request = FindWalletRequest;
    type Response = FindWalletResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        req: Self::Request,
        _params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        // Create a task in thew driver to find and prove validity for
        // the wallet
        let key_chain: KeyChain =
            req.key_chain.try_into().map_err(|e: String| bad_request(e.to_string()))?;
        let task = LookupWalletTaskDescriptor {
            wallet_id: req.wallet_id,
            blinder_seed: biguint_to_scalar(&req.blinder_seed),
            secret_share_seed: biguint_to_scalar(&req.secret_share_seed),
            key_chain,
        };

        // Propose the task and await for it to be enqueued
        let task_id =
            append_task_and_await(&req.wallet_id, task.into(), &self.global_state).await?;

        Ok(FindWalletResponse { wallet_id: req.wallet_id, task_id })
    }
}

// -------------------------
// | Orders Route Handlers |
// -------------------------

/// Handler for the GET /wallet/:id/orders route
#[derive(Clone)]
pub struct GetOrdersHandler {
    /// A copy of the relayer-global state
    pub global_state: State,
}

impl GetOrdersHandler {
    /// Create a new handler for the /wallet/:id/orders route
    pub fn new(global_state: State) -> Self {
        Self { global_state }
    }
}

#[async_trait]
impl TypedHandler for GetOrdersHandler {
    type Request = EmptyRequestResponse;
    type Response = GetOrdersResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        let wallet_id = parse_wallet_id_from_params(&params)?;
        let mut wallet = self
            .global_state
            .get_wallet(&wallet_id)?
            .ok_or_else(|| not_found(ERR_WALLET_NOT_FOUND.to_string()))?;

        wallet.remove_default_elements();
        let orders = wallet.orders.into_iter().map(ApiOrder::from).collect();
        Ok(GetOrdersResponse { orders })
    }
}

/// Handler for the GET /wallet/:id/orders/:id route
#[derive(Clone)]
pub struct GetOrderByIdHandler {
    /// A copy of the relayer-global state
    pub global_state: State,
}

impl GetOrderByIdHandler {
    /// Constructor
    pub fn new(global_state: State) -> Self {
        Self { global_state }
    }
}

#[async_trait]
impl TypedHandler for GetOrderByIdHandler {
    type Request = EmptyRequestResponse;
    type Response = GetOrderByIdResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        let wallet_id = parse_wallet_id_from_params(&params)?;
        let order_id = parse_order_id_from_params(&params)?;

        // Find the wallet in global state and use its keys to authenticate the request
        let wallet = self
            .global_state
            .get_wallet(&wallet_id)?
            .ok_or_else(|| not_found(ERR_WALLET_NOT_FOUND.to_string()))?;

        if let Some(order) = wallet.orders.get(&order_id).cloned() {
            Ok(GetOrderByIdResponse { order: (order_id, order).into() })
        } else {
            Err(not_found(ERR_ORDER_NOT_FOUND.to_string()))
        }
    }
}

/// Handler for the POST /wallet/:id/orders route
pub struct CreateOrderHandler {
    /// A copy of the relayer-global state
    global_state: State,
}

impl CreateOrderHandler {
    /// Constructor
    pub fn new(global_state: State) -> Self {
        Self { global_state }
    }
}

#[async_trait]
impl TypedHandler for CreateOrderHandler {
    type Request = CreateOrderRequest;
    type Response = CreateOrderResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        req: Self::Request,
        params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        let id = req.order.id;
        let wallet_id = parse_wallet_id_from_params(&params)?;

        // Lookup the wallet in the global state
        let old_wallet = find_wallet_for_update(wallet_id, &self.global_state)?;
        let mut new_wallet = old_wallet.clone();
        let new_order: Order = req.order.into();

        // Check that the timestamp is not too old, then add to the wallet
        let timestamp = new_order.timestamp;
        check_timestamp_staleness(timestamp)?;
        new_wallet.add_order(id, new_order).map_err(bad_request)?;
        new_wallet.reblind_wallet();

        let task = UpdateWalletTaskDescriptor {
            timestamp_received: timestamp,
            external_transfer: None,
            old_wallet,
            new_wallet,
            wallet_update_signature: req.statement_sig,
        };

        // Propose the task and await for it to be enqueued
        let task_id = append_task_and_await(&wallet_id, task.into(), &self.global_state).await?;
        Ok(CreateOrderResponse { id, task_id })
    }
}

/// Handler for the POST /wallet/:id/orders/:id/update route
pub struct UpdateOrderHandler {
    /// A copy of the relayer-global state
    global_state: State,
}

impl UpdateOrderHandler {
    /// Constructor
    pub fn new(global_state: State) -> Self {
        Self { global_state }
    }
}

#[async_trait]
impl TypedHandler for UpdateOrderHandler {
    type Request = UpdateOrderRequest;
    type Response = UpdateOrderResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        req: Self::Request,
        params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        let wallet_id = parse_wallet_id_from_params(&params)?;
        let order_id = parse_order_id_from_params(&params)?;

        // Lookup the wallet in the global state
        let old_wallet = find_wallet_for_update(wallet_id, &self.global_state)?;

        // Pop the old order and replace it with a new one
        let mut new_wallet = old_wallet.clone();

        let new_order: Order = req.order.into();
        let timestamp = new_order.timestamp;
        check_timestamp_staleness(timestamp)?;

        // We edit the value of the underlying map in-place (as opposed to `pop` and
        // `insert`) to maintain ordering of the orders. This is important for
        // the circuit, which relies on the order of the orders to be consistent
        // between the old and new wallets
        let order = new_wallet
            .orders
            .get_mut(&order_id)
            .ok_or_else(|| not_found(ERR_ORDER_NOT_FOUND.to_string()))?;
        *order = new_order;
        new_wallet.reblind_wallet();

        let task = UpdateWalletTaskDescriptor {
            timestamp_received: timestamp,
            external_transfer: None,
            old_wallet,
            new_wallet,
            wallet_update_signature: req.statement_sig,
        };

        // Propose the task and await for it to be enqueued
        let task_id = append_task_and_await(&wallet_id, task.into(), &self.global_state).await?;
        Ok(UpdateOrderResponse { task_id })
    }
}

/// Handler for the POST /wallet/:id/orders/:id/cancel route
pub struct CancelOrderHandler {
    /// A copy of the relayer-global state
    global_state: State,
}

impl CancelOrderHandler {
    /// Constructor
    pub fn new(global_state: State) -> Self {
        Self { global_state }
    }
}

#[async_trait]
impl TypedHandler for CancelOrderHandler {
    type Request = CancelOrderRequest;
    type Response = CancelOrderResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        req: Self::Request,
        params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        let wallet_id = parse_wallet_id_from_params(&params)?;
        let order_id = parse_order_id_from_params(&params)?;

        // Lookup the wallet in the global state
        let old_wallet = find_wallet_for_update(wallet_id, &self.global_state)?;

        // Remove the order from the new wallet
        let mut new_wallet = old_wallet.clone();
        let order = new_wallet
            .orders
            .remove(&order_id)
            .ok_or_else(|| not_found(ERR_ORDER_NOT_FOUND.to_string()))?;
        new_wallet.reblind_wallet();

        let task = UpdateWalletTaskDescriptor {
            timestamp_received: get_current_timestamp(),
            external_transfer: None,
            old_wallet,
            new_wallet,
            wallet_update_signature: req.statement_sig,
        };

        // Propose the task and await for it to be enqueued
        let task_id = append_task_and_await(&wallet_id, task.into(), &self.global_state).await?;
        Ok(CancelOrderResponse { task_id, order: (order_id, order).into() })
    }
}

// --------------------------
// | Balance Route Handlers |
// --------------------------

/// Handler for the GET /wallet/:id/balances route
#[derive(Clone)]
pub struct GetBalancesHandler {
    /// A copy of the relayer-global state
    pub global_state: State,
}

impl GetBalancesHandler {
    /// Constructor
    pub fn new(global_state: State) -> Self {
        Self { global_state }
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
        params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        let wallet_id = parse_wallet_id_from_params(&params)?;
        if let Some(mut wallet) = self.global_state.get_wallet(&wallet_id)? {
            // Filter out the default balances used to pad the wallet to the circuit size
            wallet.remove_default_elements();
            let balances = wallet.balances.into_values().map(ApiBalance::from).collect();

            Ok(GetBalancesResponse { balances })
        } else {
            Err(not_found(ERR_WALLET_NOT_FOUND.to_string()))
        }
    }
}

/// Handler for the GET /wallet/:wallet_id/balances/:mint route
#[derive(Clone)]
pub struct GetBalanceByMintHandler {
    /// A copy of the relayer-global state
    pub global_state: State,
}

impl GetBalanceByMintHandler {
    /// Constructor
    pub fn new(global_state: State) -> Self {
        Self { global_state }
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
        params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        let wallet_id = parse_wallet_id_from_params(&params)?;
        let mint = parse_mint_from_params(&params)?;

        if let Some(wallet) = self.global_state.get_wallet(&wallet_id)? {
            let balance = wallet
                .balances
                .get(&mint)
                .cloned()
                .map(|balance| balance.into())
                .unwrap_or_else(|| ApiBalance { mint, amount: 0u8.into() });

            Ok(GetBalanceByMintResponse { balance })
        } else {
            Err(not_found(ERR_WALLET_NOT_FOUND.to_string()))
        }
    }
}

/// Handler for the POST /wallet/:id/balances/deposit route
pub struct DepositBalanceHandler {
    /// A copy of the relayer-global state
    global_state: State,
}

impl DepositBalanceHandler {
    /// Constructor
    pub fn new(global_state: State) -> Self {
        Self { global_state }
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
    ) -> Result<Self::Response, ApiServerError> {
        // Parse the wallet ID from the params
        let wallet_id = parse_wallet_id_from_params(&params)?;

        // Lookup the old wallet by id
        let old_wallet = find_wallet_for_update(wallet_id, &self.global_state)?;

        // Apply the balance update to the old wallet to get the new wallet
        let mut new_wallet = old_wallet.clone();
        let amount = req.amount.to_u64().unwrap();
        new_wallet
            .add_balance(StateBalance { mint: req.mint.clone(), amount })
            .map_err(bad_request)?;
        new_wallet.reblind_wallet();

        let task = UpdateWalletTaskDescriptor {
            timestamp_received: get_current_timestamp(),
            external_transfer: Some(ExternalTransfer {
                account_addr: req.from_addr,
                mint: req.mint,
                amount: req.amount,
                direction: ExternalTransferDirection::Deposit,
            }),
            old_wallet,
            new_wallet,
            wallet_update_signature: req.statement_sig,
        };

        // Propose the task and await for it to be enqueued
        let task_id = append_task_and_await(&wallet_id, task.into(), &self.global_state).await?;
        Ok(DepositBalanceResponse { task_id })
    }
}

/// Handler for the POST /wallet/:id/balances/:mint/withdraw route
pub struct WithdrawBalanceHandler {
    /// A copy of the relayer-global state
    global_state: State,
}

impl WithdrawBalanceHandler {
    /// Constructor
    pub fn new(global_state: State) -> Self {
        Self { global_state }
    }
}

#[async_trait]
impl TypedHandler for WithdrawBalanceHandler {
    type Request = WithdrawBalanceRequest;
    type Response = WithdrawBalanceResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        req: Self::Request,
        params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        // Parse the wallet ID and mint from the params
        let wallet_id = parse_wallet_id_from_params(&params)?;
        let mint = parse_mint_from_params(&params)?;

        // Lookup the wallet in the global state
        let old_wallet = find_wallet_for_update(wallet_id, &self.global_state)?;

        // Apply the withdrawal to the wallet
        let withdrawal_amount = req.amount.to_u64().unwrap();

        let mut new_wallet = old_wallet.clone();
        if let Some(balance) = new_wallet.balances.get_mut(&mint)
            && balance.amount >= withdrawal_amount
        {
            balance.amount -= withdrawal_amount;
        } else {
            return Err(bad_request(ERR_INSUFFICIENT_BALANCE.to_string()));
        }
        new_wallet.reblind_wallet();

        let task = UpdateWalletTaskDescriptor {
            timestamp_received: get_current_timestamp(),
            external_transfer: Some(ExternalTransfer {
                account_addr: req.destination_addr,
                mint,
                amount: req.amount,
                direction: ExternalTransferDirection::Withdrawal,
            }),
            old_wallet,
            new_wallet,
            wallet_update_signature: req.statement_sig,
        };

        // Propose the task and await for it to be enqueued
        let task_id = append_task_and_await(&wallet_id, task.into(), &self.global_state).await?;
        Ok(WithdrawBalanceResponse { task_id })
    }
}

// ----------------------
// | Fee Route Handlers |
// ----------------------

/// Handler for the GET /wallet/:id/fees route
#[derive(Clone)]
pub struct GetFeesHandler {
    /// A copy of the relayer-global state
    global_state: State,
}

impl GetFeesHandler {
    /// Constructor
    pub fn new(global_state: State) -> Self {
        Self { global_state }
    }
}

#[async_trait]
impl TypedHandler for GetFeesHandler {
    type Request = EmptyRequestResponse;
    type Response = GetFeesResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        let wallet_id = parse_wallet_id_from_params(&params)?;

        if let Some(mut wallet) = self.global_state.get_wallet(&wallet_id)? {
            // Filter out all the default fees used to pad the wallet to the circuit size
            wallet.remove_default_elements();
            let fees = wallet.fees.into_iter().map(ApiFee::from).collect();

            Ok(GetFeesResponse { fees })
        } else {
            Err(not_found(ERR_WALLET_NOT_FOUND.to_string()))
        }
    }
}

/// Handler for the POST /wallet/:id/fees route
pub struct AddFeeHandler {
    /// A copy of the relayer-global state
    global_state: State,
}

impl AddFeeHandler {
    /// Constructor
    pub fn new(global_state: State) -> Self {
        Self { global_state }
    }
}

#[async_trait]
impl TypedHandler for AddFeeHandler {
    type Request = AddFeeRequest;
    type Response = AddFeeResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        req: Self::Request,
        params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        // Parse the wallet from the URL params
        let wallet_id = parse_wallet_id_from_params(&params)?;

        // Lookup the wallet in the global state
        let old_wallet = find_wallet_for_update(wallet_id, &self.global_state)?;

        // Ensure that the fees list is not full
        let num_fees = old_wallet.fees.iter().filter(|fee| !fee.is_default()).count();
        if num_fees >= MAX_FEES {
            return Err(bad_request(ERR_FEES_FULL.to_string()));
        }

        // Add the fee to the new wallet
        let mut new_wallet = old_wallet.clone();
        new_wallet.fees.push(req.fee.into());
        new_wallet.reblind_wallet();

        let task = UpdateWalletTaskDescriptor {
            timestamp_received: get_current_timestamp(),
            external_transfer: None,
            old_wallet,
            new_wallet,
            wallet_update_signature: req.statement_sig,
        };

        // Propose the task and await for it to be enqueued
        let task_id = append_task_and_await(&wallet_id, task.into(), &self.global_state).await?;
        Ok(AddFeeResponse { task_id })
    }
}

/// Handler for the POST /wallet/:id/fees/:index/remove route
pub struct RemoveFeeHandler {
    /// A copy of the relayer-global state
    global_state: State,
}

impl RemoveFeeHandler {
    /// Constructor
    pub fn new(global_state: State) -> Self {
        Self { global_state }
    }
}

#[async_trait]
impl TypedHandler for RemoveFeeHandler {
    type Request = RemoveFeeRequest;
    type Response = RemoveFeeResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        req: Self::Request,
        params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        // Parse the wallet id and fee index from the URL params
        let wallet_id = parse_wallet_id_from_params(&params)?;
        let fee_index = parse_index_from_params(&params)?;

        // Lookup the wallet in the global state
        let old_wallet = find_wallet_for_update(wallet_id, &self.global_state)?;

        if fee_index >= old_wallet.fees.len() {
            return Err(not_found(ERR_FEE_OUT_OF_RANGE.to_string()));
        }

        // Remove the fee from the old wallet
        let mut new_wallet = old_wallet.clone();
        let removed_fee = new_wallet.fees.remove(fee_index);
        new_wallet.reblind_wallet();

        // Start a task to submit this update to the contract
        let task = UpdateWalletTaskDescriptor {
            timestamp_received: get_current_timestamp(),
            external_transfer: None,
            old_wallet,
            new_wallet,
            wallet_update_signature: req.statement_sig,
        };

        // Propose the task and await for it to be enqueued
        let task_id = append_task_and_await(&wallet_id, task.into(), &self.global_state).await?;
        Ok(RemoveFeeResponse { task_id, fee: removed_fee.into() })
    }
}
