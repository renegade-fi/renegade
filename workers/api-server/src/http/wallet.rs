//! Groups wallet API handlers and definitions

use async_trait::async_trait;
use circuit_types::{
    Amount, SizedWallet as SizedCircuitWallet, balance::Balance,
    native_helpers::create_wallet_shares_from_private,
};
use common::types::{
    tasks::{
        LookupWalletTaskDescriptor, NewWalletTaskDescriptor, PayOfflineFeeTaskDescriptor,
        RedeemFeeTaskDescriptor, TaskDescriptor, TaskIdentifier, UpdateWalletTaskDescriptor,
    },
    token::Token,
    transfer_auth::{DepositAuth, ExternalTransferWithAuth, WithdrawalAuth},
    wallet::{Order, Wallet, WalletIdentifier, keychain::PrivateKeyChain},
};
use external_api::{
    EmptyRequestResponse,
    http::wallet::{
        CancelOrderRequest, CancelOrderResponse, CreateOrderRequest, CreateOrderResponse,
        CreateWalletRequest, CreateWalletResponse, DepositBalanceRequest, DepositBalanceResponse,
        FindWalletRequest, FindWalletResponse, GetBalanceByMintResponse, GetBalancesResponse,
        GetOrderByIdResponse, GetOrderHistoryResponse, GetOrdersResponse, GetWalletResponse,
        PayFeesResponse, RedeemNoteRequest, RedeemNoteResponse, RefreshWalletResponse,
        UpdateOrderRequest, UpdateOrderResponse, WalletUpdateAuthorization, WithdrawBalanceRequest,
        WithdrawBalanceResponse,
    },
    types::ApiOrder,
};
use hyper::HeaderMap;
use itertools::Itertools;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use price_state::PriceStreamStates;
use renegade_crypto::fields::biguint_to_scalar;
use state::State;
use task_driver::simulation::simulate_wallet_tasks;
use util::{
    err_str,
    hex::{biguint_to_hex_addr, jubjub_to_hex_string, public_sign_key_from_hex_string},
};

use crate::{
    compliance::ComplianceServerClient,
    error::{ApiServerError, bad_request, internal_error, not_found},
    router::{ERR_WALLET_NOT_FOUND, QueryParams, TypedHandler, UrlParams},
};

use super::{
    parse_mint_from_params, parse_order_id_from_params, parse_wallet_id_from_params,
    rate_limit::WalletTaskRateLimiter,
};

// -----------
// | Helpers |
// -----------

/// The default number of orders in history to truncate at if not specified
const DEFAULT_ORDER_HISTORY_LEN: usize = 100;
/// The name of the query parameter specifying the length of the order history
/// to return
const ORDER_HISTORY_LEN_PARAM: &str = "order_history_len";

/// Find the wallet in global state and apply any tasks to its state
pub(crate) async fn find_wallet_for_update(
    wallet_id: WalletIdentifier,
    state: &State,
) -> Result<Wallet, ApiServerError> {
    // Find the wallet and tasks
    let (mut wallet, tasks) = state
        .get_wallet_and_tasks(&wallet_id)
        .await?
        .ok_or_else(|| not_found(ERR_WALLET_NOT_FOUND.to_string()))?;

    // Apply tasks to the wallet
    let descriptors = tasks.into_iter().map(|t| t.descriptor).collect_vec();
    simulate_wallet_tasks(&mut wallet, descriptors).map_err(internal_error)?;
    Ok(wallet)
}

/// Append a task to a task queue and await consensus on this queue update
pub(crate) async fn append_task_and_await(
    task: TaskDescriptor,
    state: &State,
) -> Result<TaskIdentifier, ApiServerError> {
    let (task_id, waiter) = state.append_task(task).await?;
    waiter.await.map_err(err_str!(internal_error))?;

    Ok(task_id)
}

/// Rotate the wallet's public root key if the request specifies a new key
pub(crate) fn maybe_rotate_root_key(
    update_auth: &WalletUpdateAuthorization,
    wallet: &mut Wallet,
) -> Result<(), ApiServerError> {
    // Parse the new root key if it exists
    let new_pk = match update_auth.new_root_key.clone() {
        None => return Ok(()),
        Some(new_pk) => public_sign_key_from_hex_string(&new_pk).map_err(bad_request)?,
    };

    // Rotate the root key if it has changed
    if new_pk != wallet.key_chain.pk_root() {
        wallet.key_chain.set_pk_root(new_pk);
        wallet.key_chain.increment_nonce();
    }

    Ok(())
}

/// Get the USDC denominated value of a balance
///
/// Note that this function may have precision issues for large balances, it is
/// intended as a simple implementation at the expense of some precision
pub(crate) fn get_usdc_denominated_value(
    mint: &BigUint,
    amount: Amount,
    price_streams: &PriceStreamStates,
) -> Result<Option<f64>, ApiServerError> {
    let base_token = Token::from_addr_biguint(mint);
    let quote_token = Token::from_ticker("USDC");
    let amount_with_decimals = base_token.convert_to_decimal(amount);

    // If the token is USDC, return the amount
    if base_token == quote_token {
        return Ok(Some(amount_with_decimals));
    }

    // Peek at the price report from the price reporter and compute the USDC
    // denominated value
    let price = price_streams.peek_price(&base_token)?;
    let value = amount_with_decimals * price;
    Ok(Some(value))
}

// ------------------
// | Error Messages |
// ------------------

/// The error message returned when a deposit address is screened out
const ERR_SCREENED_OUT_ADDRESS: &str = "deposit address was screened as high risk";
/// The error message returned when a wallet with a given ID already exists
const ERR_WALLET_ALREADY_EXISTS: &str = "wallet id already exists";
/// The error message returned when an order with a given ID already exists
const ERR_ORDER_ALREADY_EXISTS: &str = "order id already exists";

/// Error message displayed when a given order cannot be found
pub const ERR_ORDER_NOT_FOUND: &str = "order not found";
/// Error message emitted when a withdrawal is attempted with non-zero fees
const ERR_WITHDRAW_NONZERO_FEES: &str = "cannot withdraw with non-zero fees";
/// Error message emitted when a withdrawal is attempted with an amount less
/// than the minimum allowed
const ERR_MIN_WITHDRAWAL_AMOUNT: &str = "cannot withdraw less than the minimum allowed amount";
/// Error message emitted when a deposit is attempted with an amount less than
/// the minimum allowed
const ERR_MIN_DEPOSIT_AMOUNT: &str = "cannot deposit less than the minimum allowed amount";

/// Error message emitted when historical state is disabled
const ERR_HISTORICAL_STATE_DISABLED: &str = "historical state is disabled";

// -------------------------
// | Wallet Route Handlers |
// -------------------------

/// Handler for the GET /wallet/:id route
pub struct GetWalletHandler {
    /// A copy of the relayer-global state
    state: State,
}

impl GetWalletHandler {
    /// Create a new handler for the /v0/wallet/:id route
    pub fn new(state: State) -> Self {
        Self { state }
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
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let wallet_id = parse_wallet_id_from_params(&params)?;
        let wallet = self
            .state
            .get_wallet(&wallet_id)
            .await?
            .ok_or_else(|| not_found(ERR_WALLET_NOT_FOUND.to_string()))?;

        Ok(GetWalletResponse { wallet: wallet.into() })
    }
}

/// Handler for the GET /wallet/back_of_queue route
pub struct GetBackOfQueueWalletHandler {
    /// A copy of the relayer-global state
    state: State,
}

impl GetBackOfQueueWalletHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[async_trait]
impl TypedHandler for GetBackOfQueueWalletHandler {
    type Request = EmptyRequestResponse;
    type Response = GetWalletResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        // Fetch the wallet and its tasks from state
        let wallet_id = parse_wallet_id_from_params(&params)?;
        let wallet = find_wallet_for_update(wallet_id, &self.state).await?;
        Ok(GetWalletResponse { wallet: wallet.into() })
    }
}

/// Handler for the POST /wallet route
pub struct CreateWalletHandler {
    /// A copy of the relayer-global state
    state: State,
    /// The per-wallet task rate limiter
    rate_limiter: WalletTaskRateLimiter,
}

impl CreateWalletHandler {
    /// Constructor
    pub fn new(state: State, rate_limiter: WalletTaskRateLimiter) -> Self {
        Self { state, rate_limiter }
    }
}

#[async_trait]
impl TypedHandler for CreateWalletHandler {
    type Request = CreateWalletRequest;
    type Response = CreateWalletResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        mut req: Self::Request,
        _params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        // Disallow overwriting an existing wallet
        let wallet_id = req.wallet.id;
        if self.state.get_wallet(&wallet_id).await?.is_some() {
            return Err(bad_request(ERR_WALLET_ALREADY_EXISTS));
        }

        // Overwrite the managing cluster and the match fee with the configured values
        let relayer_key = self.state.get_fee_key()?.public_key();
        let relayer_take_rate = self.state.get_relayer_fee_for_wallet(&wallet_id)?;
        req.wallet.managing_cluster = jubjub_to_hex_string(&relayer_key);
        req.wallet.match_fee = relayer_take_rate;

        // Create an async task to drive this new wallet into the on-chain state
        // and create proofs of validity
        let mut wallet: Wallet = req.wallet.try_into().map_err(|e: String| bad_request(e))?;

        // Modify the public shares of the new wallet to reflect the overwritten fields
        let circuit_wallet: SizedCircuitWallet = wallet.clone().into();
        let (_, public_shares) = create_wallet_shares_from_private(
            &circuit_wallet,
            &wallet.private_shares,
            wallet.blinder,
        );
        wallet.blinded_public_shares = public_shares;

        wallet.wallet_id = wallet_id;
        let blinder_seed = biguint_to_scalar(&req.blinder_seed);
        let task = NewWalletTaskDescriptor::new(wallet, blinder_seed).map_err(bad_request)?;

        // Check rate limits and enqueue the task
        self.rate_limiter.check_rate_limit(wallet_id).await?;
        let task_id = append_task_and_await(task.into(), &self.state).await?;

        Ok(CreateWalletResponse { wallet_id, task_id })
    }
}

/// Handler for the POST /wallet/lookup route
pub struct FindWalletHandler {
    /// A copy of the relayer-global state
    state: State,
    /// The per-wallet task rate limiter
    rate_limiter: WalletTaskRateLimiter,
}

impl FindWalletHandler {
    /// Constructor
    pub fn new(state: State, rate_limiter: WalletTaskRateLimiter) -> Self {
        Self { state, rate_limiter }
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
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        // Check that the wallet does not already exist.
        // Existing wallets can be refreshed via the /refresh route
        if self.state.get_wallet(&req.wallet_id).await?.is_some() {
            return Err(bad_request(ERR_WALLET_ALREADY_EXISTS));
        }

        // Create a task in thew driver to find and prove validity for
        // the wallet
        let keychain = PrivateKeyChain::try_from(req.private_keychain).map_err(bad_request)?;
        let blinder_seed = biguint_to_scalar(&req.blinder_seed);
        let share_seed = biguint_to_scalar(&req.secret_share_seed);
        let task =
            LookupWalletTaskDescriptor::new(req.wallet_id, blinder_seed, share_seed, keychain)
                .map_err(bad_request)?;

        // Check rate limits and enqueue the task
        self.rate_limiter.check_rate_limit(req.wallet_id).await?;
        let task_id = append_task_and_await(task.into(), &self.state).await?;

        Ok(FindWalletResponse { wallet_id: req.wallet_id, task_id })
    }
}

/// Handler for the POST /wallet/:wallet_id/refresh route
pub struct RefreshWalletHandler {
    /// A copy of the relayer-global state
    state: State,
    /// The per-wallet task rate limiter
    rate_limiter: WalletTaskRateLimiter,
}

impl RefreshWalletHandler {
    /// Constructor
    pub fn new(state: State, rate_limiter: WalletTaskRateLimiter) -> Self {
        Self { state, rate_limiter }
    }
}

#[async_trait]
impl TypedHandler for RefreshWalletHandler {
    type Request = EmptyRequestResponse;
    type Response = RefreshWalletResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let wallet_id = parse_wallet_id_from_params(&params)?;
        if self.state.get_wallet(&wallet_id).await?.is_none() {
            return Err(not_found(ERR_WALLET_NOT_FOUND));
        }

        // Clear the task queue of the wallet
        let waiter = self.state.clear_task_queue(&wallet_id).await?;
        waiter.await.map_err(internal_error)?;

        // Check rate limits and enqueue the task
        self.rate_limiter.check_rate_limit(wallet_id).await?;
        let task_id = self.state.append_wallet_refresh_task(wallet_id).await?;

        Ok(RefreshWalletResponse { task_id })
    }
}

// -------------------------
// | Orders Route Handlers |
// -------------------------

/// Handler for the GET /wallet/:id/orders route
#[derive(Clone)]
pub struct GetOrdersHandler {
    /// A copy of the relayer-global state
    pub state: State,
}

impl GetOrdersHandler {
    /// Create a new handler for the /wallet/:id/orders route
    pub fn new(state: State) -> Self {
        Self { state }
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
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let wallet_id = parse_wallet_id_from_params(&params)?;
        let mut wallet = self
            .state
            .get_wallet(&wallet_id)
            .await?
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
    pub state: State,
}

impl GetOrderByIdHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
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
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let wallet_id = parse_wallet_id_from_params(&params)?;
        let order_id = parse_order_id_from_params(&params)?;

        // Find the wallet in global state and use its keys to authenticate the request
        let wallet = self
            .state
            .get_wallet(&wallet_id)
            .await?
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
    state: State,
    /// The per-wallet task rate limiter
    rate_limiter: WalletTaskRateLimiter,
}

impl CreateOrderHandler {
    /// Constructor
    pub fn new(state: State, rate_limiter: WalletTaskRateLimiter) -> Self {
        Self { state, rate_limiter }
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
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let wallet_id = parse_wallet_id_from_params(&params)?;

        // Check that the order does not already exist
        let oid = req.order.id;
        if self.state.contains_order(&oid).await? {
            return Err(bad_request(ERR_ORDER_ALREADY_EXISTS));
        }

        // Lookup the wallet in the global state
        let old_wallet = find_wallet_for_update(wallet_id, &self.state).await?;
        let mut new_wallet = old_wallet.clone();
        maybe_rotate_root_key(&req.update_auth, &mut new_wallet)?;

        // Add the order to the wallet
        let new_order: Order = req.order.try_into().map_err(bad_request)?;
        new_wallet.add_order(oid, new_order.clone()).map_err(bad_request)?;
        new_wallet.reblind_wallet();

        let task = UpdateWalletTaskDescriptor::new_order_placement(
            oid,
            new_order,
            old_wallet,
            new_wallet,
            req.update_auth.statement_sig,
        )
        .map_err(bad_request)?;

        // Check rate limits and enqueue the task
        self.rate_limiter.check_rate_limit(wallet_id).await?;
        let task_id = append_task_and_await(task.into(), &self.state).await?;

        Ok(CreateOrderResponse { id: oid, task_id })
    }
}

/// Handler for the POST /wallet/:id/orders/:id/update route
pub struct UpdateOrderHandler {
    /// A copy of the relayer-global state
    state: State,
    /// The per-wallet task rate limiter
    rate_limiter: WalletTaskRateLimiter,
}

impl UpdateOrderHandler {
    /// Constructor
    pub fn new(state: State, rate_limiter: WalletTaskRateLimiter) -> Self {
        Self { state, rate_limiter }
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
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let wallet_id = parse_wallet_id_from_params(&params)?;
        let order_id = parse_order_id_from_params(&params)?;

        // Lookup the wallet in the global state
        let old_wallet = find_wallet_for_update(wallet_id, &self.state).await?;
        let mut new_wallet = old_wallet.clone();
        maybe_rotate_root_key(&req.update_auth, &mut new_wallet)?;

        // Edit the order if it exists in the wallet
        let new_order: Order = req.order.try_into().map_err(bad_request)?;
        let order = new_wallet
            .orders
            .get_mut(&order_id)
            .ok_or_else(|| not_found(ERR_ORDER_NOT_FOUND.to_string()))?;
        *order = new_order.clone();
        new_wallet.reblind_wallet();

        let task = UpdateWalletTaskDescriptor::new_order_placement(
            order_id,
            new_order,
            old_wallet,
            new_wallet,
            req.update_auth.statement_sig,
        )
        .map_err(bad_request)?;

        // Check rate limits and enqueue the task
        self.rate_limiter.check_rate_limit(wallet_id).await?;
        let task_id = append_task_and_await(task.into(), &self.state).await?;

        Ok(UpdateOrderResponse { task_id })
    }
}

/// Handler for the POST /wallet/:id/orders/:id/cancel route
pub struct CancelOrderHandler {
    /// A copy of the relayer-global state
    state: State,
    /// The per-wallet task rate limiter
    rate_limiter: WalletTaskRateLimiter,
}

impl CancelOrderHandler {
    /// Constructor
    pub fn new(state: State, rate_limiter: WalletTaskRateLimiter) -> Self {
        Self { state, rate_limiter }
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
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let wallet_id = parse_wallet_id_from_params(&params)?;
        let order_id = parse_order_id_from_params(&params)?;

        // Lookup the wallet in the global state
        let old_wallet = find_wallet_for_update(wallet_id, &self.state).await?;
        let mut new_wallet = old_wallet.clone();
        maybe_rotate_root_key(&req.update_auth, &mut new_wallet)?;

        // Remove the order from the new wallet
        let order = new_wallet
            .remove_order(&order_id)
            .ok_or_else(|| not_found(ERR_ORDER_NOT_FOUND.to_string()))?;
        new_wallet.reblind_wallet();

        let task = UpdateWalletTaskDescriptor::new_order_cancellation(
            order.clone(),
            old_wallet,
            new_wallet,
            req.update_auth.statement_sig,
        )
        .map_err(bad_request)?;

        // Check rate limits and enqueue the task
        self.rate_limiter.check_rate_limit(wallet_id).await?;
        let task_id = append_task_and_await(task.into(), &self.state).await?;

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
    pub state: State,
}

impl GetBalancesHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
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
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let wallet_id = parse_wallet_id_from_params(&params)?;
        if let Some(mut wallet) = self.state.get_wallet(&wallet_id).await? {
            // Filter out the default balances used to pad the wallet to the circuit size
            wallet.remove_default_elements();
            let balances = wallet.get_balances_list().to_vec();

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
    pub state: State,
}

impl GetBalanceByMintHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
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
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let wallet_id = parse_wallet_id_from_params(&params)?;
        let mint = parse_mint_from_params(&params)?;

        if let Some(wallet) = self.state.get_wallet(&wallet_id).await? {
            let balance =
                wallet.get_balance(&mint).cloned().unwrap_or_else(|| Balance::new_from_mint(mint));
            Ok(GetBalanceByMintResponse { balance })
        } else {
            Err(not_found(ERR_WALLET_NOT_FOUND.to_string()))
        }
    }
}

/// Handler for the POST /wallet/:id/balances/deposit route
pub struct DepositBalanceHandler {
    /// The minimum deposit amount allowed by the relayer
    min_deposit_amount: f64,
    /// The URL of the compliance service to use for wallet screening
    compliance_client: ComplianceServerClient,
    /// A copy of the relayer-global state
    state: State,
    /// The per-wallet task rate limiter
    rate_limiter: WalletTaskRateLimiter,
    /// The price streams from the price reporter
    price_streams: PriceStreamStates,
}

impl DepositBalanceHandler {
    /// Constructor
    pub fn new(
        min_deposit_amount: f64,
        compliance_url: Option<String>,
        state: State,
        rate_limiter: WalletTaskRateLimiter,
        price_streams: PriceStreamStates,
    ) -> Self {
        let compliance_client = ComplianceServerClient::new(compliance_url);
        Self { min_deposit_amount, compliance_client, state, rate_limiter, price_streams }
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
        // Screen the wallet for compliance
        let addr = biguint_to_hex_addr(&req.from_addr);
        if !self.compliance_client.check_address(&addr).await? {
            return Err(bad_request(ERR_SCREENED_OUT_ADDRESS));
        }

        // Check that the deposit amount is above the minimum allowed
        let deposit_amount = req.amount.to_u128().unwrap();
        let maybe_deposit_value =
            get_usdc_denominated_value(&req.mint, deposit_amount, &self.price_streams)?;

        // If we are unable to fetch a price, do not block the deposit
        if let Some(deposit_value) = maybe_deposit_value {
            if deposit_value < self.min_deposit_amount {
                return Err(bad_request(ERR_MIN_DEPOSIT_AMOUNT.to_string()));
            }
        }

        // Parse the wallet ID from the params
        let wallet_id = parse_wallet_id_from_params(&params)?;

        // Lookup the old wallet by id
        let old_wallet = find_wallet_for_update(wallet_id, &self.state).await?;
        let mut new_wallet = old_wallet.clone();
        maybe_rotate_root_key(&req.update_auth, &mut new_wallet)?;

        // Apply the balance update to the old wallet to get the new wallet
        let bal = Balance::new_from_mint_and_amount(req.mint.clone(), deposit_amount);

        new_wallet.add_balance(bal).map_err(bad_request)?;
        new_wallet.reblind_wallet();

        let deposit_with_auth = ExternalTransferWithAuth::deposit(
            req.from_addr,
            req.mint,
            deposit_amount,
            DepositAuth {
                permit_nonce: req.permit_nonce,
                permit_deadline: req.permit_deadline,
                permit_signature: req.permit_signature,
            },
        );

        let task = UpdateWalletTaskDescriptor::new_deposit(
            deposit_with_auth,
            old_wallet,
            new_wallet,
            req.update_auth.statement_sig,
        )
        .map_err(bad_request)?;

        // Check rate limits and enqueue the task
        self.rate_limiter.check_rate_limit(wallet_id).await?;
        let task_id = append_task_and_await(task.into(), &self.state).await?;

        Ok(DepositBalanceResponse { task_id })
    }
}

/// Handler for the POST /wallet/:id/balances/:mint/withdraw route
pub struct WithdrawBalanceHandler {
    /// The minimum withdrawal amount allowed by the relayer
    min_withdrawal_amount: f64,
    /// A copy of the relayer-global state
    state: State,
    /// The per-wallet task rate limiter
    rate_limiter: WalletTaskRateLimiter,
    /// The price streams from the price reporter
    price_streams: PriceStreamStates,
}

impl WithdrawBalanceHandler {
    /// Constructor
    pub fn new(
        min_withdrawal_amount: f64,
        state: State,
        rate_limiter: WalletTaskRateLimiter,
        price_streams: PriceStreamStates,
    ) -> Self {
        Self { min_withdrawal_amount, state, rate_limiter, price_streams }
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
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        // Parse the wallet ID and mint from the params
        let wallet_id = parse_wallet_id_from_params(&params)?;
        let mint = parse_mint_from_params(&params)?;

        // Lookup the wallet in the global state
        let old_wallet = find_wallet_for_update(wallet_id, &self.state).await?;
        let mut new_wallet = old_wallet.clone();
        maybe_rotate_root_key(&req.update_auth, &mut new_wallet)?;

        // Check that fees are paid for the wallet
        if old_wallet.has_outstanding_fees() {
            return Err(bad_request(ERR_WITHDRAW_NONZERO_FEES.to_string()));
        }

        // Apply the withdrawal to the wallet
        let withdrawal_amount = req.amount.to_u128().unwrap();
        new_wallet.withdraw(&mint, withdrawal_amount).map_err(bad_request)?;
        new_wallet.reblind_wallet();

        // Check that the withdrawal amount is above the minimum allowed or withdraws
        // the entire balance if it is not
        let maybe_withdrawal_value =
            get_usdc_denominated_value(&mint, withdrawal_amount, &self.price_streams)?;

        // If we are unable to fetch a price, do not block the withdrawal
        let new_balance = new_wallet.get_balance(&mint).unwrap();
        if let Some(withdrawal_value) = maybe_withdrawal_value {
            if withdrawal_value < self.min_withdrawal_amount && new_balance.amount > 0 {
                return Err(bad_request(ERR_MIN_WITHDRAWAL_AMOUNT.to_string()));
            }
        }

        // Create the withdrawal task
        let withdrawal_with_auth = ExternalTransferWithAuth::withdrawal(
            req.destination_addr,
            mint,
            withdrawal_amount,
            WithdrawalAuth { external_transfer_signature: req.external_transfer_sig },
        );

        let task = UpdateWalletTaskDescriptor::new_withdrawal(
            withdrawal_with_auth,
            old_wallet,
            new_wallet,
            req.update_auth.statement_sig,
        )
        .map_err(bad_request)?;

        // Check rate limits and enqueue the task
        self.rate_limiter.check_rate_limit(wallet_id).await?;
        let task_id = append_task_and_await(task.into(), &self.state).await?;

        Ok(WithdrawBalanceResponse { task_id })
    }
}

/// Handler for the POST /wallet/:id/redeem-note route
pub struct RedeemNoteHandler {
    /// A copy of the relayer-global state
    state: State,
    /// The per-wallet task rate limiter
    rate_limiter: WalletTaskRateLimiter,
}

impl RedeemNoteHandler {
    /// Constructor
    pub fn new(state: State, rate_limiter: WalletTaskRateLimiter) -> Self {
        Self { state, rate_limiter }
    }
}

#[async_trait]
impl TypedHandler for RedeemNoteHandler {
    type Request = RedeemNoteRequest;
    type Response = RedeemNoteResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        req: Self::Request,
        params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let wallet_id = parse_wallet_id_from_params(&params)?;

        // Lookup the wallet in the global state, then verify that the note _can_ be
        // redeemed into the wallet
        let mut old_wallet = find_wallet_for_update(wallet_id, &self.state).await?;
        let bal = req.note.as_balance();
        old_wallet.add_balance(bal).map_err(bad_request)?;

        let task = RedeemFeeTaskDescriptor::new(wallet_id, req.note, req.decryption_key);

        // Check rate limits and enqueue the task
        self.rate_limiter.check_rate_limit(wallet_id).await?;
        let task_id = append_task_and_await(task.into(), &self.state).await?;

        Ok(RedeemNoteResponse { task_id })
    }
}

// ----------------------
// | Fee Route Handlers |
// ----------------------

/// The handler for the `/wallet/:id/pay-fees` route
///
/// Note that we do not rate limit the endpoint, fees must always be payable
#[derive(Clone)]
pub struct PayFeesHandler {
    /// A copy of the relayer-global state
    state: State,
}

impl PayFeesHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[async_trait]
impl TypedHandler for PayFeesHandler {
    type Request = EmptyRequestResponse;
    type Response = PayFeesResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let wallet_id = parse_wallet_id_from_params(&params)?;
        let wallet = find_wallet_for_update(wallet_id, &self.state).await?;

        // Pay all fees in the wallet
        let mut tasks = Vec::new();
        for (_mint, balance) in wallet.balances.iter() {
            if balance.relayer_fee_balance > 0 {
                let task = PayOfflineFeeTaskDescriptor::new_relayer_fee(wallet_id, balance.clone())
                    .expect("infallible");
                let task_id = append_task_and_await(task.into(), &self.state).await?;
                tasks.push(task_id);
            }

            if balance.protocol_fee_balance > 0 {
                let task =
                    PayOfflineFeeTaskDescriptor::new_protocol_fee(wallet_id, balance.clone())
                        .expect("infallible");
                let task_id = append_task_and_await(task.into(), &self.state).await?;
                tasks.push(task_id);
            }
        }

        Ok(PayFeesResponse { task_ids: tasks })
    }
}

// --------------------------------
// | Order History Route Handlers |
// --------------------------------

/// The handler for the `/wallet/:id/order-history` route
#[derive(Clone)]
pub struct GetOrderHistoryHandler {
    /// A copy of the relayer-global state
    state: State,
}

impl GetOrderHistoryHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[async_trait]
impl TypedHandler for GetOrderHistoryHandler {
    type Request = EmptyRequestResponse;
    type Response = GetOrderHistoryResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
        mut query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        if !self.state.historical_state_enabled()? {
            return Err(bad_request(ERR_HISTORICAL_STATE_DISABLED));
        }

        let wallet_id = parse_wallet_id_from_params(&params)?;
        let len = query_params
            .remove(ORDER_HISTORY_LEN_PARAM)
            .map(|x| x.parse::<usize>())
            .transpose()
            .map_err(bad_request)?
            .unwrap_or(DEFAULT_ORDER_HISTORY_LEN);

        let orders = self.state.get_order_history(len, &wallet_id).await.map_err(internal_error)?;
        Ok(GetOrderHistoryResponse { orders, pagination_token: None })
    }
}
