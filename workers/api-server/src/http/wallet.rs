//! Groups wallet API handlers and definitions

use async_trait::async_trait;
use circuit_types::{
    balance::Balance, native_helpers::create_wallet_shares_from_private, order::Order,
    SizedWallet as SizedCircuitWallet,
};
use common::types::{
    tasks::{
        LookupWalletTaskDescriptor, NewWalletTaskDescriptor, TaskDescriptor, TaskIdentifier,
        UpdateWalletTaskDescriptor,
    },
    transfer_auth::{DepositAuth, ExternalTransferWithAuth, WithdrawalAuth},
    wallet::{KeyChain, Wallet, WalletIdentifier},
};
use external_api::{
    http::wallet::{
        CancelOrderRequest, CancelOrderResponse, CreateOrderRequest, CreateOrderResponse,
        CreateWalletRequest, CreateWalletResponse, DepositBalanceRequest, DepositBalanceResponse,
        FindWalletRequest, FindWalletResponse, GetBalanceByMintResponse, GetBalancesResponse,
        GetOrderByIdResponse, GetOrdersResponse, GetWalletResponse, UpdateOrderRequest,
        UpdateOrderResponse, WithdrawBalanceRequest, WithdrawBalanceResponse,
    },
    types::ApiOrder,
    EmptyRequestResponse,
};
use hyper::HeaderMap;
use num_traits::ToPrimitive;
use renegade_crypto::fields::biguint_to_scalar;
use state::State;
use util::{err_str, hex::jubjub_to_hex_string};

use crate::{
    error::{bad_request, internal_error, not_found, ApiServerError},
    router::{TypedHandler, UrlParams, ERR_WALLET_NOT_FOUND},
};

use super::{parse_mint_from_params, parse_order_id_from_params, parse_wallet_id_from_params};

// -----------
// | Helpers |
// -----------

/// Find the wallet for the given id in the global state
///
/// Attempts to acquire the lock for an update on the wallet
fn find_wallet_for_update(
    wallet_id: WalletIdentifier,
    state: &State,
) -> Result<Wallet, ApiServerError> {
    // Find the wallet in global state and use its keys to authenticate the request
    state.get_wallet(&wallet_id)?.ok_or_else(|| not_found(ERR_WALLET_NOT_FOUND.to_string()))
}

/// Append a task to a task queue and await consensus on this queue update
async fn append_task_and_await(
    task: TaskDescriptor,
    state: &State,
) -> Result<TaskIdentifier, ApiServerError> {
    let (task_id, waiter) = state.append_task(task)?;
    waiter.await.map_err(err_str!(internal_error))?;

    Ok(task_id)
}

// ------------------
// | Error Messages |
// ------------------

/// Error message displayed when a balance is insufficient to transfer the
/// requested amount
const ERR_INSUFFICIENT_BALANCE: &str = "insufficient balance";
/// Error message displayed when a given order cannot be found
const ERR_ORDER_NOT_FOUND: &str = "order not found";

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

        // Filter out empty orders, balances
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
        mut req: Self::Request,
        _params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        // Overwrite the managing cluster and the match fee with the configured values
        let relayer_key = self.global_state.get_fee_decryption_key()?.public_key();
        let relayer_take_rate = self.global_state.get_relayer_take_rate()?;
        req.wallet.managing_cluster = jubjub_to_hex_string(&relayer_key);
        req.wallet.match_fee = relayer_take_rate;

        // Create an async task to drive this new wallet into the on-chain state
        // and create proofs of validity
        let wallet_id = req.wallet.id;
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
        let task = NewWalletTaskDescriptor::new(wallet).map_err(bad_request)?;

        // Propose the task and await for it to be enqueued
        let task_id = append_task_and_await(task.into(), &self.global_state).await?;
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

        let blinder_seed = biguint_to_scalar(&req.blinder_seed);
        let share_seed = biguint_to_scalar(&req.secret_share_seed);
        let task =
            LookupWalletTaskDescriptor::new(req.wallet_id, blinder_seed, share_seed, key_chain)
                .map_err(bad_request)?;

        // Propose the task and await for it to be enqueued
        let task_id = append_task_and_await(task.into(), &self.global_state).await?;

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
        new_wallet.add_order(id, new_order).map_err(bad_request)?;
        new_wallet.reblind_wallet();

        let task = UpdateWalletTaskDescriptor::new(
            None, // transfer
            old_wallet,
            new_wallet,
            req.statement_sig,
        )
        .map_err(bad_request)?;

        // Propose the task and await for it to be enqueued
        let task_id = append_task_and_await(task.into(), &self.global_state).await?;
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

        let task = UpdateWalletTaskDescriptor::new(
            None, // transfer
            old_wallet,
            new_wallet,
            req.statement_sig,
        )
        .map_err(bad_request)?;

        // Propose the task and await for it to be enqueued
        let task_id = append_task_and_await(task.into(), &self.global_state).await?;
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
            .remove_order(&order_id)
            .ok_or_else(|| not_found(ERR_ORDER_NOT_FOUND.to_string()))?;
        new_wallet.reblind_wallet();

        let task = UpdateWalletTaskDescriptor::new(
            None, // transfer
            old_wallet,
            new_wallet,
            req.statement_sig,
        )
        .map_err(bad_request)?;

        // Propose the task and await for it to be enqueued
        let task_id = append_task_and_await(task.into(), &self.global_state).await?;
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
        let amount = req.amount.to_u128().unwrap();
        let bal = Balance::new_from_mint_and_amount(req.mint.clone(), amount);

        new_wallet.add_balance(bal).map_err(bad_request)?;
        new_wallet.reblind_wallet();

        let deposit_with_auth = ExternalTransferWithAuth::deposit(
            req.from_addr,
            req.mint,
            amount,
            DepositAuth {
                permit_nonce: req.permit_nonce,
                permit_deadline: req.permit_deadline,
                permit_signature: req.permit_signature,
            },
        );

        let task = UpdateWalletTaskDescriptor::new(
            Some(deposit_with_auth),
            old_wallet,
            new_wallet,
            req.wallet_commitment_sig,
        )
        .map_err(bad_request)?;

        // Propose the task and await for it to be enqueued
        let task_id = append_task_and_await(task.into(), &self.global_state).await?;
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
        let withdrawal_amount = req.amount.to_u128().unwrap();

        let mut new_wallet = old_wallet.clone();
        if let Some(balance) = new_wallet.balances.get_mut(&mint)
            && balance.amount >= withdrawal_amount
        {
            balance.amount -= withdrawal_amount;
        } else {
            return Err(bad_request(ERR_INSUFFICIENT_BALANCE.to_string()));
        }
        new_wallet.reblind_wallet();

        let withdrawal_with_auth = ExternalTransferWithAuth::withdrawal(
            req.destination_addr,
            mint,
            withdrawal_amount,
            WithdrawalAuth { external_transfer_signature: req.external_transfer_sig },
        );

        let task = UpdateWalletTaskDescriptor::new(
            Some(withdrawal_with_auth),
            old_wallet,
            new_wallet,
            req.wallet_commitment_sig,
        )
        .map_err(bad_request)?;

        // Propose the task and await for it to be enqueued
        let task_id = append_task_and_await(task.into(), &self.global_state).await?;
        Ok(WithdrawBalanceResponse { task_id })
    }
}
