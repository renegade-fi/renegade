//! Groups wallet API handlers and definitions

use async_trait::async_trait;
use circuits::types::{
    balance::Balance as StateBalance,
    transfers::{ExternalTransfer, ExternalTransferDirection},
};
use crossbeam::channel::Sender as CrossbeamSender;
use crypto::fields::biguint_to_scalar;
use hyper::{HeaderMap, StatusCode};
use itertools::Itertools;
use num_traits::ToPrimitive;
use tokio::sync::mpsc::UnboundedSender as TokioSender;

use crate::{
    api_server::{
        error::ApiServerError,
        http::parse_index_from_params,
        router::{TypedHandler, UrlParams, ERR_WALLET_NOT_FOUND},
    },
    external_api::{
        http::wallet::{
            AddFeeRequest, AddFeeResponse, CancelOrderResponse, CreateOrderRequest,
            CreateOrderResponse, CreateWalletRequest, CreateWalletResponse, DepositBalanceRequest,
            DepositBalanceResponse, FindWalletRequest, FindWalletResponse,
            GetBalanceByMintResponse, GetBalancesResponse, GetFeesResponse, GetOrderByIdResponse,
            GetOrdersResponse, GetWalletResponse, RemoveFeeRequest, RemoveFeeResponse,
            WithdrawBalanceRequest, WithdrawBalanceResponse,
        },
        types::{Balance as ApiBalance, Fee as ApiFee, Order as ApiOrder},
        EmptyRequestResponse,
    },
    gossip_api::gossip::GossipOutbound,
    proof_generation::jobs::ProofManagerJob,
    starknet_client::client::StarknetClient,
    state::RelayerState,
    tasks::{
        create_new_wallet::NewWalletTask, driver::TaskDriver, lookup_wallet::LookupWalletTask,
        update_wallet::UpdateWalletTask,
    },
    MAX_FEES, MAX_ORDERS,
};

use super::{parse_mint_from_params, parse_order_id_from_params, parse_wallet_id_from_params};

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

/// Error message displayed when a balance is insufficient to transfer the requested amount
const ERR_INSUFFICIENT_BALANCE: &str = "insufficient balance";
/// Error message displayed when a given order cannot be found
const ERR_ORDER_NOT_FOUND: &str = "order not found";
/// Error message displayed when `MAX_ORDERS` is exceeded
const ERR_ORDERS_FULL: &str = "wallet's orderbook is full";
/// The error message to display when a fee list is full
const ERR_FEES_FULL: &str = "wallet's fee list is full";
/// The error message to display when a fee index is out of range
const ERR_FEE_OUT_OF_RANGE: &str = "fee index out of range";

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
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        let wallet_id = parse_wallet_id_from_params(&params)?;
        let mut wallet = if let Some(wallet) = self
            .global_state
            .read_wallet_index()
            .await
            .get_wallet(&wallet_id)
            .await
        {
            wallet
        } else {
            return Err(ApiServerError::HttpStatusCode(
                StatusCode::NOT_FOUND,
                ERR_WALLET_NOT_FOUND.to_string(),
            ));
        };

        // Filter out empty orders, balances, and fees
        wallet.orders = wallet
            .orders
            .into_iter()
            .filter(|(_id, order)| !order.is_default())
            .map(|(id, order)| (id, order))
            .collect();
        wallet.balances = wallet
            .balances
            .into_iter()
            .filter(|(_mint, balance)| !balance.is_default())
            .map(|(mint, balance)| (mint, balance))
            .collect();
        wallet.fees.retain(|fee| !fee.is_default());

        Ok(GetWalletResponse {
            wallet: wallet.into(),
        })
    }
}

/// Handler for the POST /wallet route
pub struct CreateWalletHandler {
    /// A starknet client
    starknet_client: StarknetClient,
    /// A copy of the relayer-global state
    global_state: RelayerState,
    /// A sender to the proof manager's work queue, used to enqueue
    /// proofs of `VALID NEW WALLET` and await their completion
    proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    /// A copy of the task driver used to create an manage long-lived
    /// async workflows
    task_driver: TaskDriver,
}

impl CreateWalletHandler {
    /// Constructor
    pub fn new(
        starknet_client: StarknetClient,
        global_state: RelayerState,
        proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
        task_driver: TaskDriver,
    ) -> Self {
        Self {
            starknet_client,
            global_state,
            proof_manager_work_queue,
            task_driver,
        }
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
        let task = NewWalletTask::new(
            wallet_id,
            req.wallet,
            self.starknet_client.clone(),
            self.global_state.clone(),
            self.proof_manager_work_queue.clone(),
        );
        let task_id = self.task_driver.start_task(task).await;

        Ok(CreateWalletResponse { wallet_id, task_id })
    }
}

/// Handler for the POST /wallet route
pub struct FindWalletHandler {
    /// A starknet client
    starknet_client: StarknetClient,
    /// A sender to the network manager's work queue
    network_sender: TokioSender<GossipOutbound>,
    /// A copy of the relayer-global state
    global_state: RelayerState,
    /// A sender to the proof manager's work queue, used to enqueue
    /// proofs of `VALID NEW WALLET` and await their completion
    proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    /// A copy of the task driver used to create an manage long-lived
    /// async workflows
    task_driver: TaskDriver,
}

impl FindWalletHandler {
    /// Constructor
    pub fn new(
        starknet_client: StarknetClient,
        network_sender: TokioSender<GossipOutbound>,
        global_state: RelayerState,
        proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
        task_driver: TaskDriver,
    ) -> Self {
        Self {
            starknet_client,
            network_sender,
            global_state,
            proof_manager_work_queue,
            task_driver,
        }
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
        let task = LookupWalletTask::new(
            req.wallet_id,
            biguint_to_scalar(&req.blinder_seed),
            biguint_to_scalar(&req.secret_share_seed),
            req.key_chain,
            self.starknet_client.clone(),
            self.network_sender.clone(),
            self.global_state.clone(),
            self.proof_manager_work_queue.clone(),
        );
        let task_id = self.task_driver.start_task(task).await;

        Ok(FindWalletResponse {
            wallet_id: req.wallet_id,
            task_id,
        })
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
        _headers: HeaderMap,
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
            // Filter out default orders used to pad the wallet to the circuit size
            let non_default_orders = wallet
                .orders
                .into_iter()
                .filter(|(_id, order)| !order.is_default())
                .map(ApiOrder::from)
                .collect_vec();

            Ok(GetOrdersResponse {
                orders: non_default_orders,
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
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        let wallet_id = parse_wallet_id_from_params(&params)?;
        let order_id = parse_order_id_from_params(&params)?;

        // Find the wallet in global state and use its keys to authenticate the request
        let wallet = self
            .global_state
            .read_wallet_index()
            .await
            .get_wallet(&wallet_id)
            .await
            .ok_or_else(|| {
                ApiServerError::HttpStatusCode(
                    StatusCode::NOT_FOUND,
                    ERR_WALLET_NOT_FOUND.to_string(),
                )
            })?;

        if let Some(order) = wallet.orders.get(&order_id).cloned() {
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

/// Handler for the POST /wallet/:id/orders route
pub struct CreateOrderHandler {
    /// A starknet client
    starknet_client: StarknetClient,
    /// A sender to the network manager's work queue
    network_sender: TokioSender<GossipOutbound>,
    /// A copy of the relayer-global state
    global_state: RelayerState,
    /// A sender to the proof manager's work queue, used to enqueue
    /// proofs of `VALID NEW WALLET` and await their completion
    proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    /// A copy of the task driver used for long-lived async workflows
    task_driver: TaskDriver,
}

impl CreateOrderHandler {
    /// Constructor
    pub fn new(
        starknet_client: StarknetClient,
        network_sender: TokioSender<GossipOutbound>,
        global_state: RelayerState,
        proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
        task_driver: TaskDriver,
    ) -> Self {
        Self {
            starknet_client,
            network_sender,
            global_state,
            proof_manager_work_queue,
            task_driver,
        }
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
        let old_wallet = self
            .global_state
            .read_wallet_index()
            .await
            .get_wallet(&wallet_id)
            .await
            .ok_or_else(|| {
                ApiServerError::HttpStatusCode(
                    StatusCode::NOT_FOUND,
                    ERR_WALLET_NOT_FOUND.to_string(),
                )
            })?;

        // Ensure that there is space below MAX_ORDERS for the new order
        let num_orders = old_wallet
            .orders
            .values()
            .filter(|order| !order.is_default())
            .count();

        if num_orders >= MAX_ORDERS {
            return Err(ApiServerError::HttpStatusCode(
                StatusCode::BAD_REQUEST,
                ERR_ORDERS_FULL.to_string(),
            ));
        }

        // Add the order to the new wallet
        let mut new_wallet = old_wallet.clone();
        new_wallet.orders.insert(id, req.order.into());
        new_wallet.orders.retain(|_id, order| !order.is_default());

        // Spawn a task to handle the order creation flow
        let task = UpdateWalletTask::new(
            None, /* external_transfer */
            old_wallet,
            new_wallet,
            self.starknet_client.clone(),
            self.network_sender.clone(),
            self.global_state.clone(),
            self.proof_manager_work_queue.clone(),
        );
        let task_id = self.task_driver.start_task(task).await;

        Ok(CreateOrderResponse { id, task_id })
    }
}

/// Handler for the POST /wallet/:id/orders/:id/cancel route
pub struct CancelOrderHandler {
    /// A starknet client
    starknet_client: StarknetClient,
    /// A sender to the network manager's work queue
    network_sender: TokioSender<GossipOutbound>,
    /// A copy of the relayer-global state
    global_state: RelayerState,
    /// A sender to the proof manager's work queue, used to enqueue
    /// proofs of `VALID NEW WALLET` and await their completion
    proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    /// A copy of the task driver used for long-lived async workflows
    task_driver: TaskDriver,
}

impl CancelOrderHandler {
    /// Constructor
    pub fn new(
        starknet_client: StarknetClient,
        network_sender: TokioSender<GossipOutbound>,
        global_state: RelayerState,
        proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
        task_driver: TaskDriver,
    ) -> Self {
        Self {
            starknet_client,
            network_sender,
            global_state,
            proof_manager_work_queue,
            task_driver,
        }
    }
}

#[async_trait]
impl TypedHandler for CancelOrderHandler {
    type Request = EmptyRequestResponse;
    type Response = CancelOrderResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        let wallet_id = parse_wallet_id_from_params(&params)?;
        let order_id = parse_order_id_from_params(&params)?;

        // Lookup the wallet in the global state
        let old_wallet = self
            .global_state
            .read_wallet_index()
            .await
            .get_wallet(&wallet_id)
            .await
            .ok_or_else(|| {
                ApiServerError::HttpStatusCode(
                    StatusCode::NOT_FOUND,
                    ERR_WALLET_NOT_FOUND.to_string(),
                )
            })?;

        // Remove the order from the new wallet
        let mut new_wallet = old_wallet.clone();
        let order = new_wallet.orders.remove(&order_id).ok_or_else(|| {
            ApiServerError::HttpStatusCode(StatusCode::NOT_FOUND, ERR_ORDER_NOT_FOUND.to_string())
        })?;

        // Spawn a task to handle the order creation flow
        let task = UpdateWalletTask::new(
            None, /* external_transfer */
            old_wallet,
            new_wallet,
            self.starknet_client.clone(),
            self.network_sender.clone(),
            self.global_state.clone(),
            self.proof_manager_work_queue.clone(),
        );
        let task_id = self.task_driver.start_task(task).await;

        Ok(CancelOrderResponse {
            task_id,
            order: (order_id, order).into(),
        })
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
        _headers: HeaderMap,
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
            // Filter out the default balances used to pad the wallet to the circuit size
            let non_default_balances = wallet
                .balances
                .into_values()
                .filter(|balance| !balance.is_default())
                .map(ApiBalance::from)
                .collect_vec();

            Ok(GetBalancesResponse {
                balances: non_default_balances,
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
        _headers: HeaderMap,
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
                .unwrap_or_else(|| ApiBalance {
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

/// Handler for the POST /wallet/:id/balances/deposit route
pub struct DepositBalanceHandler {
    /// A starknet client
    starknet_client: StarknetClient,
    /// A sender to the network manager's work queue
    network_sender: TokioSender<GossipOutbound>,
    /// A copy of the relayer-global state
    global_state: RelayerState,
    /// A sender to the proof manager's work queue, used to enqueue
    /// proofs of `VALID NEW WALLET` and await their completion
    proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    /// A copy of the task driver used for long-lived async workflows
    task_driver: TaskDriver,
}

impl DepositBalanceHandler {
    /// Constructor
    pub fn new(
        starknet_client: StarknetClient,
        network_sender: TokioSender<GossipOutbound>,
        global_state: RelayerState,
        proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
        task_driver: TaskDriver,
    ) -> Self {
        Self {
            starknet_client,
            network_sender,
            global_state,
            proof_manager_work_queue,
            task_driver,
        }
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
        let old_wallet = self
            .global_state
            .read_wallet_index()
            .await
            .get_wallet(&wallet_id)
            .await
            .ok_or_else(|| {
                ApiServerError::HttpStatusCode(
                    StatusCode::NOT_FOUND,
                    ERR_WALLET_NOT_FOUND.to_string(),
                )
            })?;

        // Apply the balance update to the old wallet to get the new wallet
        let mut new_wallet = old_wallet.clone();
        new_wallet
            .balances
            .entry(req.mint.clone())
            .or_insert(StateBalance {
                mint: req.mint.clone(),
                amount: 0u64,
            })
            .amount += req.amount.to_u64().unwrap();

        // Begin an update-wallet task
        let task = UpdateWalletTask::new(
            Some(ExternalTransfer {
                account_addr: req.from_addr,
                mint: req.mint,
                amount: req.amount,
                direction: ExternalTransferDirection::Deposit,
            }),
            old_wallet,
            new_wallet,
            self.starknet_client.clone(),
            self.network_sender.clone(),
            self.global_state.clone(),
            self.proof_manager_work_queue.clone(),
        );
        let task_id = self.task_driver.start_task(task).await;

        Ok(DepositBalanceResponse { task_id })
    }
}

/// Handler for the POST /wallet/:id/balances/:mint/withdraw route
pub struct WithdrawBalanceHandler {
    /// A starknet client
    starknet_client: StarknetClient,
    /// A sender to the network manager's work queue
    network_sender: TokioSender<GossipOutbound>,
    /// A copy of the relayer-global state
    global_state: RelayerState,
    /// A sender to the proof manager's work queue, used to enqueue
    /// proofs of `VALID NEW WALLET` and await their completion
    proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    /// A copy of the task driver used for long-lived async workflows
    task_driver: TaskDriver,
}

impl WithdrawBalanceHandler {
    /// Constructor
    pub fn new(
        starknet_client: StarknetClient,
        network_sender: TokioSender<GossipOutbound>,
        global_state: RelayerState,
        proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
        task_driver: TaskDriver,
    ) -> Self {
        Self {
            starknet_client,
            network_sender,
            global_state,
            proof_manager_work_queue,
            task_driver,
        }
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
        let old_wallet = self
            .global_state
            .read_wallet_index()
            .await
            .get_wallet(&wallet_id)
            .await
            .ok_or_else(|| {
                ApiServerError::HttpStatusCode(
                    StatusCode::NOT_FOUND,
                    ERR_WALLET_NOT_FOUND.to_string(),
                )
            })?;

        // Apply the withdrawal to the wallet
        let withdrawal_amount = req.amount.to_u64().unwrap();

        let mut new_wallet = old_wallet.clone();
        if let Some(balance) = new_wallet.balances.get_mut(&mint)
        && balance.amount >= withdrawal_amount {
            balance.amount -= withdrawal_amount;
        } else {
            return Err(ApiServerError::HttpStatusCode(
                StatusCode::BAD_REQUEST, ERR_INSUFFICIENT_BALANCE.to_string()
            ));
        }

        // Begin a task
        let task = UpdateWalletTask::new(
            Some(ExternalTransfer {
                account_addr: req.destination_addr,
                mint,
                amount: req.amount,
                direction: ExternalTransferDirection::Withdrawal,
            }),
            old_wallet,
            new_wallet,
            self.starknet_client.clone(),
            self.network_sender.clone(),
            self.global_state.clone(),
            self.proof_manager_work_queue.clone(),
        );
        let task_id = self.task_driver.start_task(task).await;

        Ok(WithdrawBalanceResponse { task_id })
    }
}

// ----------------------
// | Fee Route Handlers |
// ----------------------

/// Handler for the GET /wallet/:id/fees route
#[derive(Clone, Debug)]
pub struct GetFeesHandler {
    /// A copy of the relayer-global state
    global_state: RelayerState,
}

impl GetFeesHandler {
    /// Constructor
    pub fn new(global_state: RelayerState) -> Self {
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

        if let Some(wallet) = self
            .global_state
            .read_wallet_index()
            .await
            .get_wallet(&wallet_id)
            .await
        {
            // Filter out all the default fees used to pad the wallet to the circuit size
            let non_default_fees = wallet
                .fees
                .into_iter()
                .filter(|fee| !fee.is_default())
                .map(ApiFee::from)
                .collect_vec();

            Ok(GetFeesResponse {
                fees: non_default_fees,
            })
        } else {
            Err(ApiServerError::HttpStatusCode(
                StatusCode::NOT_FOUND,
                ERR_WALLET_NOT_FOUND.to_string(),
            ))
        }
    }
}

/// Handler for the POST /wallet/:id/fees route
pub struct AddFeeHandler {
    /// A starknet client
    starknet_client: StarknetClient,
    /// A sender to the network manager's work queue
    network_sender: TokioSender<GossipOutbound>,
    /// A copy of the relayer-global state
    global_state: RelayerState,
    /// A sender to the proof manager's work queue, used to enqueue
    /// proofs of `VALID NEW WALLET` and await their completion
    proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    /// A copy of the task driver used for long-lived async workflows
    task_driver: TaskDriver,
}

impl AddFeeHandler {
    /// Constructor
    pub fn new(
        starknet_client: StarknetClient,
        network_sender: TokioSender<GossipOutbound>,
        global_state: RelayerState,
        proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
        task_driver: TaskDriver,
    ) -> Self {
        Self {
            starknet_client,
            network_sender,
            global_state,
            proof_manager_work_queue,
            task_driver,
        }
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
        let old_wallet = self
            .global_state
            .read_wallet_index()
            .await
            .get_wallet(&wallet_id)
            .await
            .ok_or_else(|| {
                ApiServerError::HttpStatusCode(
                    StatusCode::NOT_FOUND,
                    ERR_WALLET_NOT_FOUND.to_string(),
                )
            })?;

        // Ensure that the fees list is not full
        let num_fees = old_wallet
            .fees
            .iter()
            .filter(|fee| !fee.is_default())
            .count();
        if num_fees >= MAX_FEES {
            return Err(ApiServerError::HttpStatusCode(
                StatusCode::BAD_REQUEST,
                ERR_FEES_FULL.to_string(),
            ));
        }

        // Add the fee to the new wallet
        let mut new_wallet = old_wallet.clone();
        new_wallet.fees.push(req.fee.into());

        // Create a task to submit this update to the contract
        let task = UpdateWalletTask::new(
            None, /* external_transfer */
            old_wallet,
            new_wallet,
            self.starknet_client.clone(),
            self.network_sender.clone(),
            self.global_state.clone(),
            self.proof_manager_work_queue.clone(),
        );
        let task_id = self.task_driver.start_task(task).await;

        Ok(AddFeeResponse { task_id })
    }
}

/// Handler for the POST /wallet/:id/fees/:index/remove route
pub struct RemoveFeeHandler {
    /// A starknet client
    starknet_client: StarknetClient,
    /// A sender to the network manager's work queue
    network_sender: TokioSender<GossipOutbound>,
    /// A copy of the relayer-global state
    global_state: RelayerState,
    /// A sender to the proof manager's work queue, used to enqueue
    /// proofs of `VALID NEW WALLET` and await their completion
    proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    /// A copy of the task driver used for long-lived async workflows
    task_driver: TaskDriver,
}

impl RemoveFeeHandler {
    /// Constructor
    pub fn new(
        starknet_client: StarknetClient,
        network_sender: TokioSender<GossipOutbound>,
        global_state: RelayerState,
        proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
        task_driver: TaskDriver,
    ) -> Self {
        Self {
            starknet_client,
            network_sender,
            global_state,
            proof_manager_work_queue,
            task_driver,
        }
    }
}

#[async_trait]
impl TypedHandler for RemoveFeeHandler {
    type Request = RemoveFeeRequest;
    type Response = RemoveFeeResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        // Parse the wallet id and fee index from the URL params
        let wallet_id = parse_wallet_id_from_params(&params)?;
        let fee_index = parse_index_from_params(&params)?;

        // Lookup the wallet in the global state
        let old_wallet = self
            .global_state
            .read_wallet_index()
            .await
            .get_wallet(&wallet_id)
            .await
            .ok_or_else(|| {
                ApiServerError::HttpStatusCode(
                    StatusCode::NOT_FOUND,
                    ERR_WALLET_NOT_FOUND.to_string(),
                )
            })?;

        if fee_index >= old_wallet.fees.len() {
            return Err(ApiServerError::HttpStatusCode(
                StatusCode::NOT_FOUND,
                ERR_FEE_OUT_OF_RANGE.to_string(),
            ));
        }

        // Remove the fee from the old wallet
        let mut new_wallet = old_wallet.clone();
        let removed_fee = new_wallet.fees.remove(fee_index);

        // Start a task to submit this update to the contract
        let task = UpdateWalletTask::new(
            None, /* external_transfer */
            old_wallet,
            new_wallet,
            self.starknet_client.clone(),
            self.network_sender.clone(),
            self.global_state.clone(),
            self.proof_manager_work_queue.clone(),
        );
        let task_id = self.task_driver.start_task(task).await;

        Ok(RemoveFeeResponse {
            task_id,
            fee: removed_fee.into(),
        })
    }
}
