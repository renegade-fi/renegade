//! Groups wallet API handlers and definitions

use async_trait::async_trait;
use crossbeam::channel::Sender as CrossbeamSender;
use hyper::StatusCode;

use crate::{
    api_server::{
        error::ApiServerError,
        router::{TypedHandler, UrlParams},
    },
    external_api::{
        http::wallet::{
            CreateOrderRequest, CreateOrderResponse, CreateWalletRequest, CreateWalletResponse,
            GetBalanceByMintResponse, GetBalancesResponse, GetFeesResponse, GetOrderByIdResponse,
            GetOrdersResponse, GetWalletResponse,
        },
        types::{Balance, Wallet},
        EmptyRequestResponse,
    },
    proof_generation::jobs::ProofManagerJob,
    starknet_client::client::StarknetClient,
    state::RelayerState,
    tasks::{create_new_order::NewOrderTask, create_new_wallet::NewWalletTask},
};

use super::{parse_mint_from_params, parse_order_id_from_params, parse_wallet_id_from_params};

// ---------------
// | HTTP Routes |
// ---------------

/// Create a new wallet
pub(super) const CREATE_WALLET_ROUTE: &str = "/v0/wallet";
/// Returns the wallet information for the given id
pub(super) const GET_WALLET_ROUTE: &str = "/v0/wallet/:wallet_id";
/// Route to the orders of a given wallet
pub(super) const WALLET_ORDERS_ROUTE: &str = "/v0/wallet/:wallet_id/orders";
/// Returns a single order by the given identifier
pub(super) const GET_ORDER_BY_ID_ROUTE: &str = "/v0/wallet/:wallet_id/orders/:order_id";
/// Returns the balances within a given wallet
pub(super) const GET_BALANCES_ROUTE: &str = "/v0/wallet/:wallet_id/balances";
/// Returns the balance associated with the given mint
pub(super) const GET_BALANCE_BY_MINT_ROUTE: &str = "/v0/wallet/:wallet_id/balances/:mint";
/// Returns the fees within a given wallet
pub(super) const GET_FEES_ROUTE: &str = "/v0/wallet/:wallet_id/fees";

// ------------------
// | Error Messages |
// ------------------

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

/// Handler for the POST /wallet route
pub struct CreateWalletHandler {
    /// A starknet client
    starknet_client: StarknetClient,
    /// A copy of the relayer-global state
    global_state: RelayerState,
    /// A sender to the proof manager's work queue, used to enqueue
    /// proofs of `VALID NEW WALLET` and await their completion
    proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
}

impl CreateWalletHandler {
    /// Constructor
    pub fn new(
        starknet_client: StarknetClient,
        global_state: RelayerState,
        proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    ) -> Self {
        Self {
            starknet_client,
            global_state,
            proof_manager_work_queue,
        }
    }
}

#[async_trait]
impl TypedHandler for CreateWalletHandler {
    type Request = CreateWalletRequest;
    type Response = CreateWalletResponse;

    async fn handle_typed(
        &self,
        req: Self::Request,
        _params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        // Create an async task to drive this new wallet into the on-chain state
        // and create proofs of validity
        let id = req.wallet.id;
        let task = NewWalletTask::new(
            req.wallet.id,
            req.wallet,
            self.starknet_client.clone(),
            self.global_state.clone(),
            self.proof_manager_work_queue.clone(),
        );
        tokio::spawn(task.run());

        Ok(CreateWalletResponse { id })
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

/// Handler for the POST /wallet/:id/orders route
pub struct CreateOrderHandler {
    /// A starknet client
    starknet_client: StarknetClient,
    /// A copy of the relayer-global state
    global_state: RelayerState,
    /// A sender to the proof manager's work queue, used to enqueue
    /// proofs of `VALID NEW WALLET` and await their completion
    proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
}

impl CreateOrderHandler {
    /// Constructor
    pub fn new(
        starknet_client: StarknetClient,
        global_state: RelayerState,
        proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    ) -> Self {
        Self {
            starknet_client,
            global_state,
            proof_manager_work_queue,
        }
    }
}

#[async_trait]
impl TypedHandler for CreateOrderHandler {
    type Request = CreateOrderRequest;
    type Response = CreateOrderResponse;

    async fn handle_typed(
        &self,
        req: Self::Request,
        params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        let id = req.order.id;
        let wallet_id = parse_wallet_id_from_params(&params)?;

        // Spawn a task to handle the order creation flow
        let task = NewOrderTask::new(
            wallet_id,
            req.order,
            self.starknet_client.clone(),
            self.global_state.clone(),
            self.proof_manager_work_queue.clone(),
        );
        tokio::spawn(task.run());

        Ok(CreateOrderResponse { id })
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
            Ok(GetFeesResponse { fees: wallet.fees })
        } else {
            Err(ApiServerError::HttpStatusCode(
                StatusCode::NOT_FOUND,
                ERR_WALLET_NOT_FOUND.to_string(),
            ))
        }
    }
}
