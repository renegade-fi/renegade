//! Route handlers for balance operations

use alloy::primitives::Address;
use async_trait::async_trait;
use circuit_types::{Amount, baby_jubjub::BabyJubJubPoint, schnorr::SchnorrPublicKey};
use external_api::{
    EmptyRequestResponse,
    http::balance::{
        DepositBalanceRequest, DepositBalanceResponse, GetBalanceByMintResponse,
        GetBalancesResponse, WithdrawBalanceRequest, WithdrawBalanceResponse,
    },
    types::crypto_primitives::ApiSchnorrPublicKey,
};
use hyper::HeaderMap;
use itertools::Itertools;
use renegade_solidity_abi::v2::IDarkpoolV2::DepositAuth;
use state::State;
use types_account::balance::BalanceLocation;
use types_core::AccountId;
use types_tasks::{
    CreateBalanceTaskDescriptor, DepositTaskDescriptor, TaskDescriptor, WithdrawTaskDescriptor,
};
use util::hex::scalar_from_hex_string;

use crate::{
    error::{
        ApiServerError, ERR_ACCOUNT_NOT_FOUND, ERR_BALANCE_NOT_FOUND, bad_request, internal_error,
        not_found,
    },
    http::helpers::append_task,
    param_parsing::{
        parse_account_id_from_params, parse_address_from_hex_string, parse_amount_from_string,
        parse_mint_from_params,
    },
    router::{QueryParams, TypedHandler, UrlParams},
};

// ----------------------
// | Conversion Helpers |
// ----------------------

/// Convert an ApiSchnorrPublicKey to SchnorrPublicKey
fn parse_schnorr_public_key(
    api_key: &ApiSchnorrPublicKey,
) -> Result<SchnorrPublicKey, ApiServerError> {
    let x = scalar_from_hex_string(&api_key.point.x)
        .map_err(|e| bad_request(format!("invalid authority x coordinate: {e}")))?;
    let y = scalar_from_hex_string(&api_key.point.y)
        .map_err(|e| bad_request(format!("invalid authority y coordinate: {e}")))?;
    Ok(SchnorrPublicKey { point: BabyJubJubPoint { x, y } })
}

// ---------------------
// | Balance Handlers  |
// ---------------------

/// Handler for GET /v2/account/:account_id/balances
pub struct GetBalancesHandler {
    /// A handle to the relayer state
    state: State,
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
        let account_id = parse_account_id_from_params(&params)?;
        let balances = self.state.get_account_balances(&account_id).await?;
        let balances = balances.into_iter().map(Into::into).collect_vec();
        Ok(GetBalancesResponse { balances })
    }
}

/// Handler for GET /v2/account/:account_id/balances/:mint
pub struct GetBalanceByMintHandler {
    /// The global state
    state: State,
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
        let account_id = parse_account_id_from_params(&params)?;
        let token = parse_mint_from_params(&params)?;

        let balance = self.state.get_account_balance(&account_id, &token).await?;
        let balance = balance.ok_or(not_found(ERR_BALANCE_NOT_FOUND))?;

        Ok(GetBalanceByMintResponse { balance: balance.into() })
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
        // Parse parameters
        let account_id = parse_account_id_from_params(&params)?;
        let token = parse_mint_from_params(&params)?;
        let from_address = parse_address_from_hex_string(&req.from_address)?;
        let amount = parse_amount_from_string(&req.amount)?;
        let auth = DepositAuth::try_from(req.permit).map_err(bad_request)?;
        let authority = parse_schnorr_public_key(&req.authority)?;

        // Update the account for simulation
        // Deposit implies that the balance is allocated in the darkpool, so the balance
        // location is set to darkpool for all paths below
        let mut account =
            self.state.get_account(&account_id).await?.ok_or(not_found(ERR_ACCOUNT_NOT_FOUND))?;
        let has_balance = account.has_balance(&token);

        if !has_balance {
            let fee_addr = self.state.get_relayer_fee_addr().map_err(internal_error)?;
            account.create_darkpool_balance(token, from_address, fee_addr, authority);
        } else {
            account
                .deposit_balance(token, amount, BalanceLocation::Darkpool)
                .map_err(bad_request)?;
        }
        let updated_balance = account.get_darkpool_balance(&token).cloned().unwrap();

        // Create the appropriate task descriptor based on whether balance exists
        let descriptor: TaskDescriptor = if !has_balance {
            CreateBalanceTaskDescriptor::new(
                account_id,
                from_address,
                token,
                amount,
                authority,
                auth,
            )
            .into()
        } else {
            DepositTaskDescriptor::new(account_id, from_address, token, amount, auth, authority)
                .into()
        };
        let task_id = append_task(descriptor, &self.state).await?;

        Ok(DepositBalanceResponse {
            task_id,
            balance: updated_balance.into(),
            // TODO: Expose synchronous api
            completed: false,
        })
    }
}

/// Handler for POST /v2/account/:account_id/balances/:mint/withdraw
pub struct WithdrawBalanceHandler {
    /// The global state
    state: State,
}

impl WithdrawBalanceHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
    }

    /// Validate a withdrawal
    async fn validate_withdrawal(
        &self,
        account_id: AccountId,
        token: Address,
        amount: Amount,
    ) -> Result<(), ApiServerError> {
        let balance = self.state.get_account_balance(&account_id, &token).await?;
        let balance = balance.ok_or(ApiServerError::balance_not_found(token))?;

        if balance.amount() < amount {
            return Err(bad_request(format!(
                "balance amount is less than the withdrawal amount: {} < {}",
                balance.amount(),
                amount
            )));
        }

        Ok(())
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
        let account_id = parse_account_id_from_params(&params)?;
        let token = parse_mint_from_params(&params)?;

        // Validate the withdrawal
        self.validate_withdrawal(account_id, token, req.amount).await?;

        // Enqueue the withdrawal task
        let descriptor: TaskDescriptor =
            WithdrawTaskDescriptor::new(account_id, token, req.amount, req.signature).into();
        let task_id = append_task(descriptor, &self.state).await?;

        Ok(WithdrawBalanceResponse { task_id, completed: false })
    }
}
