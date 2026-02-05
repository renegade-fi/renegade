//! Route handlers for balance operations

use alloy::{
    primitives::{Address, U256},
    sol_types::SolValue,
};
use async_trait::async_trait;
use circuit_types::Amount;
use crypto::fields::scalar_to_u256;
use external_api::{
    EmptyRequestResponse,
    http::balance::{
        DepositBalanceRequest, DepositBalanceResponse, GetBalanceByMintResponse,
        GetBalancesResponse, WithdrawBalanceRequest, WithdrawBalanceResponse,
    },
};
use hyper::HeaderMap;
use itertools::Itertools;
use job_types::task_driver::TaskDriverQueue;
use renegade_solidity_abi::v2::{IDarkpoolV2::DepositAuth, auth_helpers::validate_signature};
use state::State;
use types_account::balance::{Balance, BalanceLocation};
use types_core::AccountId;
use types_tasks::{
    CreateBalanceTaskDescriptor, DepositTaskDescriptor, TaskDescriptor, WithdrawTaskDescriptor,
};
use util::on_chain::get_chain_id;

use crate::{
    error::{
        ApiServerError, ERR_ACCOUNT_NOT_FOUND, ERR_BALANCE_NOT_FOUND, bad_request, internal_error,
        not_found,
    },
    http::helpers::append_task,
    param_parsing::{
        parse_account_id_from_params, parse_address_from_hex_string, parse_amount_from_string,
        parse_mint_from_params, should_block_on_task,
    },
    router::{QueryParams, TypedHandler, UrlParams},
};

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
        let balances = balances
            .into_iter()
            .filter(|b| b.location == BalanceLocation::Darkpool)
            .map(Into::into)
            .collect_vec();

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

        let balance = self.state.get_account_darkpool_balance(&account_id, &token).await?;
        let balance = balance.ok_or(not_found(ERR_BALANCE_NOT_FOUND))?;

        Ok(GetBalanceByMintResponse { balance: balance.into() })
    }
}

/// Handler for POST /v2/account/:account_id/balances/:mint/deposit
pub struct DepositBalanceHandler {
    /// The global state
    state: State,
    /// The task driver queue
    task_queue: TaskDriverQueue,
}

impl DepositBalanceHandler {
    /// Constructor
    pub fn new(state: State, task_queue: TaskDriverQueue) -> Self {
        Self { state, task_queue }
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
        query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let blocking = should_block_on_task(&query_params);

        // Parse parameters
        let account_id = parse_account_id_from_params(&params)?;
        let token = parse_mint_from_params(&params)?;
        let from_address = parse_address_from_hex_string(&req.from_address)?;
        let amount = parse_amount_from_string(&req.amount)?;
        let auth = DepositAuth::try_from(req.permit).map_err(bad_request)?;
        let authority = req.authority.into();

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
            .map_err(bad_request)?
            .into()
        } else {
            DepositTaskDescriptor::new(account_id, from_address, token, amount, auth, authority)
                .into()
        };
        let task_id = append_task(descriptor, blocking, &self.state, &self.task_queue).await?;

        Ok(DepositBalanceResponse { task_id, balance: updated_balance.into(), completed: true })
    }
}

/// Handler for POST /v2/account/:account_id/balances/:mint/withdraw
pub struct WithdrawBalanceHandler {
    /// The global state
    state: State,
    /// The task driver queue
    task_queue: TaskDriverQueue,
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
        query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let blocking = should_block_on_task(&query_params);
        let account_id = parse_account_id_from_params(&params)?;
        let token = parse_mint_from_params(&params)?;

        // Validate the withdrawal
        self.validate_withdrawal(account_id, token, req.amount, &req.signature).await?;

        // Enqueue the withdrawal task
        let descriptor: TaskDescriptor =
            WithdrawTaskDescriptor::new(account_id, token, req.amount, req.signature).into();
        let task_id = append_task(descriptor, blocking, &self.state, &self.task_queue).await?;

        Ok(WithdrawBalanceResponse { task_id, completed: true })
    }
}

impl WithdrawBalanceHandler {
    /// Constructor
    pub fn new(state: State, task_queue: TaskDriverQueue) -> Self {
        Self { state, task_queue }
    }

    /// Validate a withdrawal
    async fn validate_withdrawal(
        &self,
        account_id: AccountId,
        token: Address,
        amount: Amount,
        signature: &[u8],
    ) -> Result<(), ApiServerError> {
        let balance = self.state.get_account_darkpool_balance(&account_id, &token).await?;
        let balance = balance.ok_or(ApiServerError::balance_not_found(token))?;

        let protocol_fee_bal = balance.protocol_fee_balance();
        let relayer_fee_bal = balance.relayer_fee_balance();
        if protocol_fee_bal > 0 || relayer_fee_bal > 0 {
            return Err(bad_request(format!(
                "balance has outstanding fees: protocol fee balance: {protocol_fee_bal} relayer fee balance: {relayer_fee_bal}",
            )));
        }

        if balance.amount() < amount {
            return Err(bad_request(format!(
                "balance amount is less than the withdrawal amount: {} < {}",
                balance.amount(),
                amount
            )));
        }

        // Validate the withdrawal signature
        self.validate_withdrawal_signature(&balance, amount, signature)?;
        Ok(())
    }

    /// Validate the withdrawal signature
    ///
    /// The signature should be over
    /// `keccak256(abi_encode(new_balance_commitment, chain_id))` and must
    /// be signed by the balance owner
    fn validate_withdrawal_signature(
        &self,
        balance: &Balance,
        amount: Amount,
        sig: &[u8],
    ) -> Result<(), ApiServerError> {
        // Compute the expected new balance commitment after withdrawal.
        // This must match the sequence in the VALID WITHDRAWAL circuit:
        // 1. Subtract the withdrawal amount
        // 2. Re-encrypt the amount share (advances share stream, updates public share)
        // 3. Compute recovery ID (advances recovery stream)
        // 4. Compute commitment
        let mut balance_clone = balance.clone();
        balance_clone.withdraw(amount);
        balance_clone.state_wrapper.reencrypt_amount_share();
        balance_clone.state_wrapper.compute_recovery_id();
        let new_balance_commitment = balance_clone.state_wrapper.compute_commitment();
        let commitment_u256 = scalar_to_u256(&new_balance_commitment);

        // Compute the expected hash: keccak256(abi_encode(commitment, chain_id))
        let chain_id = get_chain_id();
        let chain_id_u256 = U256::from(chain_id);
        let payload = (commitment_u256, chain_id_u256).abi_encode();

        // Validate the signature
        let owner = balance.owner();
        let valid = validate_signature(&payload, sig, owner).map_err(bad_request)?;
        if !valid {
            return Err(bad_request("invalid withdrawal signature"));
        }

        Ok(())
    }
}
