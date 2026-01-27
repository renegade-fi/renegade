//! Route handlers for metadata operations

use async_trait::async_trait;
use darkpool_client::DarkpoolClient;
use external_api::{
    EmptyRequestResponse,
    types::{ExchangeMetadataResponse, market::ApiToken},
};
use hyper::HeaderMap;
use state::State;
use types_core::get_all_base_tokens;
use util::on_chain::get_chain_id;

use crate::{
    error::{ApiServerError, internal_error},
    router::{QueryParams, TypedHandler, UrlParams},
};

// ----------------------
// | Metadata Handlers  |
// ----------------------

/// Handler for GET /v2/metadata/exchange
pub struct GetExchangeMetadataHandler {
    /// A handle to the relayer's state
    state: State,
    /// The darkpool client
    darkpool_client: DarkpoolClient,
}

impl GetExchangeMetadataHandler {
    /// Constructor
    pub fn new(state: State, darkpool_client: DarkpoolClient) -> Self {
        Self { state, darkpool_client }
    }
}

#[async_trait]
impl TypedHandler for GetExchangeMetadataHandler {
    type Request = EmptyRequestResponse;
    type Response = ExchangeMetadataResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        _params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let chain_id = get_chain_id();
        let settlement_contract_address = self.darkpool_client.darkpool_addr();
        let executor_address = self.state.get_executor_key().map_err(internal_error)?.address();
        let relayer_fee_recipient = self.state.get_relayer_fee_addr().map_err(internal_error)?;

        let supported_tokens = get_all_base_tokens()
            .into_iter()
            .filter_map(|t| t.get_ticker().map(|sym| ApiToken::new(t.get_alloy_address(), sym)))
            .collect();

        Ok(ExchangeMetadataResponse {
            chain_id,
            settlement_contract_address,
            executor_address,
            relayer_fee_recipient,
            supported_tokens,
        })
    }
}
