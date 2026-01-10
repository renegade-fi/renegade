//! Route handlers for metadata operations

use async_trait::async_trait;
use external_api::{EmptyRequestResponse, types::ExchangeMetadataResponse};
use hyper::HeaderMap;

use crate::{
    error::ApiServerError,
    router::{QueryParams, TypedHandler, UrlParams},
};

// ------------------
// | Error Messages |
// ------------------

/// Error message for not implemented
const ERR_NOT_IMPLEMENTED: &str = "not implemented";

// ----------------------
// | Metadata Handlers  |
// ----------------------

/// Handler for GET /v2/metadata/exchange
pub struct GetExchangeMetadataHandler;

impl GetExchangeMetadataHandler {
    /// Constructor
    pub fn new() -> Self {
        Self
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
        Err(ApiServerError::not_implemented(ERR_NOT_IMPLEMENTED))
    }
}
