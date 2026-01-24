//! v2 Route handlers for external match operations

use async_trait::async_trait;
use external_api::http::external_match::{
    AssembleExternalMatchRequest, ExternalMatchResponse, ExternalQuoteRequest,
    ExternalQuoteResponse,
};
use hyper::HeaderMap;

use crate::{
    error::{ApiServerError, bad_request},
    http::external_match::processor::ExternalMatchProcessor,
    router::{QueryParams, TypedHandler, UrlParams},
};

// ---------------------------
// | External Match Handlers |
// ---------------------------

/// Handler for POST /v2/external-matches/get-quote
pub struct GetExternalMatchQuoteHandler {
    /// The external match processor
    processor: ExternalMatchProcessor,
}

impl GetExternalMatchQuoteHandler {
    /// Constructor
    pub fn new(processor: ExternalMatchProcessor) -> Self {
        Self { processor }
    }
}

#[async_trait]
impl TypedHandler for GetExternalMatchQuoteHandler {
    type Request = ExternalQuoteRequest;
    type Response = ExternalQuoteResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        req: Self::Request,
        _params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        // TODO: Support exact output amounts
        if req.external_order.use_exact_output_amount {
            return Err(bad_request("`use_exact_output_amount` is not supported"));
        }

        // Forward to the external match processor
        let signed_quote = self.processor.fetch_signed_quote(req).await?;
        Ok(ExternalQuoteResponse { signed_quote })
    }
}

/// Handler for POST /v2/external-matches/assemble-match-bundle
pub struct AssembleMatchBundleHandler {
    /// The external match processor
    processor: ExternalMatchProcessor,
}

impl AssembleMatchBundleHandler {
    /// Constructor
    pub fn new(processor: ExternalMatchProcessor) -> Self {
        Self { processor }
    }
}

#[async_trait]
impl TypedHandler for AssembleMatchBundleHandler {
    type Request = AssembleExternalMatchRequest;
    type Response = ExternalMatchResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        req: Self::Request,
        _params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        // TODO: Support exact output amounts
        if req.order.get_external_order_ref().use_exact_output_amount {
            return Err(bad_request("`use_exact_output_amount` is not supported"));
        }

        // Forward the request to the processor
        let match_bundle = self.processor.assemble_match_bundle(req).await?;
        Ok(ExternalMatchResponse { match_bundle })
    }
}
