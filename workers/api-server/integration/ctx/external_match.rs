//! Helpers for interacting with the external match API

use external_api::http::external_match::{
    AssembleExternalMatchRequest, ExternalMatchResponse, ExternalOrder, ExternalQuoteRequest,
    ExternalQuoteResponse, SignedExternalQuote, ASSEMBLE_EXTERNAL_MATCH_ROUTE,
    REQUEST_EXTERNAL_QUOTE_ROUTE,
};
use eyre::Result;
use hyper::StatusCode;
use reqwest::{header::HeaderMap, Method, Response};

use crate::ctx::IntegrationTestCtx;

impl IntegrationTestCtx {
    /// Request an external quote for the given order
    ///
    /// Returns the quote response directly, or an error for non-200
    pub async fn request_external_quote(
        &self,
        order: &ExternalOrder,
    ) -> Result<ExternalQuoteResponse> {
        let resp = self.send_external_quote_req(order).await?;
        let status = resp.status();
        if status == StatusCode::OK {
            let resp_body: ExternalQuoteResponse = resp.json().await?;
            Ok(resp_body)
        } else {
            let txt = resp.text().await?;
            eyre::bail!("failed to request external quote: (status = {status}) {txt}");
        }
    }

    /// Request to assemble a quote into a match bundle
    pub async fn request_assemble_quote(
        &self,
        quote: &SignedExternalQuote,
    ) -> Result<ExternalMatchResponse> {
        let path = ASSEMBLE_EXTERNAL_MATCH_ROUTE;
        let req = AssembleExternalMatchRequest {
            signed_quote: quote.clone(),
            do_gas_estimation: false,
            allow_shared: false,
            receiver_address: None,
            updated_order: None,
        };

        let resp = self.send_admin_req_raw(path, Method::POST, HeaderMap::default(), req).await?;
        let status = resp.status();
        if status == StatusCode::OK {
            let resp_body: ExternalMatchResponse = resp.json().await?;
            Ok(resp_body)
        } else {
            let txt = resp.text().await?;
            eyre::bail!("failed to assemble quote into match bundle: (status = {status}) {txt}");
        }
    }

    /// Send an external match request
    pub async fn send_external_quote_req(&self, order: &ExternalOrder) -> Result<Response> {
        let req = ExternalQuoteRequest { external_order: order.clone() };

        // Add admin auth then send the request
        let path = REQUEST_EXTERNAL_QUOTE_ROUTE;
        self.send_admin_req_raw(path, Method::POST, HeaderMap::default(), req).await
    }
}
