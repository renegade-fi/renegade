//! Helpers for interacting with the external match API

use std::time::Duration;

use external_api::{
    auth::add_expiring_auth_to_headers,
    http::external_match::{
        ExternalOrder, ExternalQuoteRequest, ExternalQuoteResponse, REQUEST_EXTERNAL_QUOTE_ROUTE,
    },
};
use eyre::Result;
use hyper::StatusCode;
use reqwest::{header::HeaderMap, Method, Response};

use crate::ctx::IntegrationTestCtx;

/// The duration of the admin auth for external match requests
const REQUEST_AUTH_DURATION: Duration = Duration::from_secs(60);

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

    /// Send an external match request
    pub async fn send_external_quote_req(&self, order: &ExternalOrder) -> Result<Response> {
        let req = ExternalQuoteRequest { external_order: order.clone() };
        let mut headers = HeaderMap::new();

        // Add admin auth then send the request
        let path = REQUEST_EXTERNAL_QUOTE_ROUTE;
        let body_bytes = serde_json::to_vec(&req).expect("failed to serialize request");
        add_expiring_auth_to_headers(
            path,
            &mut headers,
            &body_bytes,
            &self.admin_api_key,
            REQUEST_AUTH_DURATION,
        );

        self.send_req_raw(path, Method::POST, headers, req).await
    }
}
