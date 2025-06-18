//! HTTP helpers for the integration tests

use std::time::Duration;

use external_api::auth::add_expiring_auth_to_headers;
use eyre::Result;
use hyper::{HeaderMap, Method};
use reqwest::Response;
use serde::{de::DeserializeOwned, Serialize};

use crate::ctx::IntegrationTestCtx;

/// The duration of the admin auth for external match requests
const REQUEST_AUTH_DURATION: Duration = Duration::from_secs(60);

impl IntegrationTestCtx {
    /// Send an http request to the mock API server
    pub async fn send_req<Req: Serialize, Resp: DeserializeOwned>(
        &self,
        route: &str,
        method: Method,
        body: Req,
    ) -> Result<Resp> {
        self.send_req_with_headers(route, method, HeaderMap::default(), body).await
    }

    /// Send an http request to the mock API server
    pub async fn send_req_with_headers<Req: Serialize, Resp: DeserializeOwned>(
        &self,
        route: &str,
        method: Method,
        headers: HeaderMap,
        body: Req,
    ) -> Result<Resp> {
        self.mock_node.send_api_req(route, method, headers, body).await
    }

    /// Send an http request to the mock API server and return the raw response
    pub async fn send_req_raw<Req: Serialize>(
        &self,
        route: &str,
        method: Method,
        headers: HeaderMap,
        body: Req,
    ) -> Result<Response> {
        self.mock_node.send_api_req_raw(route, method, headers, body).await
    }

    /// Send an admin request to the mock API server
    pub async fn send_admin_req_raw<Req: Serialize>(
        &self,
        route: &str,
        method: Method,
        mut headers: HeaderMap,
        body: Req,
    ) -> Result<Response> {
        let body_bytes = serde_json::to_vec(&body).expect("failed to serialize request");
        add_expiring_auth_to_headers(
            route,
            &mut headers,
            &body_bytes,
            &self.admin_api_key,
            REQUEST_AUTH_DURATION,
        );

        self.send_req_raw(route, method, headers, body).await
    }
}
