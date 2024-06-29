//! A client for interacting with a Renegade compliance service

use renegade_compliance_api::{ComplianceCheckResponse, ComplianceStatus, WALLET_SCREEN_PATH};
use util::err_str;

use crate::error::ApiServerError;

/// The compliance server client
#[derive(Clone)]
pub struct ComplianceServerClient {
    /// The URL of the compliance service
    ///
    /// The client is disabled and always returns `true` for compliance checks
    /// if this is not set
    url: Option<String>,
}

impl ComplianceServerClient {
    /// Create a new client
    pub fn new(url: Option<String>) -> Self {
        Self { url }
    }

    /// Check if a wallet is compliant
    pub async fn check_address(&self, wallet_address: &str) -> Result<bool, ApiServerError> {
        let client = match &self.url {
            Some(_) => reqwest::Client::new(),
            None => return Ok(true),
        };

        // Send a request to the compliance service
        let base_url = self.url.clone().unwrap();
        let url = format!("{base_url}{WALLET_SCREEN_PATH}/{wallet_address}");
        let resp = client
            .get(url)
            .header("Content-Type", "application/json")
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(err_str!(ApiServerError::ComplianceService))?;

        let body: ComplianceCheckResponse =
            resp.json().await.map_err(err_str!(ApiServerError::ComplianceService))?;
        Ok(matches!(body.compliance_status, ComplianceStatus::Compliant))
    }
}
