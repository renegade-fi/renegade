//! Helpers for invoking the `pathfinder` API directly on an RPC node
//!
//! See: https://github.com/eqlabs/pathfinder/blob/main/doc/rpc/pathfinder_rpc_api.json
//! for the pathfinder API spec

use crate::error::StarknetClientError;

use super::StarknetClient;
use serde::{Deserialize, Serialize};
use starknet::core::types::FieldElement;

/// The JSON-RPC 2.0 version
const JSON_RPC_VERSION: &str = "2.0";
/// The pathfinder API method to get a transaction's status
const GET_TRANSACTION_STATUS_METHOD: &str = "pathfinder_getTransactionStatus";

// -------------
// | Api Types |
// -------------

/// The tx status object returned by the pathfinder API, borrowed from:
/// https://github.com/eqlabs/pathfinder/blob/main/crates/rpc/src/pathfinder/methods/get_transaction_status.rs#L100
#[allow(clippy::missing_docs_in_private_items, missing_docs)]
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum TransactionStatus {
    #[serde(rename = "NOT_RECEIVED")]
    NotReceived,
    #[serde(rename = "RECEIVED")]
    Received,
    #[serde(rename = "PENDING")]
    Pending,
    #[serde(rename = "REJECTED")]
    Rejected,
    #[serde(rename = "ACCEPTED_ON_L1")]
    AcceptedOnL1,
    #[serde(rename = "ACCEPTED_ON_L2")]
    AcceptedOnL2,
    #[serde(rename = "REVERTED")]
    Reverted,
    #[serde(rename = "ABORTED")]
    Aborted,
}

impl TransactionStatus {
    /// Check if the transaction is in a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            TransactionStatus::AcceptedOnL1
                | TransactionStatus::AcceptedOnL2
                | TransactionStatus::Rejected
                | TransactionStatus::Reverted
                | TransactionStatus::Aborted
        )
    }

    /// Convert a terminal status into a `Result<(), StarknetClientError>`
    pub fn into_result(self) -> Result<(), StarknetClientError> {
        assert!(self.is_terminal());
        match self {
            TransactionStatus::AcceptedOnL1 | TransactionStatus::AcceptedOnL2 => Ok(()),
            TransactionStatus::Rejected => Err(StarknetClientError::TransactionFailure(
                "transaction rejected".to_string(),
            )),
            TransactionStatus::Reverted => Err(StarknetClientError::TransactionFailure(
                "transaction reverted".to_string(),
            )),
            TransactionStatus::Aborted => Err(StarknetClientError::TransactionFailure(
                "transaction aborted".to_string(),
            )),
            _ => unreachable!("non-terminal status found"),
        }
    }
}

/// A raw starknet JSON-RPC request
#[derive(Clone, Debug, Serialize)]
pub struct RawJsonRpcRequest {
    /// The JSON-RPC version
    pub jsonrpc: String,
    /// The ID of the request
    pub id: u64,
    /// The JSON-RPC method to call
    pub method: String,
    /// The parameters to pass to the method
    pub params: Vec<String>,
}

/// A raw starknet JSON-RPC response
#[derive(Clone, Debug, Deserialize)]
pub struct RawJsonRpcResponse<T>
where
    T: for<'de2> Deserialize<'de2>,
{
    /// The JSON-RPC version
    pub jsonrpc: String,
    /// The ID of the request
    pub id: u64,
    /// The result of the request
    #[serde(bound(deserialize = "for<'de2> T: Deserialize<'de2>"))]
    pub result: T,
}

// -------------------------
// | Client Implementation |
// -------------------------

impl StarknetClient {
    /// Get the status of a transaction from the pathfinder API
    pub async fn get_tx_status(
        &self,
        tx_hash: FieldElement,
    ) -> Result<TransactionStatus, StarknetClientError> {
        let tx_hash_str = format!("0x{tx_hash:x}");
        self.raw_json_rpc_request(GET_TRANSACTION_STATUS_METHOD.to_string(), vec![tx_hash_str])
            .await
    }

    /// Make a raw JSON-RPC request to the RPC node
    async fn raw_json_rpc_request<T: for<'de> Deserialize<'de>>(
        &self,
        method: String,
        params: Vec<String>,
    ) -> Result<T, StarknetClientError> {
        let res = self
            .http_client
            .post(self.config.starknet_json_rpc_addr.clone())
            .json(&RawJsonRpcRequest {
                jsonrpc: JSON_RPC_VERSION.to_string(),
                id: 1,
                method,
                params,
            })
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| StarknetClientError::Rpc(e.to_string()))?;

        let body_bytes = res
            .bytes()
            .await
            .map_err(|e| StarknetClientError::Rpc(e.to_string()))?;

        let resp: RawJsonRpcResponse<T> = serde_json::from_slice(&body_bytes)
            .map_err(|e| StarknetClientError::Serde(e.to_string()))?;
        Ok(resp.result)
    }
}
