//! HTTP route definitions and request/response types for order operations

#[cfg(feature = "full-api")]
use alloy::primitives::Address;
#[cfg(feature = "full-api")]
use darkpool_types::intent::Intent;
use renegade_solidity_abi::v2::IDarkpoolV2::SignatureWithNonce;
use serde::{Deserialize, Serialize};
#[cfg(feature = "full-api")]
use types_account::{
    order::{OrderMetadata, PrivacyRing},
    order_auth::OrderAuth as AccountOrderAuth,
};
use uuid::Uuid;

#[cfg(feature = "full-api")]
use crate::error::ApiTypeError;
use crate::types::{ApiOrder, ApiOrderCore, OrderAuth};

// ---------------
// | HTTP Routes |
// ---------------

/// Route to get orders for an account
pub const GET_ORDERS_ROUTE: &str = "/v2/account/:account_id/orders";
/// Route to create a new order
pub const CREATE_ORDER_ROUTE: &str = "/v2/account/:account_id/orders";
/// Route to get an order by ID
pub const GET_ORDER_BY_ID_ROUTE: &str = "/v2/account/:account_id/orders/:order_id";
/// Route to update an order
pub const UPDATE_ORDER_ROUTE: &str = "/v2/account/:account_id/orders/:order_id/update";
/// Route to cancel an order
pub const CANCEL_ORDER_ROUTE: &str = "/v2/account/:account_id/orders/:order_id/cancel";

// -------------------
// | Request/Response |
// -------------------

/// Response for get orders
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetOrdersResponse {
    /// The orders
    pub orders: Vec<ApiOrder>,
    /// The next page token for pagination
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<i64>,
}

/// Response for get order by ID
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetOrderByIdResponse {
    /// The order
    pub order: ApiOrder,
}

/// Request to create a new order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateOrderRequest {
    /// The order to create
    pub order: ApiOrderCore,
    /// The authorization for the order
    pub auth: OrderAuth,
    /// Whether to precompute the cancellation proof
    pub precompute_cancellation_proof: bool,
}

#[cfg(feature = "full-api")]
impl CreateOrderRequest {
    /// Return the components of an order from the request
    pub fn into_order_components(
        self,
    ) -> Result<(Intent, PrivacyRing, OrderMetadata), ApiTypeError> {
        let intent = self.order.get_intent()?;
        let ring = self.order.order_type.into();
        let meta = self.order.get_order_metadata()?;

        Ok((intent, ring, meta))
    }

    /// Get the order auth from the request
    pub fn get_order_auth(&self, executor: Address) -> Result<AccountOrderAuth, ApiTypeError> {
        use circuit_types::schnorr::SchnorrSignature;
        use renegade_solidity_abi::v2::IDarkpoolV2;

        let auth = match self.auth.clone() {
            OrderAuth::PublicOrder { intent_signature } => {
                let intent = self.order.get_intent()?;
                let permit = IDarkpoolV2::PublicIntentPermit { intent: intent.into(), executor };
                let intent_signature = IDarkpoolV2::SignatureWithNonce::try_from(intent_signature)
                    .map_err(ApiTypeError::parsing)?;

                AccountOrderAuth::PublicOrder { permit, intent_signature }
            },
            OrderAuth::NativelySettledPrivateOrder { intent_signature } => {
                let intent_signature =
                    SchnorrSignature::try_from(intent_signature).map_err(ApiTypeError::parsing)?;

                AccountOrderAuth::NativelySettledPrivateOrder { intent_signature }
            },
            OrderAuth::RenegadeSettledOrder { intent_signature, new_output_balance_signature } => {
                let intent_signature =
                    SchnorrSignature::try_from(intent_signature).map_err(ApiTypeError::parsing)?;
                let new_output_balance_signature =
                    SchnorrSignature::try_from(new_output_balance_signature)
                        .map_err(ApiTypeError::parsing)?;

                AccountOrderAuth::RenegadeSettledOrder {
                    intent_signature,
                    new_output_balance_signature,
                }
            },
        };

        Ok(auth)
    }
}

/// Response for create order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateOrderResponse {
    /// The task ID for the creation
    pub task_id: Uuid,
    /// Whether the operation has completed
    pub completed: bool,
}

/// Request to update an order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateOrderRequest {
    /// The updated order
    pub order: ApiOrderCore,
}

/// Response for update order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateOrderResponse {
    /// The updated order
    pub order: ApiOrder,
}

/// Request to cancel an order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CancelOrderRequest {
    /// The signature authorizing the cancellation
    pub cancel_signature: SignatureWithNonce,
}

/// Response for cancel order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CancelOrderResponse {
    /// The task ID for the cancellation
    pub task_id: Uuid,
    /// Whether the operation has completed
    pub completed: bool,
}
