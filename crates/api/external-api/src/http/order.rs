//! HTTP route definitions and request/response types for order operations

#[cfg(feature = "full-api")]
use alloy::primitives::Address;
#[cfg(feature = "full-api")]
use darkpool_types::intent::Intent;
use serde::{Deserialize, Serialize};
#[cfg(feature = "full-api")]
use types_account::order_auth::OrderAuth as AccountOrderAuth;
use uuid::Uuid;

#[cfg(feature = "full-api")]
use crate::error::ApiTypeError;
use crate::types::{ApiOrder, ApiOrderCore, OrderAuth, SignatureWithNonce};

/// Error message for permit mismatch
#[cfg(feature = "full-api")]
const ERR_PERMIT_MISMATCH: &str = "client permit does not match order";

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
    /// The order authentication
    pub auth: OrderAuth,
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
    /// Get the order auth from the request, validating the permit
    pub fn get_order_auth(&self, executor: Address) -> Result<AccountOrderAuth, ApiTypeError> {
        match self.auth.clone() {
            OrderAuth::PublicOrder { permit, intent_signature } => {
                // Validate the permit intent and executor match the order
                let order_intent = self.order.get_intent();
                let permit_intent: Intent = permit.intent.clone().into();

                if permit_intent != order_intent || permit.executor != executor {
                    return Err(ApiTypeError::validation(ERR_PERMIT_MISMATCH));
                }

                let permit = permit.into();
                let intent_signature = intent_signature.into();
                Ok(AccountOrderAuth::PublicOrder { permit, intent_signature })
            },
            OrderAuth::NativelySettledPrivateOrder { intent_signature } => {
                let intent_signature = intent_signature.into();
                Ok(AccountOrderAuth::NativelySettledPrivateOrder { intent_signature })
            },
            OrderAuth::RenegadeSettledOrder { intent_signature, new_output_balance_signature } => {
                let intent_signature = intent_signature.into();
                let new_output_balance_signature = new_output_balance_signature.into();
                Ok(AccountOrderAuth::RenegadeSettledOrder {
                    intent_signature,
                    new_output_balance_signature,
                })
            },
        }
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

/// Request to create a new order in a specific matching pool (admin only)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateOrderInPoolRequest {
    /// The order to create
    pub order: ApiOrderCore,
    /// The authorization for the order
    pub auth: OrderAuth,
    /// The matching pool to assign the order to
    pub matching_pool: String,
}

#[cfg(feature = "full-api")]
impl CreateOrderInPoolRequest {
    /// Get the order auth from the request, validating the permit
    pub fn get_order_auth(&self, executor: Address) -> Result<AccountOrderAuth, ApiTypeError> {
        match self.auth.clone() {
            OrderAuth::PublicOrder { permit, intent_signature } => {
                // Validate the permit intent matches the order intent
                let order_intent = self.order.get_intent();
                let permit_intent: Intent = permit.intent.clone().into();
                if permit_intent != order_intent || permit.executor != executor {
                    return Err(ApiTypeError::validation(ERR_PERMIT_MISMATCH));
                }

                let permit = permit.into();
                let intent_signature = intent_signature.into();
                Ok(AccountOrderAuth::PublicOrder { permit, intent_signature })
            },
            OrderAuth::NativelySettledPrivateOrder { intent_signature } => {
                let intent_signature = intent_signature.into();
                Ok(AccountOrderAuth::NativelySettledPrivateOrder { intent_signature })
            },
            OrderAuth::RenegadeSettledOrder { intent_signature, new_output_balance_signature } => {
                let intent_signature = intent_signature.into();
                let new_output_balance_signature = new_output_balance_signature.into();
                Ok(AccountOrderAuth::RenegadeSettledOrder {
                    intent_signature,
                    new_output_balance_signature,
                })
            },
        }
    }
}
