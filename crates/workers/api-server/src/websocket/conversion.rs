//! Conversion from system bus messages to websocket message bodies

use external_api::types::{
    ApiAdminOrder, ApiBalance, ApiOrder, ApiOrderUpdateType, ServerWebsocketMessageBody,
};
use system_bus::{AdminOrderUpdateType, SystemBusMessage};

/// Convert a system bus message to a websocket message body
///
/// # Panics
/// Panics if the message type is not intended for websocket consumption
pub fn system_bus_message_to_websocket_body(msg: SystemBusMessage) -> ServerWebsocketMessageBody {
    match msg {
        SystemBusMessage::AdminOrderUpdate { account_id, order, matching_pool, update_type } => {
            convert_admin_order_update(account_id, *order, matching_pool, update_type)
        },
        SystemBusMessage::AdminBalanceUpdate { account_id, balance } => {
            convert_admin_balance_update(account_id, *balance)
        },
        // Other message types are not intended for websocket consumption
        SystemBusMessage::HandshakeInProgress { .. }
        | SystemBusMessage::HandshakeCompleted { .. }
        | SystemBusMessage::NewPeer { .. }
        | SystemBusMessage::PeerExpired { .. }
        | SystemBusMessage::TaskStatusUpdate { .. }
        | SystemBusMessage::AccountUpdate { .. }
        | SystemBusMessage::ExternalOrderQuote { .. }
        | SystemBusMessage::ExternalOrderBundle { .. }
        | SystemBusMessage::NoExternalMatchFound
        | SystemBusMessage::OwnerIndexChanged { .. } => {
            panic!("invalid websocket bus subscription: message type not intended for websocket")
        },
    }
}

/// Convert an AdminOrderUpdate system bus message to a websocket message body
fn convert_admin_order_update(
    account_id: types_core::AccountId,
    order: types_account::order::Order,
    matching_pool: String,
    update_type: AdminOrderUpdateType,
) -> ServerWebsocketMessageBody {
    // Convert the order to an ApiAdminOrder
    let api_order: ApiOrder = order.into();
    let admin_order = ApiAdminOrder { order: api_order, account_id, matching_pool };

    // Convert the update type
    let api_update_type = convert_admin_order_update_type(update_type);
    ServerWebsocketMessageBody::AdminOrderUpdate {
        account_id,
        order: admin_order,
        update_type: api_update_type,
    }
}

/// Convert an AdminBalanceUpdate system bus message to a websocket message body
fn convert_admin_balance_update(
    account_id: types_core::AccountId,
    balance: types_account::balance::Balance,
) -> ServerWebsocketMessageBody {
    let api_balance: ApiBalance = balance.into();
    ServerWebsocketMessageBody::AdminBalanceUpdate { account_id, balance: api_balance }
}

/// Convert an AdminOrderUpdateType to an ApiOrderUpdateType
#[allow(clippy::needless_pass_by_value)]
fn convert_admin_order_update_type(update_type: AdminOrderUpdateType) -> ApiOrderUpdateType {
    match update_type {
        AdminOrderUpdateType::Created => ApiOrderUpdateType::Created,
        AdminOrderUpdateType::Updated => ApiOrderUpdateType::InternalFill,
        AdminOrderUpdateType::Cancelled => ApiOrderUpdateType::Cancelled,
    }
}
