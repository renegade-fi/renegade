//! Conversion from system bus messages to websocket message bodies

use external_api::types::{
    AdminBalanceUpdateMessage, AdminOrderUpdateMessage, ApiAdminOrder, ApiBalance, ApiOrder,
    ApiOrderCore, ApiOrderUpdateType, ApiPartialOrderFill, ApiTimestampedPriceFloat, FeeTake,
    FillMessage, ServerWebsocketMessageBody,
};
use system_bus::{AdminOrderUpdateType, SystemBusMessage};

/// Convert a system bus message to a websocket message body
///
/// # Panics
/// Panics if the message type is not intended for websocket consumption
pub fn system_bus_message_to_websocket_body(msg: SystemBusMessage) -> ServerWebsocketMessageBody {
    match msg {
        SystemBusMessage::AdminOrderUpdate {
            account_id,
            order,
            matching_pool,
            update_type,
            matchable_amount,
        } => convert_admin_order_update(
            account_id,
            *order,
            matching_pool,
            update_type,
            matchable_amount,
        ),
        SystemBusMessage::AdminBalanceUpdate { account_id, balance } => {
            convert_admin_balance_update(account_id, *balance)
        },
        SystemBusMessage::Fill { account_id: _, order, fill_amount, filled } => {
            convert_fill(*order, fill_amount, filled)
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
    matchable_amount: circuit_types::Amount,
) -> ServerWebsocketMessageBody {
    // Convert the order to an ApiAdminOrder
    let api_order: ApiOrder = order.into();
    let admin_order =
        ApiAdminOrder { order: api_order, account_id, matching_pool, matchable_amount };

    // Convert the update type
    let api_update_type = convert_admin_order_update_type(update_type);
    ServerWebsocketMessageBody::AdminOrderUpdate(AdminOrderUpdateMessage {
        account_id,
        order: admin_order,
        update_type: api_update_type,
    })
}

/// Convert an AdminBalanceUpdate system bus message to a websocket message body
fn convert_admin_balance_update(
    account_id: types_core::AccountId,
    balance: types_account::balance::Balance,
) -> ServerWebsocketMessageBody {
    let api_balance: ApiBalance = balance.into();
    ServerWebsocketMessageBody::AdminBalanceUpdate(AdminBalanceUpdateMessage {
        account_id,
        balance: api_balance,
    })
}

/// Convert a Fill system bus message to a websocket message body.
///
/// The relayer's per-order state does not yet carry a price/fee/tx_hash for
/// the fill, so those fields are emitted as zero/empty placeholders. The
/// `amount` is the delta of the order's `amount_in` between pre- and
/// post-fill, computed by the publisher.
fn convert_fill(
    order: types_account::order::Order,
    fill_amount: circuit_types::Amount,
    filled: bool,
) -> ServerWebsocketMessageBody {
    let api_order_core: ApiOrderCore = order.into();
    let fill = ApiPartialOrderFill {
        amount: fill_amount,
        price: ApiTimestampedPriceFloat { price: "0".to_string(), timestamp: 0 },
        fees: FeeTake::default(),
        tx_hash: String::new(),
    };
    ServerWebsocketMessageBody::Fill(FillMessage { fill, order: api_order_core, filled })
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
