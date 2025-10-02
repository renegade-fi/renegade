//! Helpers for emitting events after a wallet update

use common::types::{
    MatchingPoolName,
    tasks::WalletUpdateType,
    wallet::{Order, OrderIdentifier},
};
use itertools::Itertools;
use job_types::event_manager::{
    ExternalTransferEvent, OrderCancellationEvent, OrderPlacementEvent, OrderUpdateEvent,
    RelayerEventType, try_send_event,
};
use state::storage::tx::matching_pools::GLOBAL_MATCHING_POOL;
use util::err_str;

use crate::tasks::update_wallet::{UpdateWalletTask, UpdateWalletTaskError};

/// A deposit or withdrawal wallet update type is missing an external transfer
const ERR_MISSING_TRANSFER: &str = "missing external transfer";
/// A cancelled order cannot be found in an order cancellation wallet update
/// type
const ERR_MISSING_CANCELLED_ORDER: &str = "missing cancelled order";
/// An order metadata is missing from the global state
const ERR_MISSING_ORDER_METADATA: &str = "missing order metadata";

impl UpdateWalletTask {
    // --- Event Helpers --- //

    /// Emit the completion event to the event manager
    pub(crate) fn emit_event(&mut self) -> Result<(), UpdateWalletTaskError> {
        try_send_event(self.completion_event.take().unwrap(), &self.ctx.event_queue)
            .map_err(err_str!(UpdateWalletTaskError::SendEvent))
    }

    /// Construct the event to emit after the task is complete & record
    /// it in the task
    pub(crate) async fn prepare_completion_event(&mut self) -> Result<(), UpdateWalletTaskError> {
        let event = match &self.update_type {
            WalletUpdateType::Deposit { .. } | WalletUpdateType::Withdraw { .. } => {
                self.construct_external_transfer_event()?
            },
            WalletUpdateType::PlaceOrder { order, id, matching_pool, .. } => {
                self.construct_order_placement_or_update_event(id, order, matching_pool)
            },
            WalletUpdateType::CancelOrder { order } => {
                self.construct_order_cancellation_event(order).await?
            },
        };

        self.completion_event = Some(event);
        Ok(())
    }

    /// Construct an external transfer event
    fn construct_external_transfer_event(&self) -> Result<RelayerEventType, UpdateWalletTaskError> {
        let wallet_id = self.new_wallet.wallet_id;
        let transfer = self
            .transfer
            .clone()
            .map(|t| t.external_transfer)
            .ok_or(UpdateWalletTaskError::Missing(ERR_MISSING_TRANSFER.to_string()))?;

        Ok(RelayerEventType::ExternalTransfer(ExternalTransferEvent::new(wallet_id, transfer)))
    }

    /// Construct either an order placement or an order update event,
    /// depending on whether the order already exists in the new wallet
    fn construct_order_placement_or_update_event(
        &self,
        order_id: &OrderIdentifier,
        order: &Order,
        matching_pool: &Option<MatchingPoolName>,
    ) -> RelayerEventType {
        let wallet_id = self.new_wallet.wallet_id;
        let order_id = *order_id;
        let order = order.clone();
        let matching_pool = matching_pool.clone().unwrap_or(GLOBAL_MATCHING_POOL.to_string());

        if self.old_wallet.contains_order(&order_id) {
            RelayerEventType::OrderUpdate(OrderUpdateEvent::new(
                wallet_id,
                order_id,
                order,
                matching_pool,
            ))
        } else {
            RelayerEventType::OrderPlacement(OrderPlacementEvent::new(
                wallet_id,
                order_id,
                order,
                matching_pool,
            ))
        }
    }

    /// Construct an order cancellation event
    async fn construct_order_cancellation_event(
        &self,
        order: &Order,
    ) -> Result<RelayerEventType, UpdateWalletTaskError> {
        let wallet_id = self.new_wallet.wallet_id;
        let order = order.clone();

        // Find the ID of the cancelled order
        let mut new_order_ids = self.new_wallet.get_nonzero_orders().into_keys();
        let order_id = self
            .old_wallet
            .get_nonzero_orders()
            .into_keys()
            .find(|id| !new_order_ids.contains(id))
            .ok_or(UpdateWalletTaskError::Missing(ERR_MISSING_CANCELLED_ORDER.to_string()))?;

        let amount_remaining = order.amount;

        let amount_filled = self
            .ctx
            .state
            .get_order_metadata(&order_id)
            .await?
            .ok_or(UpdateWalletTaskError::Missing(ERR_MISSING_ORDER_METADATA.to_string()))?
            .total_filled();

        Ok(RelayerEventType::OrderCancellation(OrderCancellationEvent::new(
            wallet_id,
            order_id,
            order,
            amount_remaining,
            amount_filled,
        )))
    }
}
