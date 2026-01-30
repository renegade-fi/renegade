//! Darkpool contract event handling (PublicIntent events)

use alloy::{
    providers::{DynProvider, Provider},
    rpc::types::{Filter, Log},
    sol_types::SolEvent,
};
use circuit_types::Amount;
use futures_util::Stream;
use renegade_solidity_abi::v2::IDarkpoolV2::{PublicIntentCancelled, PublicIntentUpdated};
use tracing::{info, warn};

use crate::{error::OnChainEventListenerError, executor::OnChainEventListenerExecutor};

/// Error message for amount remaining overflow
const ERR_AMOUNT_REMAINING_OVERFLOW: &str = "Amount remaining overflow";
/// Error message for missing topic0 in log
const ERR_LOG_MISSING_TOPIC: &str = "Log missing topic0";

impl OnChainEventListenerExecutor {
    /// Create a subscription for darkpool events (PublicIntent updates and
    /// cancellations)
    pub(crate) async fn create_darkpool_subscription(
        &self,
        client: &DynProvider,
    ) -> Result<impl Stream<Item = Log>, OnChainEventListenerError> {
        // Subscribe to both intent update and cancellation events
        let filter =
            Filter::new().address(self.darkpool_client().darkpool_addr()).event_signature(vec![
                PublicIntentUpdated::SIGNATURE_HASH,
                PublicIntentCancelled::SIGNATURE_HASH,
            ]);

        let stream = client.subscribe_logs(&filter).await?.into_stream();
        Ok(stream)
    }

    /// Dispatch darkpool events by topic0 to the appropriate handler
    pub(crate) async fn dispatch_darkpool_event(
        &self,
        log: Log,
    ) -> Result<(), OnChainEventListenerError> {
        // Extract event signature from first topic
        let topic0 = log
            .topics()
            .first()
            .ok_or_else(|| OnChainEventListenerError::State(ERR_LOG_MISSING_TOPIC.into()))?;

        // Route to appropriate handler based on event type
        match *topic0 {
            t if t == PublicIntentUpdated::SIGNATURE_HASH => {
                self.handle_public_intent_updated(log).await
            },
            t if t == PublicIntentCancelled::SIGNATURE_HASH => {
                self.handle_public_intent_cancelled(log).await
            },
            _ => {
                tracing::debug!("Unknown darkpool event: topic={topic0}");
                Ok(())
            },
        }
    }

    /// Handle a PublicIntentUpdated event emitted when a public intent is
    /// partially or fully filled on-chain
    ///
    /// Updates the order's remaining amount or removes it if fully filled.
    async fn handle_public_intent_updated(
        &self,
        log: Log,
    ) -> Result<(), OnChainEventListenerError> {
        let Some(tx_hash) = log.transaction_hash else {
            warn!("PublicIntentUpdated event missing transaction hash, skipping");
            return Ok(());
        };

        // Decode event data
        let event = log.log_decode::<PublicIntentUpdated>()?;
        let intent_hash = event.inner.intentHash;
        let owner = event.inner.owner;
        let amount_remaining: Amount =
            event.inner.amountRemaining.try_into().map_err(|_| {
                OnChainEventListenerError::State(ERR_AMOUNT_REMAINING_OVERFLOW.into())
            })?;

        // Look up order by intent hash, skip if not managed by this relayer
        let Some((account_id, order_id)) =
            self.state().get_order_by_intent_hash(&intent_hash).await?
        else {
            return Ok(());
        };
        info!(
            "Handling PublicIntentUpdated: owner={owner:#x}, intent_hash={intent_hash:#x}, amount_remaining={amount_remaining}, tx={tx_hash:#x}"
        );

        // Non-selected nodes wait before processing to allow primary to handle first
        if !self.should_execute_update(tx_hash).await? {
            self.sleep_for_crash_recovery().await;

            // Check if already processed by another node
            let Some(order) = self.state().get_account_order(&order_id).await? else {
                return Ok(()); // Order was removed (fully filled)
            };

            // Use monotonic guard: if local remaining <= event remaining, we've already
            // processed an equal-or-later update. This works because remaining only
            // decreases (fills reduce it, no increases possible currently).
            // TODO: Once public intent update feature is added (allowing increases),
            // this monotonic guard will be insufficient - will need on-chain fetch or
            // cursor.
            if order.intent.inner.amount_in <= amount_remaining {
                return Ok(()); // Already processed equal-or-later update
            }
        }

        // Update or remove order based on remaining amount
        if amount_remaining == 0 {
            self.state().remove_order_from_account(account_id, order_id).await?.await?;
        } else {
            let Some(mut order) = self.state().get_account_order(&order_id).await? else {
                return Ok(());
            };
            order.intent.inner.amount_in = amount_remaining;
            self.state().update_order(order).await?.await?;
        }

        // TODO: Emit ExternalFillEvent to notify clients

        Ok(())
    }

    /// Handle a PublicIntentCancelled event emitted when a user cancels their
    /// public intent on-chain
    ///
    /// Removes the order from the account.
    async fn handle_public_intent_cancelled(
        &self,
        log: Log,
    ) -> Result<(), OnChainEventListenerError> {
        let Some(tx_hash) = log.transaction_hash else {
            warn!("PublicIntentCancelled event missing transaction hash, skipping");
            return Ok(());
        };

        // Decode event data
        let event = log.log_decode::<PublicIntentCancelled>()?;
        let intent_hash = event.inner.intentHash;
        let owner = event.inner.owner;

        // Look up order by intent hash, skip if not managed by this relayer
        let Some((account_id, order_id)) =
            self.state().get_order_by_intent_hash(&intent_hash).await?
        else {
            return Ok(());
        };
        info!(
            "Handling PublicIntentCancelled: owner={owner:#x}, intent_hash={intent_hash:#x}, tx={tx_hash:#x}"
        );

        // Non-selected nodes wait before processing to allow primary to handle first
        if !self.should_execute_update(tx_hash).await? {
            self.sleep_for_crash_recovery().await;

            // Check if already processed by another node
            if self.state().get_order_by_intent_hash(&intent_hash).await?.is_none() {
                return Ok(());
            }
        }

        // Remove the cancelled order
        self.state().remove_order_from_account(account_id, order_id).await?.await?;

        // TODO: Emit cancellation event to notify clients

        Ok(())
    }
}
