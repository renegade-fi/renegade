//! Darkpool contract event handling (PublicIntent events)

use alloy::{
    primitives::{B256, TxHash},
    providers::{DynProvider, Provider},
    rpc::types::{Filter, Log},
    sol_types::SolEvent,
};
use circuit_types::Amount;
use darkpool_types::{
    bounded_match_result::BoundedMatchResult, settlement_obligation::SettlementObligation,
};
use futures_util::Stream;
use renegade_metrics::record_match_volume_from_obligation;
use renegade_solidity_abi::v2::IDarkpoolV2::{PublicIntentCancelled, PublicIntentUpdated};
use tracing::{info, warn};
use types_account::OrderId;
use types_core::AccountId;

use crate::{error::OnChainEventListenerError, executor::OnChainEventListenerExecutor};

/// Error message for amount remaining overflow
const ERR_AMOUNT_REMAINING_OVERFLOW: &str = "Amount remaining overflow";
/// Error message for missing topic0 in log
const ERR_LOG_MISSING_TOPIC: &str = "Log missing topic0";
/// Error message for missing transaction hash in log
const ERR_LOG_MISSING_TX_HASH: &str = "Log missing transaction hash";

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
        // Skip non-external-match transactions; relayer-submitted transaction
        // flows are expected to update state outside the chain-events listener
        let (tx_hash, external_matches) = self.find_external_matches_for_log(&log).await?;
        if external_matches.is_empty() {
            info!("Skipping darkpool event from non-external-match tx: tx={tx_hash:#x}");
            return Ok(());
        }

        // Extract event signature from first topic
        let topic0 = log
            .topics()
            .first()
            .ok_or_else(|| OnChainEventListenerError::State(ERR_LOG_MISSING_TOPIC.into()))?;

        // Route to appropriate handler based on event type
        match *topic0 {
            t if t == PublicIntentUpdated::SIGNATURE_HASH => {
                self.handle_public_intent_updated(log, tx_hash, &external_matches).await
            },
            t if t == PublicIntentCancelled::SIGNATURE_HASH => {
                self.handle_public_intent_cancelled(log, tx_hash).await
            },
            _ => {
                tracing::warn!("Unknown darkpool event: topic={topic0}");
                Ok(())
            },
        }
    }

    /// Decode all external matches in the log's transaction
    async fn find_external_matches_for_log(
        &self,
        log: &Log,
    ) -> Result<(TxHash, Vec<(B256, BoundedMatchResult, Amount)>), OnChainEventListenerError> {
        let tx_hash = log
            .transaction_hash
            .ok_or_else(|| OnChainEventListenerError::darkpool(ERR_LOG_MISSING_TX_HASH))?;
        let external_matches = self.darkpool_client().find_external_matches_in_tx(tx_hash).await?;
        Ok((tx_hash, external_matches))
    }

    /// Handle a PublicIntentUpdated event emitted when a public intent is
    /// partially or fully filled on-chain
    ///
    /// Updates the order's remaining amount or removes it if fully filled.
    async fn handle_public_intent_updated(
        &self,
        log: Log,
        tx_hash: TxHash,
        external_matches: &[(B256, BoundedMatchResult, Amount)],
    ) -> Result<(), OnChainEventListenerError> {
        // Decode event data and normalize amounts into the local Amount type
        let event = log.log_decode::<PublicIntentUpdated>()?.inner.data;
        let fill_amount: Option<Amount> = event.fillAmount.try_into().ok();
        let amount_remaining: Amount = event
            .amountRemaining
            .try_into()
            .map_err(|_| OnChainEventListenerError::State(ERR_AMOUNT_REMAINING_OVERFLOW.into()))?;

        // Look up order by intent hash, skip if not managed by this relayer
        let Some((account_id, order_id)) =
            self.state().get_order_by_intent_hash(&event.intentHash).await?
        else {
            return Ok(());
        };

        if !self.should_process_update(tx_hash, order_id, amount_remaining).await? {
            return Ok(());
        }

        if let Some(fill_amount) = fill_amount {
            self.maybe_record_external_match_metrics(
                tx_hash,
                event.intentHash,
                fill_amount,
                account_id,
                &external_matches,
            )
        } else {
            warn!(
                "PublicIntentUpdated fill amount overflow; skipping external-match metrics: tx={tx_hash:#x}"
            );
        }

        // Update or remove the order based on remaining amount
        self.apply_public_intent_update(account_id, order_id, amount_remaining).await?;

        // TODO: Emit ExternalFillEvent to notify clients

        Ok(())
    }

    /// Determine whether this node should process the update now.
    async fn should_process_update(
        &self,
        tx_hash: TxHash,
        order_id: OrderId,
        amount_remaining: Amount,
    ) -> Result<bool, OnChainEventListenerError> {
        if self.should_execute_update(tx_hash).await? {
            return Ok(true);
        }

        self.sleep_for_crash_recovery().await;

        let Some(order) = self.state().get_account_order(&order_id).await? else {
            return Ok(false);
        };

        // TODO: Once public intent update feature is added (allowing increases),
        // this monotonic guard will be insufficient.
        if order.intent.inner.amount_in <= amount_remaining {
            return Ok(false);
        }

        Ok(true)
    }

    /// Apply the remaining-amount update for a public intent.
    async fn apply_public_intent_update(
        &self,
        account_id: AccountId,
        order_id: OrderId,
        amount_remaining: Amount,
    ) -> Result<(), OnChainEventListenerError> {
        if amount_remaining == 0 {
            self.state().remove_order_from_account(account_id, order_id).await?.await?;
            info!(
                "Removed order {order_id} from account {account_id} via PublicIntentUpdated (amount_remaining=0)"
            );
            return Ok(());
        }

        let Some(mut order) = self.state().get_account_order(&order_id).await? else {
            return Ok(());
        };

        order.intent.inner.amount_in = amount_remaining;
        order.metadata.mark_filled();
        self.state().update_order(order).await?.await?;
        Ok(())
    }

    /// Record match volume metrics for an external match transaction.
    ///
    /// We map the event to the first decoded external match for the same
    /// intent hash
    fn maybe_record_external_match_metrics(
        &self,
        tx_hash: TxHash,
        intent_hash: B256,
        fill_amount: Amount,
        account_id: AccountId,
        external_matches: &[(B256, BoundedMatchResult, Amount)],
    ) {
        let Some((match_res, external_amount_in)) =
            select_external_match_for_intent(external_matches, intent_hash)
        else {
            warn!(
                "Could not map PublicIntentUpdated to decoded external match call: no intent-hash match: tx={tx_hash:#x}, intent_hash={intent_hash:#x}, fill_amount={fill_amount}"
            );
            return;
        };

        if match_res.to_external_obligation(external_amount_in).amount_out != fill_amount {
            warn!(
                "Mapped PublicIntentUpdated to external match without fill-amount equality: tx={tx_hash:#x}, intent_hash={intent_hash:#x}, fill_amount={fill_amount}, external_amount_in={external_amount_in}"
            );
        }

        // Build the internal-party obligation represented by PublicIntentUpdated:
        // `fill_amount` is internal amount in, and the decoded calldata gives amount
        // out
        let obligation = SettlementObligation {
            input_token: match_res.internal_party_input_token,
            output_token: match_res.internal_party_output_token,
            amount_in: fill_amount,
            amount_out: external_amount_in,
        };

        record_match_volume_from_obligation(
            &obligation,
            true, // is_external_match
            &[account_id],
        );
    }

    /// Handle a PublicIntentCancelled event emitted when a user cancels their
    /// public intent on-chain
    ///
    /// Removes the order from the account.
    async fn handle_public_intent_cancelled(
        &self,
        log: Log,
        tx_hash: TxHash,
    ) -> Result<(), OnChainEventListenerError> {
        // Decode event data
        let event = log.log_decode::<PublicIntentCancelled>()?;
        let intent_hash = event.inner.intentHash;

        // Look up order by intent hash, skip if not managed by this relayer
        let Some((account_id, order_id)) =
            self.state().get_order_by_intent_hash(&intent_hash).await?
        else {
            return Ok(());
        };
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
        info!("Removed order {order_id} from account {account_id} via PublicIntentCancelled");

        // TODO: Emit cancellation event to notify clients

        Ok(())
    }
}

/// Select the first decoded external match for the provided intent hash.
///
/// We assume a transaction does not settle the same intent hash more than once.
fn select_external_match_for_intent(
    matches: &[(B256, BoundedMatchResult, Amount)],
    intent_hash: B256,
) -> Option<(BoundedMatchResult, Amount)> {
    let mut intent_candidates =
        matches.iter().filter(|(match_intent_hash, _, _)| *match_intent_hash == intent_hash);

    let (_, match_res, external_amount_in) = intent_candidates.next()?;
    Some((match_res.clone(), *external_amount_in))
}
