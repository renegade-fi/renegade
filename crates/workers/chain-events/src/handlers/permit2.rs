//! Permit2 Approval/Permit event handling and subscription management

use alloy::{
    primitives::{Address, B256},
    providers::{DynProvider, Provider},
    rpc::types::{Filter, Log},
    sol_types::SolEvent,
};
use darkpool_client::client::erc20::abis::permit2::IPermit2;
use futures_util::{
    StreamExt,
    stream::{self, LocalBoxStream},
};
use tracing::{info, warn};

use crate::{error::OnChainEventListenerError, executor::OnChainEventListenerExecutor};

/// Boxed local stream type for chain event log subscriptions.
type LogStream = LocalBoxStream<'static, Log>;

impl OnChainEventListenerExecutor {
    /// Create Permit2 subscriptions for Approval and Permit events
    ///
    /// Filters for events where:
    /// - topic1 (owner) matches tracked owners
    /// - topic3 (spender) is the darkpool contract
    pub(crate) async fn create_permit2_subscriptions(
        &self,
        client: &DynProvider,
    ) -> Result<(LogStream, LogStream), OnChainEventListenerError> {
        let owners = self.get_tracked_owners();
        info!("Tracking {} owners for Permit2", owners.len());

        let owner_topics: Vec<B256> = owners.into_iter().map(|addr| addr.into_word()).collect();
        if owner_topics.is_empty() {
            info!("No tracked owners; skipping Permit2 subscriptions");
            return Ok((stream::empty().boxed_local(), stream::empty().boxed_local()));
        }

        let permit2_addr = self.darkpool_client().permit2_addr();
        let spender_topic = self.darkpool_client().darkpool_addr().into_word();

        // Filter for Approval events: owner approves spender for token
        let approval_filter = Filter::new()
            .address(vec![permit2_addr])
            .event_signature(IPermit2::Approval::SIGNATURE_HASH)
            .topic1(owner_topics.clone())
            .topic3(vec![spender_topic]);

        // Filter for Permit events: signature-based approval
        let permit_filter = Filter::new()
            .address(vec![permit2_addr])
            .event_signature(IPermit2::Permit::SIGNATURE_HASH)
            .topic1(owner_topics)
            .topic3(vec![spender_topic]);

        let approval_stream =
            client.subscribe_logs(&approval_filter).await?.into_stream().boxed_local();
        let permit_stream =
            client.subscribe_logs(&permit_filter).await?.into_stream().boxed_local();

        Ok((approval_stream, permit_stream))
    }

    /// Handle a Permit2 Approval or Permit event
    ///
    /// Both events have the same effect on allowance state - they set the
    /// allowance for (owner, token, spender). We handle them identically.
    pub(crate) async fn handle_permit2_event(
        &self,
        log: Log,
    ) -> Result<(), OnChainEventListenerError> {
        // Extract owner and token from indexed topics
        // topics[0] = event signature, topics[1] = owner, topics[2] = token
        let topics = log.topics();
        if topics.len() < 3 {
            warn!("Permit2 event missing expected topics, skipping");
            return Ok(());
        }

        let owner = Address::from_word(topics[1]);
        let token = Address::from_word(topics[2]);
        let tx_hash = log.transaction_hash.unwrap_or_default();

        info!("Handling Permit2 event: owner={owner:#x}, token={token:#x}, tx={tx_hash:#x}");

        // Look up account by owner
        let Some(account_id) = self.state().get_account_by_owner(&owner).await? else {
            return Ok(());
        };

        // Only process if account has orders for this token
        let orders = self.state().get_orders_with_input_token(&account_id, &token).await?;
        if orders.is_empty() {
            return Ok(());
        }

        // Reuse existing balance update logic (already computes min(balance, permit))
        self.handle_balance_update(account_id, owner, token, tx_hash).await
    }
}
