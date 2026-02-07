//! Helper functions for the HTTP API

use std::time::Duration;

use darkpool_types::{
    balance::{DarkpoolBalance, DarkpoolStateBalance},
    intent::{DarkpoolStateIntent, Intent},
};
use external_api::types::ApiOrderCore;
use job_types::task_driver::{TaskDriverQueue, new_task_notification};
use state::State;
use tokio::time::timeout;
use types_account::{
    MatchingPoolName, OrderId,
    order::{OrderMetadata, PrivacyRing},
    order_auth::OrderAuth,
};
use types_core::AccountId;
use types_tasks::{CreateOrderTaskDescriptor, TaskDescriptor, TaskIdentifier};

use crate::{
    error::{ApiServerError, bad_request, internal_error},
    http::account::account_not_found,
};

/// The timeout for awaiting a blocking task completion
const BLOCKING_TASK_TIMEOUT: Duration = Duration::from_secs(30);

/// Append a task to the task queue
///
/// If `blocking` is true, the function will await the task's completion
/// with a 30-second timeout.
pub async fn append_task(
    task: TaskDescriptor,
    blocking: bool,
    state: &State,
    task_queue: &TaskDriverQueue,
) -> Result<TaskIdentifier, ApiServerError> {
    let (tid, waiter) = state.append_task(task).await?;
    waiter.await?;

    if !blocking {
        return Ok(tid);
    }

    // Register for task completion notification and await with timeout
    let (rx, job) = new_task_notification(tid);
    task_queue.send(job).map_err(|e| internal_error(e.to_string()))?;

    match timeout(BLOCKING_TASK_TIMEOUT, rx).await {
        Ok(Ok(Ok(()))) => Ok(tid),
        Ok(Ok(Err(e))) => Err(internal_error(e)),
        Ok(Err(_recv_err)) => Err(internal_error("task notification channel closed unexpectedly")),
        Err(_timeout) => Err(internal_error("task timeout")),
    }
}

/// Append a create order task to the task queue
pub(crate) async fn append_create_order_task(
    account_id: AccountId,
    order: ApiOrderCore,
    auth: OrderAuth,
    matching_pool: MatchingPoolName,
    blocking: bool,
    state: &State,
    task_queue: &TaskDriverQueue,
) -> Result<TaskIdentifier, ApiServerError> {
    let order_id = order.id;
    let (intent, ring, metadata) = order.into_order_components();
    let descriptor = match ring {
        PrivacyRing::Ring0 => {
            create_ring0_order_task_descriptor(
                account_id,
                order_id,
                intent,
                metadata,
                auth,
                matching_pool,
            )
            .await
        },
        PrivacyRing::Ring1 => {
            create_ring1_order_task_descriptor(
                account_id,
                order_id,
                intent,
                metadata,
                auth,
                matching_pool,
                state,
            )
            .await
        },
        PrivacyRing::Ring2 => {
            create_ring2_order_task_descriptor(
                account_id,
                order_id,
                intent,
                metadata,
                auth,
                matching_pool,
                state,
            )
            .await
        },
        _ => unreachable!("ring must be Ring0, Ring1, or Ring2, got {ring:?}"),
    }?;

    append_task(descriptor.into(), blocking, state, task_queue).await
}

/// Create a ring 0 order task descriptor
async fn create_ring0_order_task_descriptor(
    account_id: AccountId,
    order_id: OrderId,
    intent: Intent,
    metadata: OrderMetadata,
    auth: OrderAuth,
    matching_pool: MatchingPoolName,
) -> Result<CreateOrderTaskDescriptor, ApiServerError> {
    let descriptor = CreateOrderTaskDescriptor::new_ring0(
        account_id,
        order_id,
        intent,
        metadata,
        auth,
        matching_pool,
    )
    .map_err(bad_request)?;
    Ok(descriptor)
}

/// Create a ring 1 order task descriptor
async fn create_ring1_order_task_descriptor(
    account_id: AccountId,
    order_id: OrderId,
    intent: Intent,
    metadata: OrderMetadata,
    auth: OrderAuth,
    matching_pool: MatchingPoolName,
    state: &State,
) -> Result<CreateOrderTaskDescriptor, ApiServerError> {
    // Build a new intent
    let mut keychain =
        state.get_account_keychain(&account_id).await?.ok_or_else(account_not_found)?;
    let share_seed = keychain.sample_share_stream().seed;
    let recovery_seed = keychain.sample_recovery_id_stream().seed;
    let original_intent = DarkpoolStateIntent::new(intent.clone(), share_seed, recovery_seed);

    // The signature is over the intent's initial commitment
    let commitment = original_intent.compute_commitment();
    let descriptor = CreateOrderTaskDescriptor::new_ring1(
        account_id,
        order_id,
        intent,
        commitment,
        metadata,
        auth,
        matching_pool,
    )
    .map_err(bad_request)?;
    Ok(descriptor)
}

/// Create a ring 2 order task descriptor
async fn create_ring2_order_task_descriptor(
    account_id: AccountId,
    order_id: OrderId,
    intent: Intent,
    metadata: OrderMetadata,
    auth: OrderAuth,
    matching_pool: MatchingPoolName,
    state: &State,
) -> Result<CreateOrderTaskDescriptor, ApiServerError> {
    let mut keychain =
        state.get_account_keychain(&account_id).await?.ok_or_else(account_not_found)?;
    let authority = keychain.schnorr_public_key;

    // Compute a commitment to the new intent
    let share_seed = keychain.sample_share_stream().seed;
    let recovery_seed = keychain.sample_recovery_id_stream().seed;
    let original_intent = DarkpoolStateIntent::new(intent.clone(), share_seed, recovery_seed);
    let intent_commitment = original_intent.compute_commitment();

    // Compute a balance commitment if necessary
    let mut balance_commitment = None;
    let out_token = intent.out_token;
    if state.get_account_darkpool_balance(&account_id, &out_token).await?.is_none() {
        // New balance needs to be created
        let relayer_fee_recipient = state.get_relayer_fee_addr()?;
        let inner = DarkpoolBalance::new(out_token, intent.owner, relayer_fee_recipient, authority);

        let share_seed = keychain.sample_share_stream().seed;
        let recovery_seed = keychain.sample_recovery_id_stream().seed;
        let balance = DarkpoolStateBalance::new(inner, share_seed, recovery_seed);
        balance_commitment = Some(balance.compute_commitment());
    }

    let descriptor = CreateOrderTaskDescriptor::new_ring2(
        account_id,
        order_id,
        intent,
        intent_commitment,
        balance_commitment,
        authority,
        metadata,
        auth,
        matching_pool,
    )
    .map_err(bad_request)?;
    Ok(descriptor)
}
