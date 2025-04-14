//! Removes old task queues from the state

use std::borrow::Cow;

use state::{
    error::StateError,
    storage::{db::deserialize_value, traits::Key, tx::ReadTxn},
    State, TASK_QUEUE_TABLE, TASK_TO_KEY_TABLE,
};
use tracing::info;
use uuid::Uuid;

/// A type alias used for reading from the database
type CowBuffer<'a> = Cow<'a, [u8]>;

/// Remove all old task queues from the state
pub(crate) async fn remove_old_queues(state: &State) -> Result<(), String> {
    // Old task queues
    let keys = find_old_task_queues(state).await?;
    info!("found {} old task queues", keys.len());
    delete_keys(state, keys, TASK_QUEUE_TABLE).await?;
    info!("deleted old task queues");

    // Old paused queues
    let paused_keys = find_old_paused_queues(state).await?;
    info!("found {} old paused queues", paused_keys.len());
    delete_keys(state, paused_keys, TASK_QUEUE_TABLE).await?;
    info!("deleted old paused queues");

    // Old task -> queue mappings
    let mappings = find_old_task_to_queue_mappings(state).await?;
    info!("found {} old task -> queue mappings", mappings.len());
    delete_keys(state, mappings, TASK_TO_KEY_TABLE).await?;
    info!("deleted old task -> queue mappings");

    Ok(())
}

// --- Find Queues --- //

/// Find all old task queues
async fn find_old_task_queues(state: &State) -> Result<Vec<Uuid>, StateError> {
    state.with_read_tx(find_old_task_queues_with_tx).await
}

/// Find all old task queue keys with a tx scoped in
fn find_old_task_queues_with_tx(tx: &ReadTxn) -> Result<Vec<Uuid>, StateError> {
    let mut cursor = tx.inner().cursor::<CowBuffer, CowBuffer>(TASK_QUEUE_TABLE).unwrap();
    let mut keys = Vec::new();
    while !cursor.seek_next_raw()? {
        let pair = cursor.get_current_raw()?;
        if pair.is_none() {
            continue;
        }

        let (key, _) = pair.unwrap();
        if let Ok(id) = deserialize_value(&key) {
            keys.push(id);
        }
    }

    Ok(keys)
}

/// Find all the old paused queue keys in the state
async fn find_old_paused_queues(state: &State) -> Result<Vec<String>, StateError> {
    state.with_read_tx(find_old_paused_queues_with_tx).await
}

/// Find all the old paused queue keys in the state with a tx scoped in
fn find_old_paused_queues_with_tx(tx: &ReadTxn) -> Result<Vec<String>, StateError> {
    let mut cursor = tx.inner().cursor::<CowBuffer, CowBuffer>(TASK_QUEUE_TABLE).unwrap();
    let mut keys = Vec::new();
    while !cursor.seek_next_raw()? {
        let pair = cursor.get_current_raw()?;
        if pair.is_none() {
            continue;
        }

        let (key, _) = pair.unwrap();
        if let Ok(value) = deserialize_value::<String>(&key)
            && value.ends_with("paused")
        {
            keys.push(value);
        }
    }

    Ok(keys)
}

/// Find all old task -> queue mappings
async fn find_old_task_to_queue_mappings(state: &State) -> Result<Vec<Uuid>, StateError> {
    state.with_read_tx(find_old_task_to_queue_mappings_with_tx).await
}

/// Find all old task -> queue mappings with a tx scoped in
fn find_old_task_to_queue_mappings_with_tx(tx: &ReadTxn) -> Result<Vec<Uuid>, StateError> {
    let mut cursor = tx.inner().cursor::<CowBuffer, CowBuffer>(TASK_TO_KEY_TABLE).unwrap();
    let mut keys = Vec::new();
    while !cursor.seek_next_raw()? {
        let pair = cursor.get_current_raw()?;
        if pair.is_none() {
            continue;
        }

        let (key, _) = pair.unwrap();
        if let Ok(value) = deserialize_value::<Uuid>(&key) {
            keys.push(value);
        }
    }

    Ok(keys)
}

// --- Delete Queues --- //

/// Delete a set of keys from the state
async fn delete_keys<K: Key + Send + Sync + 'static>(
    state: &State,
    keys: Vec<K>,
    table: &'static str,
) -> Result<(), String> {
    state
        .with_write_tx(move |tx| {
            for key in keys.iter() {
                tx.inner().delete(table, key)?;
            }
            Ok(())
        })
        .await
        .map_err(|e| e.to_string())
}
