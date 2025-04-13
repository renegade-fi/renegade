//! Removes all existing queues with the old format

use std::borrow::Cow;

use state::{
    error::StateError,
    storage::{db::deserialize_value, tx::ReadTxn},
    State, TASK_QUEUE_TABLE,
};
use tracing::info;

/// Remove all existing queues with the old format
pub(crate) async fn remove_existing_queues(state: &State) -> Result<(), String> {
    let queues = get_existing_queues(state).await?;
    info!("removing {} queues", queues.len());
    delete_queues(state, queues).await?;
    info!("done removing queues");
    Ok(())
}

// --- Helpers --- //

/// A cowbuffer like in the state
type CowBuffer<'a> = Cow<'a, [u8]>;

/// Get all existing queues with the old format
async fn get_existing_queues(state: &State) -> Result<Vec<String>, String> {
    state.with_read_tx(get_all_queues_with_tx).await.map_err(|e| e.to_string())
}

/// Get all queues with a tx
fn get_all_queues_with_tx<'a>(tx: &ReadTxn<'a>) -> Result<Vec<String>, StateError> {
    let mut cursor = tx.inner().cursor::<String, CowBuffer>(TASK_QUEUE_TABLE)?;

    let mut queues = Vec::new();
    while !cursor.seek_next_raw()? {
        let key = cursor.get_current_raw()?;
        if key.is_none() {
            continue;
        }

        let (key, _) = key.unwrap();
        if let Ok(key_str) = deserialize_value::<String>(&key) {
            if key_str.starts_with("task-queue-") {
                queues.push(key_str);
            }
        }
    }

    Ok(queues)
}

/// Delete all the given queues
async fn delete_queues(state: &State, queues: Vec<String>) -> Result<(), String> {
    state
        .with_write_tx(|tx| {
            for key in queues {
                tx.inner().delete(TASK_QUEUE_TABLE, &key)?;
            }
            Ok(())
        })
        .await
        .map_err(|e| e.to_string())
}
