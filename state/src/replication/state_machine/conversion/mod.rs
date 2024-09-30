//! Shim code for converting between serialization formats
mod matching_pools;
mod order_history;
mod order_to_wallet;
mod orders_table;
mod priorities_table;
mod task_assignment;
mod task_history;
mod task_queue;
mod task_to_key;
mod wallets_table;

use libmdbx::{RO, RW};
use matching_pools::convert_matching_pool_entry;
use order_history::convert_order_history_entry;
use order_to_wallet::convert_order_to_wallet_entry;
use orders_table::convert_orders_entry;
use priorities_table::convert_priorities_entry;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use task_assignment::convert_task_assignment_entry;
use task_history::convert_task_history_entry;
use task_queue::convert_task_queue_entry;
use task_to_key::convert_task_to_key_entry;
use wallets_table::convert_wallets_entry;

use crate::{
    storage::{cursor::DbCursor, tx::StateTxn, CowBuffer},
    ORDERS_TABLE, ORDER_HISTORY_TABLE, ORDER_TO_WALLET_TABLE, POOL_TABLE, PRIORITIES_TABLE,
    TASK_ASSIGNMENT_TABLE, TASK_HISTORY_TABLE, TASK_QUEUE_TABLE, TASK_TO_KEY_TABLE, WALLETS_TABLE,
};

// const EXCLUDED_TABLES: &[&str] = &[
//     RAFT_LOGS_TABLE,
//     RAFT_METADATA_TABLE,
//     PEER_INFO_TABLE,
//     CLUSTER_MEMBERSHIP_TABLE,
//     NODE_METADATA_TABLE,
//     RELAYER_FEES_TABLE,
// ];

// pub const ALL_TABLES: [&str; NUM_TABLES] = [
//     PRIORITIES_TABLE, // done
//     ORDERS_TABLE, // done
//     ORDER_HISTORY_TABLE, // done
//     POOL_TABLE, // done
//     ORDER_TO_WALLET_TABLE, // done
//     WALLETS_TABLE, // done
//     TASK_QUEUE_TABLE, // done
//     TASK_TO_KEY_TABLE, // done
//     TASK_ASSIGNMENT_TABLE, // done
//     TASK_HISTORY_TABLE, // done
//     MPC_PREPROCESSING_TABLE, // skipped
// ];

/// A key-value pair with serialized keys and values
pub type SerializeKV = (Vec<u8>, Vec<u8>);

/// Convert a cursor of values from one serialization format to another
pub fn convert_serialized_values(
    table_name: &str,
    dest_tx: &StateTxn<'_, RW>,
    mut cursor: DbCursor<'_, RO, CowBuffer, CowBuffer>,
) -> Result<(), String> {
    while !cursor.seek_next_raw().map_err(|e| e.to_string())? {
        let (k, v) = cursor.get_current_raw().map_err(|e| e.to_string())?.unwrap();
        let (k, v) = match table_name {
            PRIORITIES_TABLE => convert_priorities_entry(&k, &v)?,
            ORDERS_TABLE => convert_orders_entry(&k, &v)?,
            ORDER_HISTORY_TABLE => convert_order_history_entry(&k, &v)?,
            POOL_TABLE => convert_matching_pool_entry(&k, &v)?,
            ORDER_TO_WALLET_TABLE => convert_order_to_wallet_entry(&k, &v)?,
            WALLETS_TABLE => convert_wallets_entry(&k, &v)?,
            TASK_QUEUE_TABLE => convert_task_queue_entry(&k, &v)?,
            TASK_TO_KEY_TABLE => convert_task_to_key_entry(&k, &v)?,
            TASK_ASSIGNMENT_TABLE => convert_task_assignment_entry(&k, &v)?,
            TASK_HISTORY_TABLE => convert_task_history_entry(&k, &v)?,
            _ => panic!("Unsupported table"),
        };

        // TODO: Insert into the db
        dest_tx.inner().write_raw(table_name, &k, &v).map_err(|e| e.to_string())?;
    }

    Ok(())
}

/// Tries to deserialize the buffer using bincode:
///   - If that fails, the format is assumed to be CBOR and the original buffer
///     is returned
///   - If that succeeds, the result is serialized using CBOR and returned
fn convert_serialized_bytes<'de, T: Deserialize<'de> + Serialize>(
    buf: &'de [u8],
) -> Result<Vec<u8>, String> {
    match bincode::deserialize::<T>(buf) {
        Ok(v) => {
            let mut buf = Vec::new();
            ciborium::ser::into_writer(&v, &mut buf)
                .map_err(|e| e.to_string())
                .map_err(|e| e.to_string())?;

            Ok(buf)
        },
        Err(_) => Ok(buf.to_vec()),
    }
}

/// Returns whether the buffer can be deserialized as a given type
fn can_deserialize_as<T: DeserializeOwned>(buf: &[u8]) -> bool {
    // Try bincode first, then ciborium
    if bincode::deserialize::<T>(buf).is_ok() {
        return true;
    }

    ciborium::de::from_reader::<T, _>(buf).is_ok()
}

/// Deserialize a buffer as a given type
/// Try bincode first, then ciborium
fn deserialize_as<'de, T: DeserializeOwned>(buf: &'de [u8]) -> Result<T, String> {
    match bincode::deserialize::<T>(buf) {
        Ok(v) => Ok(v),
        Err(_) => ciborium::de::from_reader::<T, _>(buf).map_err(|e| e.to_string()),
    }
}
