//! Shim code for converting the task to key table from the old serialization
//! format to the new serialization format

use common::types::tasks::{TaskIdentifier, TaskQueueKey};

use super::{can_deserialize_as, convert_serialized_bytes, SerializeKV};

/// Convert an entry in the task to key table from the old serialization format
/// to the new serialization format
pub fn convert_task_to_key_entry(k: &[u8], v: &[u8]) -> Result<SerializeKV, String> {
    if can_deserialize_as::<TaskIdentifier>(k) {
        let k = convert_serialized_bytes::<TaskIdentifier>(k)?;
        let v = convert_serialized_bytes::<TaskQueueKey>(v)?;
        Ok((k, v))
    } else {
        Err("Invalid key type for task to key".to_string())
    }
}
