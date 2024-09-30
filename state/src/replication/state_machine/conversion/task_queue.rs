//! Shim code for converting the task queue from the old serialization format to
//! the new serialization format

use std::collections::VecDeque;

use common::types::tasks::{QueuedTask, TaskQueueKey};

use super::{can_deserialize_as, convert_serialized_bytes, SerializeKV};

/// Convert an entry in the task queue from the old serialization format to the
/// new serialization format
pub fn convert_task_queue_entry(k: &[u8], v: &[u8]) -> Result<SerializeKV, String> {
    if can_deserialize_as::<TaskQueueKey>(k) {
        let k = convert_serialized_bytes::<TaskQueueKey>(k)?;
        let v = convert_serialized_bytes::<VecDeque<QueuedTask>>(v)?;
        Ok((k, v))
    } else if can_deserialize_as::<String>(k) {
        let k = convert_serialized_bytes::<String>(k)?;
        let v = convert_serialized_bytes::<bool>(v)?;
        Ok((k, v))
    } else {
        return Err("Invalid key type for task queue".to_string());
    }
}
