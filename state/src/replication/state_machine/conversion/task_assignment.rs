//! Shim code for converting the task assignment table from the old
//! serialization format to the new serialization format

use common::types::{gossip::WrappedPeerId, tasks::TaskIdentifier};

use super::{can_deserialize_as, convert_serialized_bytes, deserialize_as, SerializeKV};

/// Convert an entry in the task assignment table from the old serialization
/// format to the new serialization format
pub fn convert_task_assignment_entry(k: &[u8], v: &[u8]) -> Result<SerializeKV, String> {
    if can_deserialize_as::<String>(k) {
        convert_task_assignment_key(k, v)
    } else {
        Err("Invalid key type for task assignment".to_string())
    }
}

/// Convert a task assignment key from the old serialization format to the new
fn convert_task_assignment_key(k: &[u8], v: &[u8]) -> Result<SerializeKV, String> {
    let k_str = deserialize_as::<String>(k)?;
    let k_out = convert_serialized_bytes::<String>(k)?;

    if k_str.starts_with("task-assignment-") {
        let v_out = convert_serialized_bytes::<WrappedPeerId>(v)?;
        Ok((k_out, v_out))
    } else if k_str.starts_with("assigned-tasks-") {
        let v_out = convert_serialized_bytes::<Vec<TaskIdentifier>>(v)?;
        Ok((k_out, v_out))
    } else {
        Err("Invalid key type for task assignment".to_string())
    }
}
