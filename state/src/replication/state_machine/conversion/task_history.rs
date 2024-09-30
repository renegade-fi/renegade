//! Shim code for converting the task history table from the old serialization
//! format to the new serialization format

use common::types::tasks::HistoricalTask;

use super::{convert_serialized_bytes, SerializeKV};

/// Convert an entry in the task history table from the old serialization format
/// to the new serialization format
pub fn convert_task_history_entry(k: &[u8], v: &[u8]) -> Result<SerializeKV, String> {
    let k = convert_serialized_bytes::<String>(k)?;
    let v = convert_serialized_bytes::<Vec<HistoricalTask>>(v)?;
    Ok((k, v))
}
