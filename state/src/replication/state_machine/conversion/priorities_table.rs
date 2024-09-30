//! Shim code for converting between serialization formats for the priorities

use common::types::{gossip::ClusterId, wallet::OrderIdentifier};

use super::{can_deserialize_as, convert_serialized_bytes, SerializeKV};

/// Convert a serialized relayer fee entry from one serialization format to
/// another
pub(super) fn convert_priorities_entry(k: &[u8], v: &[u8]) -> Result<SerializeKV, String> {
    if can_deserialize_as::<OrderIdentifier>(k) {
        convert_order_priorities_entry(k, v)
    } else if can_deserialize_as::<ClusterId>(k) {
        convert_cluster_priorities_entry(k, v)
    } else {
        panic!("Invalid key type for priorities table");
    }
}

/// Convert a serialized order priority entry from one serialization format to
/// another
fn convert_order_priorities_entry(k: &[u8], v: &[u8]) -> Result<SerializeKV, String> {
    let k = convert_serialized_bytes::<OrderIdentifier>(&k)?;
    let v = convert_serialized_bytes::<u32>(&v)?;

    Ok((k, v))
}

/// Convert a serialized cluster priority entry from one serialization format to
/// another
fn convert_cluster_priorities_entry(k: &[u8], v: &[u8]) -> Result<SerializeKV, String> {
    let k = convert_serialized_bytes::<ClusterId>(&k)?;
    let v = convert_serialized_bytes::<u32>(&v)?;

    Ok((k, v))
}
