//! Shim code for converting the matching pools table from the old serialization
//! format to the new serialization format

use common::types::MatchingPoolName;

use crate::storage::tx::matching_pools::POOL_KEY_PREFIX;

use super::{can_deserialize_as, convert_serialized_bytes, deserialize_as, SerializeKV};

/// Convert an entry in the matching pools table from the old serialization
/// format to the new serialization format
pub fn convert_matching_pool_entry(k: &[u8], v: &[u8]) -> Result<SerializeKV, String> {
    let k_str = deserialize_as::<String>(k)?;
    let k_out = convert_serialized_bytes::<String>(k)?;

    if k_str == "all-matching-pools" {
        let v = convert_serialized_bytes::<Vec<MatchingPoolName>>(v)?;
        Ok((k_out, v))
    } else if k_str.starts_with(POOL_KEY_PREFIX) {
        let v = convert_serialized_bytes::<String>(v)?;
        Ok((k_out, v))
    } else {
        Err("Invalid key type for matching pools table".to_string())
    }
}
