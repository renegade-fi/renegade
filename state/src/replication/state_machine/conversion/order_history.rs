//! Shim code for converting the order history table from the old serialization
//! format to the new serialization format

use common::types::wallet::{order_metadata::OrderMetadata, WalletIdentifier};

use crate::replication::state_machine::conversion::deserialize_as;

use super::{can_deserialize_as, convert_serialized_bytes, SerializeKV};

/// Convert an entry in the order history table from the old serialization
/// format to the new serialization format
pub fn convert_order_history_entry(k: &[u8], v: &[u8]) -> Result<SerializeKV, String> {
    if can_deserialize_as::<String>(k) {
        let k = convert_serialized_bytes::<String>(k)?;
        let v = convert_serialized_bytes::<Vec<OrderMetadata>>(v)?;

        Ok((k, v))
    } else {
        Err("Invalid key type for order history table".to_string())
    }
}

/// Convert an entry in the order history table from the old serialization
/// format to the new serialization format
pub fn convert_with_wallet_id_key(k: &[u8], v: &[u8]) -> Result<SerializeKV, String> {
    let k = convert_serialized_bytes::<WalletIdentifier>(k)?;
    let v = convert_serialized_bytes::<Vec<u8>>(v)?;

    Ok((k, v))
}
