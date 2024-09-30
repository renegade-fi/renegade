//! Shim code for converting the order to wallet table from the old
//! serialization format to the new serialization format

use common::types::wallet::{OrderIdentifier, WalletIdentifier};

use super::{can_deserialize_as, convert_serialized_bytes, deserialize_as, SerializeKV};

/// Convert an entry in the order to wallet table from the old serialization
/// format to the new serialization format
pub fn convert_order_to_wallet_entry(k: &[u8], v: &[u8]) -> Result<SerializeKV, String> {
    let k = convert_serialized_bytes::<OrderIdentifier>(k)?;
    let v = convert_serialized_bytes::<WalletIdentifier>(v)?;

    Ok((k, v))
}
