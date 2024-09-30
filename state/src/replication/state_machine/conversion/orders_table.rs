//! Shim code for converting the orders table from the old serialization format
//! to the new format

use crate::replication::state_machine::conversion::{convert_serialized_values, SerializeKV};
use common::types::{
    network_order::NetworkOrder, proof_bundles::OrderValidityWitnessBundle, wallet::OrderIdentifier,
};
use serde::de::DeserializeOwned;

use super::{can_deserialize_as, convert_serialized_bytes, deserialize_as};

/// Convert an entry in the orders table from the old serialization format to
/// the new serialization format
pub fn convert_orders_entry(k: &[u8], v: &[u8]) -> Result<SerializeKV, String> {
    // All keys are strings in the order table
    if can_deserialize_as::<String>(k) {
        convert_with_string_key(k, v)
    } else {
        Err("Invalid key type for orders table".to_string())
    }
}

/// Convert an entry in the orders table from the old serialization format to
/// the new serialization format
#[allow(clippy::if_same_then_else)]
pub fn convert_with_string_key(k: &[u8], v: &[u8]) -> Result<SerializeKV, String> {
    let k_out = convert_serialized_bytes::<String>(k)?;
    let k_str = deserialize_as::<String>(k)?;
    let v_out;

    if k_str.starts_with("order:") {
        v_out = convert_serialized_bytes::<(NetworkOrder, Option<OrderValidityWitnessBundle>)>(v)?;
    } else if k_str.starts_with("nullifier:") {
        v_out = convert_serialized_bytes::<Vec<OrderIdentifier>>(v)?;
    } else if k_str == "local-orders" {
        v_out = convert_serialized_bytes::<Vec<OrderIdentifier>>(v)?;
    } else {
        return Err("Invalid key type for orders table".to_string());
    }

    Ok((k_out, v_out))
}
