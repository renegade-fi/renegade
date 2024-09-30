//! Shim code for converting the wallets table from the old serialization
//! format to the new serialization format

use common::types::wallet::{Wallet, WalletIdentifier};

use super::{convert_serialized_bytes, SerializeKV};

/// Convert an entry in the wallets table from the old serialization format to
/// the new serialization format
pub fn convert_wallets_entry(k: &[u8], v: &[u8]) -> Result<SerializeKV, String> {
    let k = convert_serialized_bytes::<WalletIdentifier>(k)?;
    let v = convert_serialized_bytes::<Wallet>(v)?;
    Ok((k, v))
}
