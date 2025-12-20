//! Removes old proofs from the state

use common::types::wallet::OrderIdentifier;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use state::{State, storage::tx::RwTxn};
use tracing::{info, warn};

/// Removes old proofs from the state
pub async fn remove_old_proofs(state: &State) -> Result<(), String> {
    state
        .with_write_tx(move |tx| {
            if let Err(e) = remove_old_proofs_with_tx(tx) {
                warn!("error removing old proofs: {e}");
            }

            Ok(())
        })
        .await?;

    Ok(())
}

/// Remove old proofs with a tx
fn remove_old_proofs_with_tx(tx: &RwTxn) -> Result<(), String> {
    let cursor = tx.inner().cursor::<String, AnyValue>("proofs").map_err(|e| e.to_string())?;
    let iter = cursor.into_iter();

    let mut n_deleted = 0;
    for res in iter {
        let (k, _v) = res.map_err(|e| e.to_string())?;
        let oid = k.split(":").last().unwrap();
        let oid = OrderIdentifier::parse_str(oid).map_err(|e| e.to_string())?;

        if tx.contains_order(&oid).map_err(|e| e.to_string())? {
            continue;
        }

        tx.delete_proofs_for_order(&oid).map_err(|e| e.to_string())?;
        n_deleted += 1;
    }

    info!("deleted old proofs for {n_deleted} phantom orders");
    Ok(())
}

/// A type that deserializes from any input (we only care about keys)
#[derive(Debug, Clone)]
struct AnyValue;

impl<'de> Deserialize<'de> for AnyValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        serde::de::IgnoredAny::deserialize(deserializer)?;
        Ok(AnyValue)
    }
}

impl Serialize for AnyValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_unit()
    }
}
