//! Removes a single wallet from the state so that it may be refreshed

use common::types::wallet::WalletIdentifier;
use state::State;
use tracing::{info, warn};

/// The ID of the quoter wallet to remove
const QUOTER_WALLET_ID: &str = "e48509a3-6eba-9015-5cde-ac031d1e517e";

/// Remove a single wallet from the state so that it may be refreshed
pub(crate) async fn remove_quoter_wallet(state: &State) -> Result<(), String> {
    let wid = WalletIdentifier::parse_str(QUOTER_WALLET_ID).map_err(|e| e.to_string())?;

    info!("removing quoter wallet: {:?}", wid);
    state
        .with_write_tx(move |tx| {
            let wallet = tx.get_wallet(&wid)?;
            if wallet.is_none() {
                warn!("wallet not found, skipping");
                return Ok(());
            }

            let wallet = wallet.unwrap();
            let wallet_json = serde_json::to_string(&wallet).expect("failed to serialize wallet");
            info!("removed wallet: {}", wallet_json);

            // Remove the wallet from the state
            tx.remove_wallet(&wid)?;
            Ok(())
        })
        .await?;

    Ok(())
}
