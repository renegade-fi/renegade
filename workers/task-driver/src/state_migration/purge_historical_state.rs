//! Purges historical state
//!
//! This includes terminal historical orders and task history

use common::types::wallet::WalletIdentifier;
use state::State;
use tracing::error;

/// Purges historical state for all wallets
pub async fn purge_historical_state(state: &State) -> Result<(), String> {
    let wallets = state.get_all_wallets().await?;
    for wallet in wallets {
        purge_wallet_historical_state(state, wallet.wallet_id).await?;
    }

    Ok(())
}

/// Purges historical state for a single wallet
async fn purge_wallet_historical_state(
    state: &State,
    wallet_id: WalletIdentifier,
) -> Result<(), String> {
    purge_order_history(state, wallet_id).await?;
    purge_task_history(state, wallet_id).await
}

/// Purges all terminal orders from a wallet's order history
async fn purge_order_history(state: &State, wallet_id: WalletIdentifier) -> Result<(), String> {
    let res = state
        .with_write_tx(move |tx| {
            tx.purge_terminal_orders(&wallet_id)?;
            Ok(())
        })
        .await;

    if let Err(e) = res {
        error!("error purging order history for wallet {wallet_id}: {e}");
    }

    Ok(())
}

/// Purges a wallet's task history
async fn purge_task_history(state: &State, wallet_id: WalletIdentifier) -> Result<(), String> {
    let res = state
        .with_write_tx(move |tx| {
            tx.purge_task_history(&wallet_id)?;
            Ok(())
        })
        .await;

    if let Err(e) = res {
        error!("error purging task history for wallet {wallet_id}: {e}");
    }

    Ok(())
}
