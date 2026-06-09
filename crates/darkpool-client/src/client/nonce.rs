//! A nonce manager that can be resynced from the chain after a lost
//! transaction
//!
//! Mirrors alloy's `CachedNonceManager` (locked, sequential nonces per signer)
//! with one addition: `poison(address)` marks the cached nonce stale, so the
//! next fill refetches the chain's PENDING count instead of incrementing the
//! cache. Without this, a transaction that is acked by the RPC but never mined
//! leaves the cache one ahead of the chain forever: every subsequent tx from
//! the signer is nonce-gapped behind the lost head and the signer is wedged
//! until process restart (observed 2026-06-09: signers pinned 45+ minutes).
//!
//! Refetching PENDING lands the next tx on the lost head's nonce, filling the
//! gap; any still-queued higher-nonce txs then become valid. A replayed
//! settlement that already executed reverts at the darkpool (nonce already
//! spent), which the task layer already handles as a normal failure.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex as StdMutex},
};

use alloy::{
    network::Network,
    providers::{Provider, fillers::NonceManager},
    transports::TransportResult,
};
use alloy_primitives::Address;
use tokio::sync::Mutex;
use tracing::info;

/// A per-signer cached nonce manager whose cache can be invalidated
/// (poisoned) after a failed submission
#[derive(Clone, Debug, Default)]
pub struct ResyncNonceManager {
    /// The cached last-used nonce per signer, `None` until first fetch.
    ///
    /// The outer std mutex is held only to clone the inner `Arc` (never across
    /// an await); the inner tokio mutex serializes nonce assignment per
    /// signer, mirroring alloy's `CachedNonceManager`.
    nonces: Arc<StdMutex<HashMap<Address, Arc<Mutex<Option<u64>>>>>>,
    /// Signers whose cache must be refetched from the chain on next use
    poisoned: Arc<StdMutex<HashMap<Address, bool>>>,
}

impl ResyncNonceManager {
    /// Mark the signer's cached nonce stale; the next fill refetches the
    /// chain's pending transaction count
    pub fn poison(&self, address: Address) {
        self.poisoned.lock().expect("nonce poison lock").insert(address, true);
    }

    /// Take (and clear) the signer's poisoned flag
    fn take_poisoned(&self, address: Address) -> bool {
        self.poisoned.lock().expect("nonce poison lock").remove(&address).unwrap_or(false)
    }

    /// Get the per-signer nonce slot
    fn nonce_slot(&self, address: Address) -> Arc<Mutex<Option<u64>>> {
        let mut map = self.nonces.lock().expect("nonce map lock");
        Arc::clone(map.entry(address).or_default())
    }
}

#[async_trait::async_trait]
impl NonceManager for ResyncNonceManager {
    async fn get_next_nonce<P, N>(&self, provider: &P, address: Address) -> TransportResult<u64>
    where
        P: Provider<N>,
        N: Network,
    {
        let slot = self.nonce_slot(address);
        let mut nonce = slot.lock().await;

        // Check the poison flag AFTER acquiring the per-signer lock so a
        // poison racing an in-flight fill applies to the next fill
        let resync = self.take_poisoned(address);
        let next = match *nonce {
            Some(last_used) if !resync => last_used + 1,
            prev => {
                // First use, or resync after a lost tx: the chain's pending
                // count is exactly the next nonce that can mine
                let pending = provider.get_transaction_count(address).pending().await?;
                if resync {
                    info!(
                        signer = %address,
                        cached = ?prev,
                        chain_pending = pending,
                        "nonce cache resynced from chain after failed submission"
                    );
                }
                pending
            },
        };

        *nonce = Some(next);
        Ok(next)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Poisoning is per-signer and one-shot
    #[test]
    fn test_poison_take_semantics() {
        let mgr = ResyncNonceManager::default();
        let a = Address::with_last_byte(1);
        let b = Address::with_last_byte(2);

        assert!(!mgr.take_poisoned(a));
        mgr.poison(a);
        assert!(mgr.take_poisoned(a), "poison must be observed");
        assert!(!mgr.take_poisoned(a), "poison must be one-shot");
        assert!(!mgr.take_poisoned(b), "poison must be per-signer");
    }
}
