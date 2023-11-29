//! Groups state primitives for indexing and tracking wallet information

use std::collections::HashMap;

use common::types::{
    gossip::WrappedPeerId,
    wallet::{OrderIdentifier, Wallet, WalletAuthenticationPath, WalletIdentifier, WalletMetadata},
};

use common::{new_async_shared, AsyncShared};
use futures::{stream::iter as to_stream, StreamExt};
use itertools::Itertools;
use tokio::sync::{RwLockReadGuard, RwLockWriteGuard};
use uuid::Uuid;

// ------------------
// | State Indexing |
// ------------------

/// An abstraction over a set of wallets that indexes wallets and de-normalizes
/// their data
#[derive(Clone, Debug)]
pub struct WalletIndex {
    /// The peer_id of the local node
    peer_id: WrappedPeerId,
    /// A mapping from wallet ID to wallet information
    wallet_map: HashMap<Uuid, AsyncShared<Wallet>>,
    /// A reverse index mapping from order to wallet
    order_to_wallet: HashMap<OrderIdentifier, WalletIdentifier>,
}

impl WalletIndex {
    /// Create a wallet index
    pub fn new(peer_id: WrappedPeerId) -> Self {
        Self { peer_id, wallet_map: HashMap::new(), order_to_wallet: HashMap::new() }
    }

    // -----------
    // | Locking |
    // -----------

    /// Acquire a read lock on a wallet
    pub async fn read_wallet(&self, wallet_id: &Uuid) -> Option<RwLockReadGuard<Wallet>> {
        if let Some(locked_wallet) = self.wallet_map.get(wallet_id) {
            Some(locked_wallet.read().await)
        } else {
            None
        }
    }

    /// Acquire a write lock on a wallet
    pub async fn write_wallet(&self, wallet_id: &Uuid) -> Option<RwLockWriteGuard<Wallet>> {
        if let Some(locked_wallet) = self.wallet_map.get(wallet_id) {
            Some(locked_wallet.write().await)
        } else {
            None
        }
    }

    // -----------
    // | Getters |
    // -----------

    /// Get the wallet with the given ID
    pub async fn get_wallet(&self, wallet_id: &WalletIdentifier) -> Option<Wallet> {
        self.read_wallet(wallet_id).await.map(|locked_val| locked_val.clone())
    }

    /// Get the wallet that an order is allocated in
    pub fn get_wallet_for_order(&self, order_id: &OrderIdentifier) -> Option<WalletIdentifier> {
        self.order_to_wallet.get(order_id).cloned()
    }

    /// Get all the wallet ids that are indexed
    pub fn get_all_wallet_ids(&self) -> Vec<WalletIdentifier> {
        self.wallet_map.keys().cloned().collect_vec()
    }

    /// Returns a list of all wallets
    pub async fn get_all_wallets(&self) -> Vec<Wallet> {
        to_stream(self.wallet_map.values().cloned())
            .then(|locked_wallet| async move { locked_wallet.read().await.clone() })
            .collect::<Vec<_>>()
            .await
    }

    /// Returns a mapping from wallet ID to the wallet's metadata
    ///
    /// Used to serialize into the handshake response
    pub async fn get_metadata_map(&self) -> HashMap<WalletIdentifier, WalletMetadata> {
        let mut res = HashMap::new();
        for (id, wallet) in self.wallet_map.iter() {
            res.insert(*id, wallet.read().await.metadata.clone());
        }

        res
    }

    // -----------
    // | Setters |
    // -----------

    /// Add a concurrency safe wallet to the index
    pub fn add_wallet(&mut self, mut wallet: Wallet) {
        // Add orders in the wallet to the inverse mapping
        for order_id in wallet.orders.keys() {
            self.order_to_wallet.insert(*order_id, wallet.wallet_id);
        }

        // Index the wallet
        wallet.metadata.replicas.insert(self.peer_id);
        self.wallet_map.insert(wallet.wallet_id, new_async_shared(wallet));
    }

    /// Add a given peer as a replica of a wallet
    pub async fn add_replica(&self, wallet_id: &WalletIdentifier, peer_id: WrappedPeerId) {
        if let Some(wallet) = self.wallet_map.get(wallet_id) {
            wallet.write().await.metadata.replicas.insert(peer_id);
        }
    }

    /// Add a Merkle authentication proof for a given wallet
    pub async fn add_wallet_merkle_proof(
        &self,
        wallet_id: &WalletIdentifier,
        merkle_proof: WalletAuthenticationPath,
    ) {
        if let Some(wallet) = self.wallet_map.get(wallet_id) {
            wallet.write().await.merkle_proof = Some(merkle_proof)
        }
    }

    /// Merge metadata for a given wallet into the local wallet state
    pub async fn merge_metadata(&self, wallet_id: &WalletIdentifier, metadata: &WalletMetadata) {
        if let Some(wallet) = self.wallet_map.get(wallet_id) {
            if wallet.read().await.metadata.replicas.is_superset(&metadata.replicas) {
                return;
            }

            // Acquire a write lock only if we are missing replicas
            let mut locked_wallet = wallet.write().await;
            locked_wallet.metadata.replicas.extend(&metadata.replicas);
        }
    }

    /// Expire peers as replicas of each wallet we know about
    ///
    /// This method is called when a cluster peer is determined to have failed;
    /// we should update the replication state and take any steps necessary
    /// to get the wallet replicated on a safe number of peers
    pub async fn remove_peer_replicas(&self, peer: &WrappedPeerId) {
        for (_, wallet) in self.wallet_map.iter() {
            let mut locked_wallet = wallet.write().await;
            locked_wallet.metadata.replicas.remove(peer);
        }
    }
}

#[cfg(test)]
mod tests {
    use common::types::wallet::PrivateKeyChain;
    use constants::Scalar;
    use num_bigint::BigUint;
    use rand::thread_rng;

    /// Test serialization/deserialization of a PrivateKeyChain
    #[test]
    fn test_private_keychain_serde() {
        let mut rng = thread_rng();

        // Test with root specified
        let keychain = PrivateKeyChain {
            sk_root: Some((&BigUint::from(0u8)).into()),
            sk_match: Scalar::random(&mut rng).into(),
        };
        let serialized = serde_json::to_string(&keychain).unwrap();
        let deserialized: PrivateKeyChain = serde_json::from_str(&serialized).unwrap();
        assert_eq!(keychain, deserialized);

        // Test with no root specified
        let keychain = PrivateKeyChain { sk_root: None, sk_match: Scalar::random(&mut rng).into() };
        let serialized = serde_json::to_string(&keychain).unwrap();
        let deserialized: PrivateKeyChain = serde_json::from_str(&serialized).unwrap();
        assert_eq!(keychain, deserialized);
    }
}
