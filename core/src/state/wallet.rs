//! Groups state primitives for indexing and tracking wallet information

use std::{
    collections::{HashMap, HashSet},
    fmt::{Display, Formatter, Result as FmtResult},
    sync::RwLockReadGuard,
};

use circuits::types::{balance::Balance, fee::Fee, order::Order};
use itertools::Itertools;
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use termion::color;
use uuid::Uuid;

use crate::{gossip::types::WrappedPeerId, handshake::types::OrderIdentifier};

use super::{new_shared, Shared};

/// An error message to panic with when a wallet lock is poisoned
const ERR_WALLET_POISONED: &str = "wallet lock poisoned";

/// A type alias for the wallet identifier type, currently a UUID
pub type WalletIdentifier = Uuid;
/// Represents a wallet managed by the local relayer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Wallet {
    /// The identifier used to index the wallet
    pub wallet_id: WalletIdentifier,
    /// A list of orders in this wallet
    pub orders: HashMap<OrderIdentifier, Order>,
    /// A mapping of mint (u64) to Balance information
    pub balances: HashMap<u64, Balance>,
    /// A list of the fees in this wallet
    pub fees: Vec<Fee>,
    /// Wallet metadata; replicas, trusted peers, etc
    pub metadata: WalletMetadata,
}

/// Metadata relevant to the wallet's network state
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletMetadata {
    /// The peers which are believed by the local node to be replicating a given wallet
    pub replicas: HashSet<WrappedPeerId>,
}

/// An abstraction over a set of wallets that indexes wallet and de-normalizes
/// their data
#[derive(Clone, Debug)]
pub struct WalletIndex {
    /// The peer_id of the local node
    peer_id: WrappedPeerId,
    /// A mapping from wallet ID to wallet information
    wallet_map: HashMap<Uuid, Shared<Wallet>>,
}

impl WalletIndex {
    /// Create a wallet index
    pub fn new(peer_id: WrappedPeerId) -> Self {
        Self {
            peer_id,
            wallet_map: HashMap::new(),
        }
    }

    // -----------
    // | Locking |
    // -----------

    /// Acquire a read lock on a wallet
    pub fn read_wallet(&self, wallet_id: &Uuid) -> Option<RwLockReadGuard<Wallet>> {
        self.wallet_map
            .get(wallet_id)
            .map(|wallet| wallet.read().expect(ERR_WALLET_POISONED))
    }

    // -----------
    // | Getters |
    // -----------

    /// Return a random wallet, used for sampling wallets to match with
    pub fn get_random_wallet<R: RngCore>(&self, rng: &mut R) -> Wallet {
        let key_index = rng.gen_range(0..self.wallet_map.len());
        self.wallet_map
            .values()
            .nth(key_index)
            .unwrap()
            .read()
            .expect(ERR_WALLET_POISONED)
            .clone()
    }

    /// Returns a list of all wallets
    pub fn get_all_wallets(&self) -> Vec<Wallet> {
        self.wallet_map
            .values()
            .map(|wallet| wallet.read().expect(ERR_WALLET_POISONED).clone())
            .collect_vec()
    }

    /// Returns a mapping from wallet ID to the wallet's metadata
    ///
    /// Used to serialize into the handshake response
    pub fn get_metadata_map(&self) -> HashMap<WalletIdentifier, WalletMetadata> {
        let mut res = HashMap::new();
        for (id, wallet) in self.wallet_map.iter() {
            res.insert(
                *id,
                wallet.read().expect(ERR_WALLET_POISONED).metadata.clone(),
            );
        }

        res
    }

    // -----------
    // | Setters |
    // -----------

    /// Add a concurrency safe wallet to the index
    pub fn add_wallet(&mut self, mut wallet: Wallet) {
        wallet.metadata.replicas.insert(self.peer_id);
        self.wallet_map.insert(wallet.wallet_id, new_shared(wallet));
    }

    /// Add a given peer as a replica of a wallet
    pub fn add_replica(&self, wallet_id: &WalletIdentifier, peer_id: WrappedPeerId) {
        if let Some(wallet) = self.wallet_map.get(wallet_id) {
            wallet
                .write()
                .expect(ERR_WALLET_POISONED)
                .metadata
                .replicas
                .insert(peer_id);
        }
    }

    /// Merge metadata for a given wallet into the local wallet state
    pub fn merge_metadata(&self, wallet_id: &WalletIdentifier, metadata: &WalletMetadata) {
        if let Some(wallet) = self.wallet_map.get(wallet_id) {
            if wallet
                .read()
                .expect(ERR_WALLET_POISONED)
                .metadata
                .replicas
                .is_superset(&metadata.replicas)
            {
                return;
            }

            // Acquire a write lock only if we are missing replicas
            let mut locked_wallet = wallet.write().expect(ERR_WALLET_POISONED);
            locked_wallet.metadata.replicas.extend(&metadata.replicas);
        }
    }

    /// Expire peers as replicas of each wallet we know about
    ///
    /// This method is called when a cluster peer is determined to have failed; we should
    /// update the replication state and take any steps necessary to get the wallet replicated
    /// on a safe number of peers
    pub fn remove_peer_replicas(&self, peers: &[WrappedPeerId]) {
        for (_, wallet) in self.wallet_map.iter() {
            let mut locked_wallet = wallet.write().expect("wallet lock poisoned");
            for peer in peers.iter() {
                locked_wallet.metadata.replicas.remove(peer);
            }
        }
    }
}

/// Display implementation for when the relayer is placed in Debug mode
impl Display for WalletIndex {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        // Write a header
        f.write_fmt(format_args!(
            "\n\t{}Managed Wallets:{}\n",
            color::Fg(color::LightGreen),
            color::Fg(color::Reset)
        ))?;

        // Write each wallet into the debug
        for (wallet_id, wallet) in self.wallet_map.iter() {
            f.write_fmt(format_args!(
                "\t\t- {}{:?}:{} {{\n\t\t\t{}replicas{}: [\n",
                color::Fg(color::LightYellow),
                wallet_id,
                color::Fg(color::Reset),
                color::Fg(color::Blue),
                color::Fg(color::Reset),
            ))?;
            for replica in wallet.read().unwrap().metadata.replicas.iter() {
                f.write_fmt(format_args!("\t\t\t\t{}\n", replica.0))?;
            }

            f.write_str("\t\t\t]\n\t\t}")?;
        }

        Ok(())
    }
}
