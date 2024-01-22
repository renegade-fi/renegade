//! This crate defines the relayer's state machine and durable, consistent
//! storage primitives
//!
//! We store our relayer state in an embedded database using `libmdbx` as the
//! underlying storage engine. The database is then replicated by a raft
//! instance at higher layers in the application

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![deny(unsafe_code)]
#![allow(incomplete_features)]
#![feature(let_chains)]
#![feature(io_error_more)]
#![feature(generic_const_exprs)]

use circuit_types::wallet::Nullifier;
use common::types::{
    gossip::{PeerInfo, WrappedPeerId},
    network_order::NetworkOrder,
    proof_bundles::OrderValidityProofBundle,
    wallet::{OrderIdentifier, Wallet},
};
use replication::RaftPeerId;
use serde::{Deserialize, Serialize};

pub mod applicator;
mod interface;
pub mod replication;
pub mod storage;

/// Re-export the state interface
pub use interface::*;

/// The `StateTransition` type encapsulates all possible state transitions,
/// allowing transitions to be handled generically before they are applied
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum StateTransition {
    /// Add a wallet to the managed state
    AddWallet { wallet: Wallet },
    /// Update a wallet in the managed state
    UpdateWallet { wallet: Wallet },
    /// Add an order to the network order book
    AddOrder { order: NetworkOrder },
    /// Add a validity proof to an existing order in the book
    AddOrderValidityProof { order_id: OrderIdentifier, proof: OrderValidityProofBundle },
    /// Cancel all orders on a given nullifier
    NullifyOrders { nullifier: Nullifier },
    /// Add a set of peers to the p2p network topology
    AddPeers { peers: Vec<PeerInfo> },
    /// Add a raft learner to the cluster
    AddRaftLearner { peer_id: RaftPeerId },
    /// Add a raft peer to the local consensus cluster
    AddRaftPeer { peer_id: RaftPeerId },
    /// Remove a peer from the p2p network topology
    RemovePeer { peer_id: WrappedPeerId },
    /// Remove a raft peer from the local consensus cluster
    RemoveRaftPeer { peer_id: RaftPeerId },
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use std::time::Duration;

    use tempfile::tempdir;

    use crate::storage::db::{DbConfig, DB};

    /// Sleep for the given number of ms
    pub fn sleep_ms(ms: u64) {
        std::thread::sleep(Duration::from_millis(ms));
    }

    /// Get a tempdir to open the DB at
    pub fn tmp_db_path() -> String {
        let tempdir = tempdir().unwrap();
        tempdir.path().to_str().unwrap().to_string()
    }

    /// Create a mock database in a temporary location
    pub fn mock_db() -> DB {
        let path = tmp_db_path();
        let config = DbConfig { path: path.to_string() };

        DB::new(&config).unwrap()
    }
}
