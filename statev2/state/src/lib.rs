//! This crate defines the relayer's state machine and durable, consistent storage primitives
//!
//! We store our relayer state in an embedded database using `libmdbx` as the underlying storage
//! engine. The database is then replicated by a raft instance at higher layers in the application

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(unsafe_code)]
#![allow(incomplete_features)]
#![feature(let_chains)]
#![feature(io_error_more)]

pub mod replication;
pub mod storage;

#[cfg(test)]
pub(crate) mod test_helpers {
    use tempfile::tempdir;

    use crate::storage::db::{DbConfig, DB};

    /// Create a mock database in a temporary location
    pub fn mock_db() -> DB {
        let tempdir = tempdir().unwrap();
        let path = tempdir.path().to_str().unwrap();

        DB::new(DbConfig {
            path: path.to_string(),
        })
        .unwrap()
    }
}
