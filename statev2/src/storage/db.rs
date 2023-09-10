//! Defines the interface to the `mdbx` instance
//!
//! We serialize types using the `flexbuffers` format (a schema-less version of
//! `flatbuffers`): https://flatbuffers.dev/flexbuffers.html

use std::{borrow::Cow, path::Path};

use libmdbx::{Database, TableFlags, Transaction, WriteFlags, WriteMap, RO, RW};
use serde::{Deserialize, Serialize};

use super::{
    error::StorageError,
    traits::{Key, Value},
};

/// The number of tables to open in the database
const NUM_TABLES: usize = 2;

/// The database config
pub struct DbConfig {
    /// The path to open the database at
    path: String,
}

/// The persistent storage layer for the relayer's state machine
///
/// Contains a reference to an `mdbx` instance
pub struct DB {
    /// The underlying `mdbx` instance
    db: Database<WriteMap>,
    /// The config for the database
    #[allow(unused)]
    config: DbConfig,
}

impl DB {
    /// Constructor
    pub fn new(config: DbConfig) -> Result<Self, StorageError> {
        let db_path = Path::new(&config.path);
        let db = Database::new()
            .set_max_tables(NUM_TABLES)
            .open(db_path)
            .map_err(StorageError::OpenDb)?;

        Ok(Self { db, config })
    }

    /// Create a new table in the database
    pub fn create_table(&self, table_name: &str) -> Result<(), StorageError> {
        // Begin a tx
        let tx = self.new_write_tx()?;
        tx.create_table(Some(table_name), TableFlags::default())
            .map_err(StorageError::TxOp)
            .map(|_| ())
            .and_then(|_| tx.commit().map_err(StorageError::Commit).map(|_| ()))
    }

    /// Set a key in the database
    pub fn write<K: Key, V: Value>(
        &self,
        table_name: &str,
        key: &K,
        value: &V,
    ) -> Result<(), StorageError> {
        // Serialize the key and value
        let key_bytes = Self::serialize_value(key)?;
        let value_bytes = Self::serialize_value(value)?;

        // Begin a tx
        let tx = self.new_write_tx()?;
        let table = tx
            .open_table(Some(table_name))
            .map_err(StorageError::OpenTable)?;

        // Set the value
        tx.put(&table, key_bytes, value_bytes, WriteFlags::default())
            .map_err(StorageError::TxOp)
            .and_then(|_| tx.commit().map_err(StorageError::Commit).map(|_| ()))
    }

    /// Get a key from the database
    pub fn read<K: Key, V: Value>(
        &self,
        table_name: &str,
        key: &K,
    ) -> Result<Option<V>, StorageError> {
        // Serialize the key
        let key_bytes = Self::serialize_value(key)?;

        // Begin a tx
        let tx = self.new_read_tx()?;
        let table = tx
            .open_table(Some(table_name))
            .map_err(StorageError::OpenTable)?;

        // Get the value
        let value_bytes: Option<Cow<'_, [u8]>> =
            tx.get(&table, &key_bytes).map_err(StorageError::TxOp)?;
        value_bytes
            .map(|bytes| Self::deserialize_value(&bytes))
            .transpose()
    }

    // -----------
    // | Helpers |
    // -----------

    /// Serialize a value to a `flexbuffers` byte vector
    fn serialize_value<V: Serialize>(value: &V) -> Result<Vec<u8>, StorageError> {
        flexbuffers::to_vec(value).map_err(StorageError::Serialization)
    }

    /// Deserialize a value from a `flexbuffers` byte vector
    fn deserialize_value<V: for<'de> Deserialize<'de>>(
        value_bytes: &[u8],
    ) -> Result<V, StorageError> {
        flexbuffers::from_slice(value_bytes).map_err(StorageError::Deserialization)
    }

    /// Create a new read-only transaction
    fn new_read_tx(&self) -> Result<Transaction<'_, RO, WriteMap>, StorageError> {
        self.db.begin_ro_txn().map_err(StorageError::BeginTx)
    }

    /// Create a new read-write transaction
    fn new_write_tx(&self) -> Result<Transaction<'_, RW, WriteMap>, StorageError> {
        self.db.begin_rw_txn().map_err(StorageError::BeginTx)
    }
}

#[cfg(test)]
mod test {
    use serde::{Deserialize, Serialize};
    use tempfile::tempdir;

    use super::{DbConfig, DB};

    // -----------
    // | Helpers |
    // -----------

    /// A structure to store for testing
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct TestValue {
        a: u64,
        b: Vec<String>,
        c: (u64, u64),
    }

    impl TestValue {
        /// Get a dummy test value
        fn dummy() -> Self {
            Self {
                a: 1,
                b: vec![String::from("test"), String::from("value")],
                c: (1, 2),
            }
        }
    }

    /// Create a mock database backed by a temporary directory
    fn mock_db() -> DB {
        let tempdir = tempdir().unwrap();
        let path = tempdir.path().to_str().unwrap();

        DB::new(DbConfig {
            path: path.to_string(),
        })
        .unwrap()
    }

    // ---------
    // | Tests |
    // ---------

    /// Tests storing an item then retrieving it
    #[test]
    fn test_put_and_get() {
        // Add a value to the DB then read it back
        let db = mock_db();

        const TABLE_NAME: &str = "test_table";
        let key_name = "test_key".to_string();

        db.create_table(TABLE_NAME).unwrap();
        db.write(TABLE_NAME, &key_name, &TestValue::dummy())
            .unwrap();
        let val: Option<TestValue> = db.read(TABLE_NAME, &key_name).unwrap();

        assert_eq!(val.unwrap(), TestValue::dummy());
    }

    /// Tests retrieving a value that doesn't exist
    #[test]
    fn test_get_nonexistent() {
        let db = mock_db();

        const TABLE_NAME: &str = "test_table";
        let key_name = "test_key".to_string();

        db.create_table(TABLE_NAME).unwrap();
        let val: Option<TestValue> = db.read(TABLE_NAME, &key_name).unwrap();

        assert_eq!(val, None);
    }
}
