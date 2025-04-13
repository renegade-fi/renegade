//! Defines the interface to the `mdbx` instance
//!
//! We serialize types using the `flexbuffers` format (a schema-less version of
//! `flatbuffers`): https://flatbuffers.dev/flexbuffers.html

use std::{ops::Bound, path::Path};

use libmdbx::{Database, Geometry, WriteMap, RO, RW};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use util::err_str;

use crate::{ciborium_serialize, NUM_TABLES};

use super::{
    error::StorageError,
    traits::{Key, Value},
    tx::{DbTxn, StateTxn},
};

/// The total maximum size of the DB in bytes
const MAX_DB_SIZE_BYTES: usize = 1 << 36; // 64 GB

// -----------
// | Helpers |
// -----------

/// Serialize a value to a `flexbuffers` byte vector
pub(crate) fn serialize_value<V: Serialize>(value: &V) -> Result<Vec<u8>, StorageError> {
    ciborium_serialize(value).map_err(err_str!(StorageError::Serialization))
}

/// Deserialize a value from a `flexbuffers` byte vector
pub fn deserialize_value<V: for<'de> Deserialize<'de>>(
    value_bytes: &[u8],
) -> Result<V, StorageError> {
    ciborium::de::from_reader(value_bytes).map_err(err_str!(StorageError::Deserialization))
}

// ------------
// | Database |
// ------------

/// The database config
pub struct DbConfig {
    /// The path to open the database at
    pub path: String,
    /// The number of tables to allocate
    pub num_tables: usize,
}

impl DbConfig {
    /// Constructor
    pub fn new_with_path(path: &str) -> Self {
        Self { path: path.to_string(), num_tables: NUM_TABLES }
    }
}

/// The persistent storage layer for the relayer's state machine
///
/// Contains a reference to an `mdbx` instance
pub struct DB {
    /// The path that the DB is open at
    path: String,
    /// The underlying `mdbx` instance
    db: Database<WriteMap>,
}

impl DB {
    /// Constructor
    pub fn new(config: &DbConfig) -> Result<Self, StorageError> {
        let db_path = Path::new(&config.path);
        let db_geom = Geometry {
            size: Some((Bound::Unbounded, Bound::Included(MAX_DB_SIZE_BYTES))),
            ..Default::default()
        };

        let db = Database::new()
            .set_max_tables(config.num_tables)
            .set_geometry(db_geom)
            .open(db_path)
            .map_err(StorageError::OpenDb)?;

        Ok(Self { path: config.path.clone(), db })
    }

    /// Get the path that the DB is open at
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Create a new table in the database
    pub fn create_table(&self, table_name: &str) -> Result<(), StorageError> {
        // Begin a tx
        let tx = self.new_raw_write_tx()?;
        tx.create_table(table_name)?;

        tx.commit()
    }

    /// Drop a table from the database
    ///
    /// # Safety
    ///
    /// This method is marked unsafe as it permanently deletes a table from the
    /// database, care should be taken by the caller to ensure this operation is
    /// not taken erroneously
    #[allow(unsafe_code)]
    pub unsafe fn drop_table(&self, table_name: &str) -> Result<(), StorageError> {
        let tx = self.new_raw_write_tx()?;
        tx.drop_table(table_name)?;

        tx.commit()
    }

    /// Get a key from the database
    pub fn read<K: Key, V: Value>(
        &self,
        table_name: &str,
        key: &K,
    ) -> Result<Option<V>, StorageError> {
        let tx = self.new_raw_read_tx()?;
        let val = tx.read(table_name, key)?;
        tx.commit()?;

        Ok(val)
    }

    /// Set a key in the database
    pub fn write<K: Key, V: Value>(
        &self,
        table_name: &str,
        key: &K,
        value: &V,
    ) -> Result<(), StorageError> {
        let tx = self.new_raw_write_tx()?;
        tx.write(table_name, key, value)?;
        tx.commit()
    }

    /// Delete a key from the database
    ///
    /// Returns `true` if the key was present in the table
    pub fn delete<K: Key>(&self, table_name: &str, key: &K) -> Result<bool, StorageError> {
        let tx = self.new_raw_write_tx()?;
        let did_exist = tx.delete(table_name, key)?;
        tx.commit()?;

        Ok(did_exist)
    }

    /// Create a new read-only transaction
    #[instrument(skip(self))]
    pub fn new_read_tx(&self) -> Result<StateTxn<RO>, StorageError> {
        let txn = self.new_raw_read_tx()?;
        Ok(StateTxn::new(txn))
    }

    /// Create a new raw read-only transaction
    #[instrument(skip(self))]
    pub fn new_raw_read_tx(&self) -> Result<DbTxn<RO>, StorageError> {
        let txn = self.db.begin_ro_txn().map_err(StorageError::BeginTx)?;
        Ok(DbTxn::new(txn))
    }

    /// Create a new read-write transaction
    #[instrument(skip(self))]
    pub fn new_write_tx(&self) -> Result<StateTxn<RW>, StorageError> {
        let txn = self.new_raw_write_tx()?;
        Ok(StateTxn::new(txn))
    }

    /// Create a new read-write transaction
    #[instrument(skip(self))]
    pub fn new_raw_write_tx(&self) -> Result<DbTxn<RW>, StorageError> {
        self.db.begin_rw_txn().map_err(StorageError::BeginTx).map(DbTxn::new)
    }

    /// Flush the database to disk
    pub fn sync(&self) -> Result<(), StorageError> {
        self.db.sync(true /* force */).map_err(StorageError::Sync).map(|_| ())
    }
}

#[cfg(test)]
mod test {
    use std::{sync::Arc, thread};

    use serde::{Deserialize, Serialize};

    use crate::test_helpers::mock_db;

    use super::{DbConfig, DB};

    /// A dummy table name
    const TABLE_NAME: &str = "test_table";

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
            Self { a: 1, b: vec![String::from("test"), String::from("value")], c: (1, 2) }
        }
    }

    // Default resolves to the dummy value
    impl Default for TestValue {
        fn default() -> Self {
            Self::dummy()
        }
    }

    // ---------
    // | Tests |
    // ---------

    /// Tests storing an item then retrieving it
    #[test]
    fn test_put_and_get() {
        // Add a value to the DB then read it back
        let db = mock_db();

        let key_name = "test_key".to_string();

        db.create_table(TABLE_NAME).unwrap();
        db.write(TABLE_NAME, &key_name, &TestValue::dummy()).unwrap();
        let val: Option<TestValue> = db.read(TABLE_NAME, &key_name).unwrap();

        assert_eq!(val.unwrap(), TestValue::dummy());
    }

    /// Tests retrieving a value that doesn't exist
    #[test]
    fn test_get_nonexistent() {
        let db = mock_db();

        let key_name = "test_key".to_string();
        db.create_table(TABLE_NAME).unwrap();
        let val: Option<TestValue> = db.read(TABLE_NAME, &key_name).unwrap();

        assert_eq!(val, None);
    }

    /// Tests deleting a key
    #[test]
    fn test_delete() {
        let db = mock_db();
        let key_name = "test_key".to_string();

        db.create_table(TABLE_NAME).unwrap();
        db.write(TABLE_NAME, &key_name, &TestValue::dummy()).unwrap();
        let exists = db.delete(TABLE_NAME, &key_name).unwrap();
        let val: Option<TestValue> = db.read(TABLE_NAME, &key_name).unwrap();

        assert!(exists);
        assert_eq!(val, None);
    }

    /// Tests deleting a non-existent key
    #[test]
    fn test_delete_nonexistent() {
        let db = mock_db();
        let key_name = "test_key".to_string();

        db.create_table(TABLE_NAME).unwrap();
        let exists = db.delete(TABLE_NAME, &key_name).unwrap();

        assert!(!exists);
    }

    /// Tests a read only tx to a table
    #[test]
    fn test_ro_tx_simple() {
        // Create a table and add a value
        let db = mock_db();
        db.create_table(TABLE_NAME).unwrap();

        let key = "test_key".to_string();
        let value = TestValue::dummy();

        db.write(TABLE_NAME, &key, &value).unwrap();

        // Create a read only transaction and read the value twice
        let tx = db.new_raw_read_tx().unwrap();
        let v1: Option<TestValue> = tx.read(TABLE_NAME, &key).unwrap();
        let v2: Option<TestValue> = tx.read(TABLE_NAME, &key).unwrap();
        tx.commit().unwrap();

        assert_eq!(v1.unwrap(), value);
        assert_eq!(v2.unwrap(), value);
    }

    /// Tests a read-write tx to a table
    #[test]
    fn test_rw_tx_simple() {
        // Create a mock DB
        let db = mock_db();
        db.create_table(TABLE_NAME).unwrap();

        // Write two keys to the table
        let key1 = "test_key".to_string();
        let key2 = "test_key2".to_string();
        let value1 = TestValue::dummy();
        let value2 = TestValue { a: 5, ..Default::default() };

        let tx = db.new_raw_write_tx().unwrap();
        tx.write(TABLE_NAME, &key1, &value1).unwrap();
        tx.write(TABLE_NAME, &key2, &value2).unwrap();
        tx.commit().unwrap();

        // Read the values back
        let tx = db.new_raw_read_tx().unwrap();
        let v1: Option<TestValue> = tx.read(TABLE_NAME, &key1).unwrap();
        let v2: Option<TestValue> = tx.read(TABLE_NAME, &key2).unwrap();
        tx.commit().unwrap();

        assert_eq!(v1.unwrap(), value1);
        assert_eq!(v2.unwrap(), value2);
    }

    /// Tests reading and writing to multiple tables in a tx
    #[test]
    fn test_multi_table_rw() {
        // Create the first table
        let db = mock_db();
        db.create_table(TABLE_NAME).unwrap();

        let key1 = "test_key".to_string();
        let key2 = "test_key2".to_string();
        let value1 = TestValue::dummy();
        let value2 = TestValue { a: 5, ..Default::default() };

        // Create a second table in the write tx
        const TABLE_NAME2: &str = "test_table2";
        let tx = db.new_raw_write_tx().unwrap();
        tx.create_table(TABLE_NAME2).unwrap();

        tx.write(TABLE_NAME, &key1, &value1).unwrap();
        tx.write(TABLE_NAME2, &key2, &value2).unwrap();
        tx.commit().unwrap();

        // Read the values back
        let tx = db.new_raw_read_tx().unwrap();
        let v1: Option<TestValue> = tx.read(TABLE_NAME, &key1).unwrap();
        let v2: Option<TestValue> = tx.read(TABLE_NAME2, &key2).unwrap();
        tx.commit().unwrap();

        assert_eq!(v1.unwrap(), value1);
        assert_eq!(v2.unwrap(), value2);
    }

    /// Tests concurrent transaction isolation
    #[test]
    fn test_concurrent_updates() {
        // Create a mock DB and table
        let db = Arc::new(mock_db());
        db.create_table(TABLE_NAME).unwrap();

        // Write an initial value to the table
        let key = "counter".to_string();
        let tx = db.new_raw_write_tx().unwrap();
        tx.write(TABLE_NAME, &key, &1u64).unwrap();
        tx.commit().unwrap();

        // Spawn two threads to increment the counter
        let mut join_handles = Vec::new();
        for _ in 0..2 {
            let key_clone = key.clone();
            let db_clone = db.clone();

            let handle = thread::spawn(move || {
                let tx = db_clone.new_raw_write_tx().unwrap();
                let value: u64 = tx.read(TABLE_NAME, &key_clone).unwrap().unwrap();
                tx.write(TABLE_NAME, &key_clone, &(value + 1)).unwrap();
                tx.commit().unwrap();
            });

            join_handles.push(handle);
        }

        // Await termination
        join_handles.into_iter().for_each(|handle| handle.join().unwrap());

        // Now read back the value, it should be incremented twice
        let tx = db.new_raw_read_tx().unwrap();
        let value: u64 = tx.read(TABLE_NAME, &key).unwrap().unwrap();
        tx.commit().unwrap();

        assert_eq!(value, 3);
    }

    /// Tests recovering from a crash
    #[test]
    fn test_crash_recover() {
        let db = Arc::new(mock_db());

        // Set a key
        let key = "test_key".to_string();
        let value = TestValue { a: 10, ..Default::default() };

        let tx = db.new_raw_write_tx().unwrap();
        tx.create_table(TABLE_NAME).unwrap();
        tx.write(TABLE_NAME, &key, &value).unwrap();
        tx.commit().unwrap();

        // Drop the db to simulate a crash
        db.sync().unwrap();
        let path = db.path().to_string();
        drop(db);

        // Re-open the database at the same path and read the value
        let db = Arc::new(DB::new(&DbConfig { path, num_tables: 1 }).unwrap());

        let tx = db.new_raw_read_tx().unwrap();
        let val: Option<TestValue> = tx.read(TABLE_NAME, &key).unwrap();
        tx.commit().unwrap();

        assert_eq!(val.unwrap(), value);
    }
}
