//! Transaction interfaces for the relayer state
//!
//! This module defines two transaction interfaces:
//!     - A low level `DbTxn` interface that exposes a key-value interface
//!     - A high level `StateTxn` interface that exposes a state machine
//!       interface with helpers specific to the Renegade state
//!
//! Each of the files in this module are named after the high level interface
//! they expose

pub mod matching_pools;
pub mod node_metadata;
pub mod order_book;
pub mod order_history;
pub mod peer_index;
pub mod raft_log;
pub mod relayer_fees;
pub mod task_assignments;
pub mod task_history;
pub mod task_queue;
pub mod wallet_index;

use std::collections::VecDeque;

use libmdbx::{
    Error as MdbxError, Table, TableFlags, Transaction, TransactionKind, WriteFlags, WriteMap, RW,
};
use tracing::instrument;

use crate::ALL_TABLES;

use super::{
    cursor::DbCursor,
    db::{deserialize_value, serialize_value},
    error::StorageError,
    traits::{Key, Value},
    CowBuffer,
};

// --------------------------
// | High Level Transaction |
// --------------------------

/// A high level transaction in the database
pub struct StateTxn<'db, T: TransactionKind> {
    /// The underlying `mdbx` transaction
    inner: DbTxn<'db, T>,
}

impl<'db, T: TransactionKind> StateTxn<'db, T> {
    /// Constructor
    pub fn new(tx: DbTxn<'db, T>) -> Self {
        Self { inner: tx }
    }

    /// Get the inner raw `DbTxn`
    pub fn inner(&self) -> &DbTxn<'db, T> {
        &self.inner
    }

    /// Commit the transaction
    #[instrument(skip(self))]
    pub fn commit(self) -> Result<(), StorageError> {
        self.inner.commit()
    }

    /// Read a set type from a table
    ///
    /// Assumes the set is represented by a vector
    pub fn read_set<K: Key, V: Value>(
        &self,
        table_name: &str,
        key: &K,
    ) -> Result<Vec<V>, StorageError> {
        Ok(self.inner().read(table_name, key)?.unwrap_or_default())
    }

    /// Read a queue type from a table
    ///
    /// Assumes the queue is represented by a vector    
    pub fn read_queue<K: Key, V: Value>(
        &self,
        table_name: &str,
        key: &K,
    ) -> Result<VecDeque<V>, StorageError> {
        Ok(self.inner().read(table_name, key)?.unwrap_or_default())
    }
}

impl<'db> StateTxn<'db, RW> {
    /// Create a table in the database
    pub fn create_table(&self, table_name: &str) -> Result<(), StorageError> {
        self.inner.create_table(table_name)
    }

    /// Drop a table in the database
    ///
    /// # Safety
    ///
    /// This method is marked unsafe as it permanently deletes a table from the
    /// database, care should be taken by the caller to ensure this operation
    /// is not taken erroneously
    #[allow(unsafe_code)]
    pub unsafe fn drop_table(&self, table_name: &str) -> Result<(), StorageError> {
        self.inner().drop_table(table_name)
    }

    /// Clear a table in the database
    pub fn clear_table(&self, table_name: &str) -> Result<(), StorageError> {
        self.inner().clear_table(table_name)
    }

    /// Create the tables used by the state interface
    pub fn setup_tables(&self) -> Result<(), StorageError> {
        for table in ALL_TABLES.iter() {
            self.create_table(table)?;
        }

        Ok(())
    }

    // --------
    // | Sets |
    // --------

    /// Add a value to a set type
    ///
    /// Assumes the underlying set is represented by a vector
    pub(crate) fn add_to_set<K: Key, V: Value + PartialEq>(
        &self,
        table_name: &str,
        key: &K,
        value: &V,
    ) -> Result<(), StorageError> {
        // Read the set
        let mut set = self.read_set(table_name, key)?;

        // Check if the value is already in the set
        if !set.contains(value) {
            set.push(value.clone());
            self.write_set(table_name, key, &set)?;
        }

        Ok(())
    }

    /// Remove a value from a set type
    ///
    /// Assumes the underlying set is represented by a vector
    pub(crate) fn remove_from_set<K: Key, V: Value + PartialEq>(
        &self,
        table_name: &str,
        key: &K,
        value: &V,
    ) -> Result<(), StorageError> {
        // Read the set
        let mut set = self.read_set::<K, V>(table_name, key)?;

        // Remove the value if it exists in the set
        set.retain(|v| v != value);

        // Write the updated set back to the database
        self.write_set(table_name, key, &set)?;
        Ok(())
    }

    /// Write a set type to the database
    pub(crate) fn write_set<K: Key, V: Value>(
        &self,
        table_name: &str,
        key: &K,
        value: &Vec<V>,
    ) -> Result<(), StorageError> {
        self.inner().write(table_name, key, value)
    }
}

// -------------------------
// | Low Level Transaction |
// -------------------------

/// A transaction in the database
///
/// MDBX guarantees isolation between transactions
pub struct DbTxn<'db, T: TransactionKind> {
    /// The underlying `mdbx` transaction
    txn: Transaction<'db, T, WriteMap>,
}

impl<'db, T: TransactionKind> DbTxn<'db, T> {
    /// Constructor
    pub fn new(txn: Transaction<'db, T, WriteMap>) -> Self {
        Self { txn }
    }

    /// Get a key from the database
    pub fn read<K: Key, V: Value>(
        &self,
        table_name: &str,
        key: &K,
    ) -> Result<Option<V>, StorageError> {
        // Read bytes then deserialize as a `serde::Serialize`
        let value_bytes = self.read_bytes(table_name, key)?;
        value_bytes.map(|bytes| deserialize_value(&bytes)).transpose()
    }

    /// Check if a table exists in the database
    pub fn table_exists(&self, table_name: &str) -> Result<bool, StorageError> {
        match self.txn.open_table(Some(table_name)) {
            Ok(_) => Ok(true),
            Err(MdbxError::NotFound) => Ok(false),
            Err(e) => Err(StorageError::TxOp(e)),
        }
    }

    /// Open a cursor in the txn
    pub fn cursor<K: Key, V: Value>(
        &self,
        table_name: &str,
    ) -> Result<DbCursor<'_, T, K, V>, StorageError> {
        let table = self.open_table(table_name)?;
        let cursor = self.txn.cursor(&table).map_err(StorageError::TxOp)?;

        Ok(DbCursor::new(cursor))
    }

    /// Commit the transaction
    pub fn commit(self) -> Result<(), StorageError> {
        self.txn.commit().map_err(StorageError::Commit).map(|_| ())
    }

    // -----------
    // | Helpers |
    // -----------

    /// Read a byte array directly from the database
    fn read_bytes<K: Key>(
        &self,
        table_name: &str,
        key: &K,
    ) -> Result<Option<CowBuffer>, StorageError> {
        // Serialize the key
        let key_bytes = serialize_value(key)?;

        // Get the value
        let table = self.open_table(table_name)?;
        self.txn.get(&table, &key_bytes).map_err(StorageError::TxOp)
    }

    /// Open a table if the transaction has not done so already
    fn open_table(&self, table_name: &str) -> Result<Table, StorageError> {
        self.txn.open_table(Some(table_name)).map_err(StorageError::OpenTable)
    }
}

// Write-enabled implementation
impl<'db> DbTxn<'db, RW> {
    /// Create a new table in the database
    pub fn create_table(&self, table_name: &str) -> Result<(), StorageError> {
        self.txn
            .create_table(Some(table_name), TableFlags::default())
            .map_err(StorageError::TxOp)
            .map(|_| ())
    }

    /// Drop a table from the database
    ///
    /// # Safety
    ///
    /// This method is marked unsafe as it permanently deletes a table from the
    /// database, care should be taken by the caller to ensure this operation
    /// is not taken erroneously
    #[allow(unsafe_code)]
    pub unsafe fn drop_table(&self, table_name: &str) -> Result<(), StorageError> {
        let table = self.open_table(table_name);
        let table = match table {
            Ok(t) => t,
            Err(StorageError::OpenTable(MdbxError::NotFound)) => return Ok(()),
            Err(e) => return Err(e),
        };

        self.txn.drop_table(table).map_err(StorageError::TxOp)
    }

    /// Clear a table in the database
    pub fn clear_table(&self, table_name: &str) -> Result<(), StorageError> {
        let table = self.open_table(table_name);
        let table = match table {
            Ok(t) => t,
            Err(StorageError::OpenTable(MdbxError::NotFound)) => return Ok(()),
            Err(e) => return Err(e),
        };

        self.txn.clear_table(&table).map_err(StorageError::TxOp)
    }

    /// Set a key in the database
    pub fn write<K: Key, V: Value>(
        &self,
        table_name: &str,
        key: &K,
        value: &V,
    ) -> Result<(), StorageError> {
        let value_bytes = serialize_value(value)?;
        self.write_bytes(table_name, key, &value_bytes)
    }

    /// Remove a key from the database
    pub fn delete<K: Key>(&self, table_name: &str, key: &K) -> Result<bool, StorageError> {
        // Serialize the key
        let key_bytes = serialize_value(key)?;

        // Delete the value
        let table = self.open_table(table_name)?;
        self.txn.del(&table, key_bytes, None /* data */).map_err(StorageError::TxOp)
    }

    /// Copy the contents of a cursor into a table
    pub fn copy_cursor_to_table<T: TransactionKind>(
        &self,
        table_name: &str,
        mut cursor: DbCursor<'_, T, CowBuffer, CowBuffer>,
    ) -> Result<(), StorageError> {
        while !cursor.seek_next_raw()? {
            let (k, v) = cursor.get_current_raw()?.unwrap();
            self.write_raw(table_name, &k, &v)?;
        }

        Ok(())
    }

    // -----------
    // | Helpers |
    // -----------

    /// Write a byte array directly to the database
    fn write_bytes<K: Key>(
        &self,
        table_name: &str,
        key: &K,
        value_bytes: &[u8],
    ) -> Result<(), StorageError> {
        // Serialize the key
        let key_bytes = serialize_value(key)?;

        // Set the value
        let table = self.open_table(table_name)?;
        self.txn
            .put(&table, key_bytes, value_bytes, WriteFlags::default())
            .map_err(StorageError::TxOp)
    }

    /// Write a raw (expressed as bytes) key value pair to the database
    pub(crate) fn write_raw(
        &self,
        table_name: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), StorageError> {
        let table = self.open_table(table_name)?;
        self.txn.put(&table, key, value, WriteFlags::default()).map_err(StorageError::TxOp)
    }
}

#[cfg(test)]
mod test {
    use crate::test_helpers::mock_db;

    /// Tests that dropping a tx aborts it
    #[test]
    fn test_drop_tx() {
        let db = mock_db();

        // Create a table
        const TABLE_NAME: &str = "test";
        let tx = db.new_write_tx().unwrap();
        tx.inner().create_table(TABLE_NAME).unwrap();
        tx.commit().unwrap();

        // Create a new tx and drop it
        {
            let tx = db.new_write_tx().unwrap();
            let inner = tx.inner();
            inner.write(TABLE_NAME, &"a".to_string(), &1).unwrap();
        }

        // Check that the update was aborted
        let tx = db.new_read_tx().unwrap();
        let value: Option<i32> = tx.inner().read(TABLE_NAME, &"a".to_string()).unwrap();
        assert_eq!(value, None);
    }

    /// Tests checking if a table exists
    #[test]
    fn test_table_exists() {
        let db = mock_db();
        const TABLE_NAME: &str = "test";

        // Check that the table doesn't exist
        let tx = db.new_write_tx().unwrap();
        let exists = tx.inner().table_exists(TABLE_NAME).unwrap();
        assert!(!exists);

        // Create the table
        tx.inner().create_table(TABLE_NAME).unwrap();
        tx.commit().unwrap();

        // Check that the table exists
        let tx = db.new_read_tx().unwrap();
        let exists = tx.inner().table_exists(TABLE_NAME).unwrap();
        assert!(exists);
    }
}
