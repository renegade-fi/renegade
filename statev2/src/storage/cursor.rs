//! Defines a cursor in the database
//!
//! This cursor implementation is a thin wrapper around the `mdbx` cursor that provides
//! serialization and deserialization of the keys and values in the database

use std::marker::PhantomData;

use libmdbx::{Cursor, TransactionKind, WriteFlags, RW};

use crate::storage::{db::deserialize_value, error::StorageError};

use super::{
    db::serialize_value,
    traits::{Key, Value},
    CowBuffer,
};

/// A cursor in a table
pub struct DbCursor<'txn, Tx: TransactionKind, K: Key, V: Value> {
    /// The underlying cursor
    inner: Cursor<'txn, Tx>,
    /// A phantom data field to hold the deserialized type of the table
    _phantom: PhantomData<(K, V)>,
}

/// Query methods
impl<'txn, Tx: TransactionKind, K: Key, V: Value> DbCursor<'txn, Tx, K, V> {
    /// Constructor
    pub fn new(cursor: Cursor<'txn, Tx>) -> Self {
        Self {
            inner: cursor,
            _phantom: PhantomData,
        }
    }

    /// Seek to the first key in the table and return it's kv pair
    pub fn first(&mut self) -> Result<Option<(K, V)>, StorageError> {
        let res = self
            .inner
            .first::<CowBuffer, CowBuffer>()
            .map_err(StorageError::TxOp)?;

        res.map(|(k, v)| Self::deserialize_key_value(k, v))
            .transpose()
    }

    /// Get the key/value at the current position
    pub fn get_current(&mut self) -> Result<Option<(K, V)>, StorageError> {
        let res = self
            .inner
            .get_current::<CowBuffer, CowBuffer>()
            .map_err(StorageError::TxOp)?;

        res.map(|(k, v)| Self::deserialize_key_value(k, v))
            .transpose()
    }

    /// Position the cursor at the previous key value pair and return it
    pub fn prev(&mut self) -> Result<Option<(K, V)>, StorageError> {
        let res = self
            .inner
            .prev::<CowBuffer, CowBuffer>()
            .map_err(StorageError::TxOp)?;

        res.map(|(k, v)| Self::deserialize_key_value(k, v))
            .transpose()
    }

    /// Position the cursor at a specific key
    pub fn seek(&mut self, k: K) -> Result<Option<(K, V)>, StorageError> {
        let k_bytes = serialize_value(&k)?;

        self.inner
            .set_key::<CowBuffer, CowBuffer>(&k_bytes)
            .map_err(StorageError::TxOp)?
            .map(|(k, v)| Self::deserialize_key_value(k, v))
            .transpose()
    }

    /// Position at the first key greater than or equal to the given key
    pub fn seek_geq(&mut self, k: K) -> Result<Option<(K, V)>, StorageError> {
        let k_bytes = serialize_value(&k)?;

        self.inner
            .set_range::<CowBuffer, CowBuffer>(&k_bytes)
            .map_err(StorageError::TxOp)?
            .map(|(k, v)| Self::deserialize_key_value(k, v))
            .transpose()
    }

    // -----------
    // | Helpers |
    // -----------

    /// Deserialize a key-value pair to the type of the cursor
    fn deserialize_key_value(
        k_buffer: CowBuffer,
        v_buffer: CowBuffer,
    ) -> Result<(K, V), StorageError> {
        Ok((deserialize_value(&k_buffer)?, deserialize_value(&v_buffer)?))
    }
}

/// Mutation methods
impl<'txn, K: Key, V: Value> DbCursor<'txn, RW, K, V> {
    /// Insert a key/value pair into the table, the cursor will be positioned at the inserted key
    /// or near it when this method fails
    pub fn put(&mut self, k: K, v: V) -> Result<(), StorageError> {
        let k_bytes = serialize_value(&k)?;
        let v_bytes = serialize_value(&v)?;

        self.inner
            .put(&k_bytes, &v_bytes, WriteFlags::default())
            .map_err(StorageError::TxOp)
    }

    /// Delete the current key/value pair
    pub fn delete(&mut self) -> Result<(), StorageError> {
        self.inner
            .del(WriteFlags::default())
            .map_err(StorageError::TxOp)
    }
}

impl<'txn, T: TransactionKind, K: Key, V: Value> Iterator for DbCursor<'txn, T, K, V> {
    type Item = Result<(K, V), StorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        let res = self.inner.next().map_err(StorageError::TxOp);
        if let Err(e) = res {
            return Some(Err(e));
        }

        let res = res.unwrap();
        res.map(|(k, v)| Self::deserialize_key_value(k, v))
    }
}

#[cfg(test)]
mod test {
    use crate::test_helpers::mock_db;

    /// The name of the table used for testing
    const TEST_TABLE: &str = "test-table";

    // ---------
    // | Tests |
    // ---------

    /// Test the `first` method of a cursor
    #[test]
    fn test_empty_table() {
        let db = mock_db();
        db.create_table(TEST_TABLE).unwrap();

        // Read the first key, it should be `None`
        let tx = db.new_read_tx().unwrap();
        let mut cursor = tx.cursor::<String /* key */, String /* value */>(TEST_TABLE).unwrap();
        let first = cursor.first().unwrap();

        assert!(first.is_none());
    }
}
