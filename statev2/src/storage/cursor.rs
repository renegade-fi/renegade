//! Defines a cursor in the database
//!
//! This cursor implementation is a thin wrapper around the `mdbx` cursor that
//! provides serialization and deserialization of the keys and values in the
//! database

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
    /// The buffered kv pair at the current position
    ///
    /// This field is used to provide a `seek` implementation that does not
    /// consume the value under the cursor after seeking. We prefer to seek
    /// and then separately read the value out
    buffered_value: Option<(K, V)>,
    /// A phantom data field to hold the deserialized type of the table
    _phantom: PhantomData<(K, V)>,
}

/// Query methods
impl<'txn, Tx: TransactionKind, K: Key, V: Value> DbCursor<'txn, Tx, K, V> {
    /// Constructor
    pub fn new(cursor: Cursor<'txn, Tx>) -> Self {
        Self { inner: cursor, buffered_value: None, _phantom: PhantomData }
    }

    /// Get the key/value at the current position
    pub fn get_current(&mut self) -> Result<Option<(K, V)>, StorageError> {
        if let Some((k, v)) = self.buffered_value.take() {
            return Ok(Some((k, v)));
        }

        let res = self.inner.get_current::<CowBuffer, CowBuffer>().map_err(StorageError::TxOp)?;

        res.map(|(k, v)| Self::deserialize_key_value(&k, &v)).transpose()
    }

    /// Position the cursor at the previous key value pair and return it
    pub fn prev(&mut self) -> Result<Option<(K, V)>, StorageError> {
        let res = self.inner.prev::<CowBuffer, CowBuffer>().map_err(StorageError::TxOp)?;

        res.map(|(k, v)| Self::deserialize_key_value(&k, &v)).transpose()
    }

    /// Seek to the first key in the table
    pub fn seek_first(&mut self) -> Result<(), StorageError> {
        let res = self.inner.first::<CowBuffer, CowBuffer>().map_err(StorageError::TxOp)?;

        self.buffer_kv_pair(res)
    }

    /// Seek to the last key in the table
    pub fn seek_last(&mut self) -> Result<(), StorageError> {
        let res = self.inner.last::<CowBuffer, CowBuffer>().map_err(StorageError::TxOp)?;

        self.buffer_kv_pair(res)
    }

    /// Position the cursor at a specific key
    pub fn seek(&mut self, k: &K) -> Result<(), StorageError> {
        let k_bytes = serialize_value(&k)?;
        let res =
            self.inner.set_key::<CowBuffer, CowBuffer>(&k_bytes).map_err(StorageError::TxOp)?;

        self.buffer_kv_pair(res)
    }

    /// Position at the first key greater than or equal to the given key
    pub fn seek_geq(&mut self, k: &K) -> Result<(), StorageError> {
        let k_bytes = serialize_value(k)?;
        let res =
            self.inner.set_range::<CowBuffer, CowBuffer>(&k_bytes).map_err(StorageError::TxOp)?;

        self.buffer_kv_pair(res)
    }

    // -----------
    // | Helpers |
    // -----------

    /// Deserialize a key-value pair to the type of the cursor
    fn deserialize_key_value(
        k_buffer: &CowBuffer,
        v_buffer: &CowBuffer,
    ) -> Result<(K, V), StorageError> {
        Ok((deserialize_value(k_buffer)?, deserialize_value(v_buffer)?))
    }

    /// Buffer the kv pair at the current position
    fn buffer_kv_pair(&mut self, pair: Option<(CowBuffer, CowBuffer)>) -> Result<(), StorageError> {
        self.buffered_value = pair.map(|(k, v)| Self::deserialize_key_value(&k, &v)).transpose()?;

        Ok(())
    }
}

/// Mutation methods
impl<'txn, K: Key, V: Value> DbCursor<'txn, RW, K, V> {
    /// Insert a key/value pair into the table, the cursor will be positioned at
    /// the inserted key or near it when this method fails
    pub fn put(&mut self, k: &K, v: &V) -> Result<(), StorageError> {
        let k_bytes = serialize_value(k)?;
        let v_bytes = serialize_value(v)?;

        self.inner.put(&k_bytes, &v_bytes, WriteFlags::default()).map_err(StorageError::TxOp)
    }

    /// Delete the current key/value pair
    pub fn delete(&mut self) -> Result<(), StorageError> {
        self.inner.del(WriteFlags::default()).map_err(StorageError::TxOp)
    }
}

impl<'txn, T: TransactionKind, K: Key, V: Value> Iterator for DbCursor<'txn, T, K, V> {
    type Item = Result<(K, V), StorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some((k, v)) = self.buffered_value.take() {
            return Some(Ok((k, v)));
        }

        let res = self.inner.next().map_err(StorageError::TxOp);
        if let Err(e) = res {
            return Some(Err(e));
        }

        let res = res.unwrap();
        res.map(|(k, v)| Self::deserialize_key_value(&k, &v))
    }
}

#[cfg(test)]
mod test {
    use rand::{
        seq::{IteratorRandom, SliceRandom},
        thread_rng,
    };

    use crate::{storage::db::DB, test_helpers::mock_db};

    /// The name of the table used for testing
    const TEST_TABLE: &str = "test-table";

    // -----------
    // | Helpers |
    // -----------

    /// Inserts 0..n into the table as "{i}" -> i in random order
    fn insert_n_random(db: &DB, n: usize) {
        let mut values = (0..n).collect::<Vec<_>>();
        values.shuffle(&mut thread_rng());

        let tx = db.new_raw_write_tx().unwrap();
        for i in values.into_iter() {
            let key = i.to_string();
            tx.write(TEST_TABLE, &key, &i).unwrap();
        }
        tx.commit().unwrap();
    }

    // ---------
    // | Tests |
    // ---------

    /// Test the `first` method of a cursor on an empty table
    #[test]
    fn test_empty_table() {
        let db = mock_db();
        db.create_table(TEST_TABLE).unwrap();

        // Read the first key, it should be `None`
        let tx = db.new_raw_read_tx().unwrap();
        let mut cursor = tx.cursor::<String /* key */, String /* value */>(TEST_TABLE).unwrap();
        cursor.seek_first().unwrap();
        let first = cursor.get_current().unwrap();

        assert!(first.is_none());
    }

    /// Test the `first` method of a cursor on a table
    #[test]
    fn test_first() {
        let db = mock_db();
        db.create_table(TEST_TABLE).unwrap();

        let (key, value): (String, String) = ("key".to_string(), "value".to_string());

        // Insert a key/value pair
        db.write(TEST_TABLE, &key, &value).unwrap();

        // Read the first key, it should be `Some`
        let tx = db.new_raw_read_tx().unwrap();
        let mut cursor = tx.cursor::<String, String>(TEST_TABLE).unwrap();
        cursor.seek_first().unwrap();
        let first = cursor.get_current().unwrap();

        assert_eq!(first.unwrap(), (key, value));
    }

    /// Test the `last` method of a cursor
    #[test]
    fn test_last() {
        const N: usize = 10000;
        let db = mock_db();
        db.create_table(TEST_TABLE).unwrap();

        insert_n_random(&db, N);

        // Read the last key, it should be `Some`
        let tx = db.new_raw_read_tx().unwrap();
        let mut cursor = tx.cursor::<String, usize>(TEST_TABLE).unwrap();
        cursor.seek_last().unwrap();
        let last = cursor.get_current().unwrap();

        assert_eq!(last.unwrap(), ((N - 1).to_string(), N - 1));
    }

    /// Test the sorting of a cursor
    #[test]
    fn test_sorted_order_string_key() {
        let db = mock_db();
        db.create_table(TEST_TABLE).unwrap();

        let (k1, v1) = ("b".to_string(), "b_value".to_string());
        let (k2, v2) = ("a".to_string(), "a_value".to_string());

        // Insert values in reverse sorted order
        db.write(TEST_TABLE, &k1, &v1).unwrap();
        db.write(TEST_TABLE, &k2, &v2).unwrap();

        // Read the values out of the cursor
        let tx = db.new_raw_read_tx().unwrap();
        let mut cursor = tx.cursor::<String, String>(TEST_TABLE).unwrap();
        cursor.seek_first().unwrap();
        let first = cursor.get_current().unwrap().unwrap();

        assert_eq!(first, (k2, v2));
    }

    /// Tests the sorting of a cursor with a numeric key
    #[test]
    fn test_sorted_order_numeric_key() {
        // Create a db and insert 0..N into the table randomly
        const N: usize = 1000;

        let db = mock_db();
        db.create_table(TEST_TABLE).unwrap();

        insert_n_random(&db, N);

        // Run a cursor over the table
        let tx = db.new_raw_read_tx().unwrap();
        let cursor = tx.cursor::<String, usize>(TEST_TABLE).unwrap();
        for (i, pair) in cursor.enumerate() {
            let (k, v) = pair.unwrap();
            assert_eq!(k, i.to_string());
            assert_eq!(v, i);
        }
    }

    /// Tests seeking and then peeking the current value then the next value
    #[test]
    fn test_seek_and_next() {
        // Create a db and insert 0..N into the table randomly
        const N: usize = 1000;

        let db = mock_db();
        db.create_table(TEST_TABLE).unwrap();

        insert_n_random(&db, N);

        // Choose a random seek index
        let seek_index = (0..(N - 1)).choose(&mut thread_rng()).unwrap();

        // Seek to the value, assert its correctness, then check the next value
        let tx = db.new_raw_read_tx().unwrap();
        let mut cursor = tx.cursor::<String, usize>(TEST_TABLE).unwrap();
        cursor.seek(&seek_index.to_string()).unwrap();
        let (k, v) = cursor.get_current().unwrap().unwrap();

        assert_eq!(k, seek_index.to_string());
        assert_eq!(v, seek_index);

        let (k, v) = cursor.get_current().unwrap().unwrap();
        assert_eq!(k, seek_index.to_string());
        assert_eq!(v, seek_index);

        let (k, v) = cursor.next().unwrap().unwrap();
        assert_eq!(k, (seek_index + 1).to_string());
        assert_eq!(v, seek_index + 1);
    }

    /// Tests seeking and then peeking the current value then previous value
    #[test]
    fn test_seek_and_prev() {
        // Create a db and insert 0..N into the table randomly
        const N: usize = 1000;

        let db = mock_db();
        db.create_table(TEST_TABLE).unwrap();

        insert_n_random(&db, N);

        // Choose a random seek index
        let seek_index = (1..N).choose(&mut thread_rng()).unwrap();

        // Seek to the value, assert its correctness, then check the previous value
        let tx = db.new_raw_read_tx().unwrap();
        let mut cursor = tx.cursor::<String, usize>(TEST_TABLE).unwrap();
        cursor.seek(&seek_index.to_string()).unwrap();
        let (k, v) = cursor.get_current().unwrap().unwrap();

        assert_eq!(k, seek_index.to_string());
        assert_eq!(v, seek_index);

        let (k, v) = cursor.get_current().unwrap().unwrap();
        assert_eq!(k, seek_index.to_string());
        assert_eq!(v, seek_index);

        let (k, v) = cursor.prev().unwrap().unwrap();
        assert_eq!(k, (seek_index - 1).to_string());
        assert_eq!(v, seek_index - 1);
    }

    /// Tests seeking to the to the first key greater than or equal to the given
    /// key
    #[test]
    fn test_seek_geq() {
        // Create a db and insert 0..N into the table randomly
        const N: usize = 1000;

        let db = mock_db();
        db.create_table(TEST_TABLE).unwrap();

        let mut values = (0..N).collect::<Vec<_>>();
        values.shuffle(&mut thread_rng());

        // Insert all but one value
        let exclude = (0..(N - 1)).choose(&mut thread_rng()).unwrap();
        let tx = db.new_raw_write_tx().unwrap();
        for i in values.into_iter() {
            if i == exclude {
                continue;
            }

            let key = i.to_string();
            tx.write(TEST_TABLE, &key, &i).unwrap();
        }
        tx.commit().unwrap();

        // Test `seek_geq` to a key that does exist
        let seek_ind = exclude - 1;

        let tx = db.new_raw_read_tx().unwrap();
        let mut cursor = tx.cursor::<String, usize>(TEST_TABLE).unwrap();
        cursor.seek_geq(&seek_ind.to_string()).unwrap();
        let (k, v) = cursor.get_current().unwrap().unwrap();

        assert_eq!(k, seek_ind.to_string());
        assert_eq!(v, seek_ind);

        tx.commit().unwrap();

        // Now try seeking to a key that doesn't exist
        let seek_ind = exclude;

        let tx = db.new_raw_read_tx().unwrap();
        let mut cursor = tx.cursor::<String, usize>(TEST_TABLE).unwrap();
        cursor.seek_geq(&seek_ind.to_string()).unwrap();
        let (k, v) = cursor.get_current().unwrap().unwrap();

        let expected = seek_ind + 1;
        assert_eq!(k, expected.to_string());
        assert_eq!(v, expected);
    }
}
