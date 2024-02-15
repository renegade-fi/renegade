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
    /// The filter applied to keys
    ///
    /// Only keys for which this filter returns `true` will be returned by the
    /// cursor methods
    ///
    /// Note however that the filter does not affect the position of the cursor,
    /// so while methods like `next` and `prev` will skip over keys that do not
    /// pass the filter, the cursor will still be positioned at those keys
    key_filter: Option<fn(&K) -> bool>,
    /// A phantom data field to hold the deserialized type of
    /// the table
    _phantom: PhantomData<(K, V)>,
}

// -----------------
// | Query Methods |
// -----------------

impl<'txn, Tx: TransactionKind, K: Key, V: Value> DbCursor<'txn, Tx, K, V> {
    /// Constructor
    pub fn new(cursor: Cursor<'txn, Tx>) -> Self {
        Self { inner: cursor, key_filter: None, _phantom: PhantomData }
    }

    /// Set a filter on the keys
    ///
    /// Consumes the cursor to provide a builder-like pattern
    pub fn with_key_filter(mut self, filter: fn(&K) -> bool) -> Self {
        self.key_filter = Some(filter);
        self
    }

    /// Get the key/value at the current position
    ///
    /// Assumes that the cursor is positioned at a valid key/value pair for the
    /// filter, this invariant should be maintained by other cursor methods
    pub fn get_current(&mut self) -> Result<Option<(K, V)>, StorageError> {
        let res = self.inner.get_current::<CowBuffer, CowBuffer>().map_err(StorageError::TxOp)?;
        match res {
            None => Ok(None),
            Some(kv) => self.deserialize_and_filter(kv),
        }
    }

    /// Position the cursor at the next key value pair
    ///
    /// Returns `true` if the cursor has reached the end of the table
    pub fn seek_next(&mut self) -> Result<bool, StorageError> {
        // Move the cursor forward and return early if it is exhausted
        if self.inner.next::<CowBuffer, CowBuffer>().map_err(StorageError::TxOp)?.is_none() {
            return Ok(true);
        }

        // Seek forward to the next valid key
        let end = self.seek_next_filtered(true /* forward */)?.is_none();
        Ok(end)
    }

    /// Position the cursor at the previous key value pair
    ///
    /// Returns `true` if the cursor has reached the start of the table
    pub fn seek_prev(&mut self) -> Result<bool, StorageError> {
        // Move the cursor back and return early if it is exhausted
        if self.inner.prev::<CowBuffer, CowBuffer>().map_err(StorageError::TxOp)?.is_none() {
            return Ok(true);
        }

        // Seek backward to the previous valid key
        let start = self.seek_next_filtered(false /* forward */)?.is_none();
        Ok(start)
    }

    /// Seek to the first key in the table
    pub fn seek_first(&mut self) -> Result<(), StorageError> {
        // Position the cursor at the first key then seek forward to the next valid key
        self.inner.first::<CowBuffer, CowBuffer>().map_err(StorageError::TxOp)?;
        self.seek_next_filtered(true /* forward */).map(|_| ())
    }

    /// Seek to the last key in the table
    pub fn seek_last(&mut self) -> Result<(), StorageError> {
        // Position the cursor at the last key then seek backwards to the next valid key
        self.inner.last::<CowBuffer, CowBuffer>().map_err(StorageError::TxOp)?;
        self.seek_next_filtered(false /* forward */).map(|_| ())
    }

    /// Position the cursor at a specific key
    ///
    /// Note that if the key is not present, the cursor is positioned at an
    /// empty value, the filter will then take effect on any further cursor
    /// operations
    pub fn seek(&mut self, k: &K) -> Result<(), StorageError> {
        // Validate the key
        if let Some(filter) = self.key_filter
            && !filter(k)
        {
            return Err(StorageError::InvalidKey(format!(
                "Key {k:?} passed to `Cursor::seek` does not pass filter"
            )));
        }

        let k_bytes = serialize_value(&k)?;
        self.inner.set_key::<CowBuffer, CowBuffer>(&k_bytes).map_err(StorageError::TxOp).map(|_| ())
    }

    /// Position at the first key greater than or equal to the given key
    pub fn seek_geq(&mut self, k: &K) -> Result<(), StorageError> {
        // Position the cursor at the first key then seek forward to the next valid key
        let k_bytes = serialize_value(k)?;
        self.inner.set_range::<CowBuffer, CowBuffer>(&k_bytes).map_err(StorageError::TxOp)?;
        self.seek_next_filtered(true /* forward */).map(|_| ())
    }

    // -----------
    // | Helpers |
    // -----------

    /// Seek to the next value passing the filter from (inclusive) the
    /// current cursor position. Repositions the cursor to that location,
    /// returns the value
    ///
    /// The `forward` parameter determines the direction of the search
    fn seek_next_filtered(&mut self, forward: bool) -> Result<Option<(K, V)>, StorageError> {
        // Try the current position
        let curr = self.inner.get_current::<CowBuffer, CowBuffer>().map_err(StorageError::TxOp)?;
        if let Some(val) = curr
            && let Some(kv) = self.deserialize_and_filter(val)?
        {
            return Ok(Some(kv));
        }

        // Otherwise, directionally search for the next valid key
        let next_fn = if forward {
            Cursor::<Tx>::next::<CowBuffer, CowBuffer>
        } else {
            Cursor::<Tx>::prev::<CowBuffer, CowBuffer>
        };

        while let Some(kv) = next_fn(&mut self.inner).map_err(StorageError::TxOp)? {
            if let Some(kv) = self.deserialize_and_filter(kv)? {
                return Ok(Some(kv));
            }
        }

        Ok(None)
    }

    /// Deserialize a key-value pair and filter the key
    fn deserialize_and_filter(
        &self,
        kv: (CowBuffer, CowBuffer),
    ) -> Result<Option<(K, V)>, StorageError> {
        let (k_buf, v_buf) = kv;

        // Deserialize and filter the key
        let key = deserialize_value(&k_buf)?;
        if let Some(filter) = self.key_filter
            && !filter(&key)
        {
            return Ok(None);
        }

        // Deserialize the value
        let value = deserialize_value(&v_buf)?;
        Ok(Some((key, value)))
    }
}

// --------------------
// | Mutation methods |
// --------------------

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

// ---------------------------
// | Iterator Implementation |
// ---------------------------

impl<'txn, T: TransactionKind, K: Key, V: Value> IntoIterator for DbCursor<'txn, T, K, V> {
    type Item = Result<(K, V), StorageError>;
    type IntoIter = DbCursorIter<'txn, T, K, V>;

    fn into_iter(mut self) -> Self::IntoIter {
        // Setup the initial value for the iterator
        let initial = self.get_current().unwrap();
        DbCursorIter { initial, cursor: self }
    }
}

/// The iterator type for the cursor
pub struct DbCursorIter<'txn, T: TransactionKind, K: Key, V: Value> {
    /// The initial value of the iterator
    initial: Option<(K, V)>,
    /// The underlying cursor
    cursor: DbCursor<'txn, T, K, V>,
}

impl<'txn, T: TransactionKind, K: Key, V: Value> DbCursorIter<'txn, T, K, V> {
    /// Return an iterator over only the keys in the table
    pub fn keys(self) -> impl Iterator<Item = Result<K, StorageError>> {
        <Self as Iterator>::map(self, |res| res.map(|(k, _v)| k))
    }

    /// Return an iterator over only the values in the table
    pub fn values(self) -> impl Iterator<Item = Result<V, StorageError>> {
        <Self as Iterator>::map(self, |res| res.map(|(_k, v)| v))
    }
}

impl<'txn, T: TransactionKind, K: Key, V: Value> Iterator for DbCursorIter<'txn, T, K, V> {
    type Item = Result<(K, V), StorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some((k, v)) = self.initial.take() {
            return Some(Ok((k, v)));
        }

        // Increment the cursor
        match self.cursor.seek_next() {
            Err(e) => return Some(Err(e)),
            Ok(true) => return None, // end of iterator
            _ => {},
        };

        // Get the current value under the cursor
        self.cursor.get_current().transpose()
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
        for (i, pair) in cursor.into_iter().enumerate() {
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

        cursor.seek_next().unwrap();
        let (k, v) = cursor.get_current().unwrap().unwrap();
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

        cursor.seek_prev().unwrap();
        let (k, v) = cursor.get_current().unwrap().unwrap();
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

    /// Tests a filtered cursor
    #[test]
    fn test_filtered_cursor() {
        // Create a db and insert 0..N into the table randomly
        const N: usize = 1000;
        let db = mock_db();
        db.create_table(TEST_TABLE).unwrap();

        insert_n_random(&db, N);

        // Create a filtered cursor that only returns odd keys
        let tx = db.new_raw_read_tx().unwrap();
        let mut cursor = tx
            .cursor::<String, usize>(TEST_TABLE)
            .unwrap()
            .with_key_filter(|k| k.parse::<usize>().unwrap() % 2 == 1);
        cursor.seek_first().unwrap();

        // Cursor is positioned at one, should return `Some`
        let kv = cursor.get_current().unwrap().unwrap();
        assert_eq!(kv, ("1".to_string(), 1));

        // Move the cursor to the next key, should be the next odd key
        cursor.seek_next().unwrap();
        let next = cursor.get_current().unwrap().unwrap();
        assert_eq!(next, ("3".to_string(), 3));

        // Get the current key, should still be the second odd key
        let curr = cursor.get_current().unwrap();
        assert_eq!(curr.unwrap(), ("3".to_string(), 3));

        // Get the previous key, should return `Some`
        cursor.seek_prev().unwrap();
        let prev = cursor.get_current().unwrap().unwrap();
        assert_eq!(prev, ("1".to_string(), 1));

        // Seek to the last key, should be N - 1
        cursor.seek_last().unwrap();
        let last = cursor.get_current().unwrap().unwrap();
        let idx = N - 1;
        assert_eq!(last, (idx.to_string(), idx));

        // Iterate over the cursor, should only return odd keys
        cursor.seek_first().unwrap();
        let elems = cursor.into_iter().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(elems.len(), N / 2);

        for (i, pair) in elems.into_iter().enumerate() {
            let idx = i * 2 + 1;

            let (k, v) = pair;
            assert_eq!(k, idx.to_string());
            assert_eq!(v, idx);
        }
    }
}
