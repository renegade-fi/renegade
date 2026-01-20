//! Defines a cursor in the database
//!
//! This cursor implementation is a thin wrapper around the `mdbx` cursor that
//! provides serialization and deserialization of the keys and values in the
//! database

use std::borrow::Cow;
use std::marker::PhantomData;

use libmdbx::{Cursor, RW, TransactionKind, WriteFlags};

use crate::storage::{ArchivedValue, error::StorageError};

use super::traits::{Key, Value};

/// A cursor in a table
pub struct DbCursor<'txn, Tx: TransactionKind, K: Key, V: Value> {
    /// The underlying cursor
    pub inner: Cursor<'txn, Tx>,
    /// The key prefix for filtering during iteration
    ///
    /// When set, the iterator will:
    /// 1. Use `set_range` to position at the first key with this prefix
    /// 2. Stop iteration when encountering the first key that doesn't match
    ///
    /// The prefix is stored as serialized bytes to avoid re-serialization
    /// during comparison
    key_prefix: Option<Vec<u8>>,
    /// A phantom data field to hold the deserialized type of
    /// the table
    _phantom: PhantomData<(K, V)>,
}

// -----------------
// | Query Methods |
// -----------------

impl<'txn, Tx: TransactionKind, K: Key, V: Value> DbCursor<'txn, Tx, K, V> {
    /// A type alias for a Cow buffer with the transaction lifetime
    pub type TxBytes = Cow<'txn, [u8]>;
    /// A type alias for an archived key type
    pub type ArchivedKey = ArchivedValue<'txn, K>;
    /// A type alias for an archived value type
    pub type ArchivedValue = ArchivedValue<'txn, V>;
    /// A type alias for an archived key value pair
    pub type ArchivedKV = (Self::ArchivedKey, Self::ArchivedValue);

    /// Constructor
    pub fn new(cursor: Cursor<'txn, Tx>) -> Self {
        Self { inner: cursor, key_prefix: None, _phantom: PhantomData }
    }

    /// Set a key prefix for filtering during iteration
    ///
    /// Consumes the cursor to provide a builder-like pattern.
    /// The prefix should be raw bytes (e.g., UTF-8 for string keys).
    ///
    /// When iterating, the cursor will:
    /// 1. Position at the first key matching the prefix using `set_range`
    /// 2. Stop when encountering a key that doesn't start with the prefix
    pub fn with_key_prefix(mut self, prefix: impl AsRef<[u8]>) -> Self {
        self.key_prefix = Some(prefix.as_ref().to_vec());
        self
    }

    /// Get the key/value at the current position
    pub fn get_current(&mut self) -> Result<Option<Self::ArchivedKV>, StorageError> {
        let res =
            self.inner.get_current::<Self::TxBytes, Self::TxBytes>().map_err(StorageError::TxOp)?;

        match res {
            None => Ok(None),
            Some((k_buf, v_buf)) => {
                let k_val = ArchivedValue::<'txn, K>::new(k_buf);
                let v_val = ArchivedValue::<'txn, V>::new(v_buf);
                Ok(Some((k_val, v_val)))
            },
        }
    }

    /// Get the key/value at the current position, checking prefix if set
    ///
    /// Returns `None` if the current key doesn't match the prefix, signaling
    /// end of iteration for prefix-filtered cursors
    fn get_current_checked(&mut self) -> Result<Option<Self::ArchivedKV>, StorageError> {
        let (k_buf, v_buf) = match self
            .inner
            .get_current::<Self::TxBytes, Self::TxBytes>()
            .map_err(StorageError::TxOp)?
        {
            Some(kv) => kv,
            None => return Ok(None),
        };

        // Check prefix on raw bytes
        if let Some(ref prefix) = self.key_prefix
            && !k_buf.starts_with(prefix)
        {
            return Ok(None); // End iteration
        }

        let k_val = ArchivedValue::<'txn, K>::new(k_buf);
        let v_val = ArchivedValue::<'txn, V>::new(v_buf);
        Ok(Some((k_val, v_val)))
    }

    /// Get the key/value at the current position position without deserializing
    #[allow(clippy::type_complexity)]
    pub fn get_current_raw(
        &mut self,
    ) -> Result<Option<(Self::TxBytes, Self::TxBytes)>, StorageError> {
        self.inner.get_current::<Self::TxBytes, Self::TxBytes>().map_err(StorageError::TxOp)
    }

    /// Position the cursor at the next keypair
    ///
    /// Returns `true` if the cursor has reached the end of the table
    pub fn seek_next_raw(&mut self) -> Result<bool, StorageError> {
        Ok(self.inner.next::<Self::TxBytes, Self::TxBytes>().map_err(StorageError::TxOp)?.is_none())
    }

    /// Seek to the first key in the table
    pub fn seek_first(&mut self) -> Result<(), StorageError> {
        self.inner.first::<Self::TxBytes, Self::TxBytes>().map_err(StorageError::TxOp).map(|_| ())
    }

    /// Seek to the last key in the table
    pub fn seek_last(&mut self) -> Result<(), StorageError> {
        self.inner.last::<Self::TxBytes, Self::TxBytes>().map_err(StorageError::TxOp).map(|_| ())
    }

    /// Position the cursor at a specific key
    ///
    /// Note that if the key is not present, the cursor is positioned at an
    /// empty value
    pub fn seek(&mut self, k: &K) -> Result<(), StorageError> {
        let k_bytes = k.rkyv_serialize()?;
        self.inner
            .set_key::<Self::TxBytes, Self::TxBytes>(&k_bytes)
            .map_err(StorageError::TxOp)
            .map(|_| ())
    }
}

// --------------------
// | Mutation methods |
// --------------------

impl<K: Key, V: Value> DbCursor<'_, RW, K, V> {
    /// Insert a key/value pair into the table, the cursor will be positioned at
    /// the inserted key or near it when this method fails
    pub fn put(&mut self, k: &K, v: &V) -> Result<(), StorageError> {
        let k_bytes = k.rkyv_serialize()?;
        let v_bytes = v.rkyv_serialize()?;

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
    type Item = Result<Self::ArchivedKV, StorageError>;
    type IntoIter = DbCursorIter<'txn, T, K, V>;

    fn into_iter(mut self) -> Self::IntoIter {
        // Position at prefix start if set
        if let Some(ref prefix) = self.key_prefix {
            let _ = self.inner.set_range::<Self::TxBytes, Self::TxBytes>(prefix);
        }

        // Get initial value, checking prefix if set
        let initial = self.get_current_checked().unwrap();
        DbCursorIter { initial, cursor: self }
    }
}

/// The iterator type for the cursor
pub struct DbCursorIter<'txn, T: TransactionKind, K: Key, V: Value> {
    /// The initial value of the iterator
    initial: Option<(ArchivedValue<'txn, K>, ArchivedValue<'txn, V>)>,
    /// The underlying cursor
    cursor: DbCursor<'txn, T, K, V>,
}

impl<'txn, T: TransactionKind, K: Key, V: Value> DbCursorIter<'txn, T, K, V> {
    /// A type alias for the cursor's key type
    pub type KeyElement = ArchivedValue<'txn, K>;
    /// A type alias for the cursor's value type
    pub type ValueElement = ArchivedValue<'txn, V>;
    /// A type alias for the cursor's element type
    pub type Element = (Self::KeyElement, Self::ValueElement);
}

impl<T: TransactionKind, K: Key, V: Value> DbCursorIter<'_, T, K, V> {
    /// Return an iterator over only the keys in the table
    pub fn keys(self) -> impl Iterator<Item = Result<Self::KeyElement, StorageError>> {
        <Self as Iterator>::map(self, |res| res.map(|(k, _v)| k))
    }

    /// Return an iterator over only the values in the table
    pub fn values(self) -> impl Iterator<Item = Result<Self::ValueElement, StorageError>> {
        <Self as Iterator>::map(self, |res| res.map(|(_k, v)| v))
    }
}

impl<T: TransactionKind, K: Key, V: Value> Iterator for DbCursorIter<'_, T, K, V> {
    type Item = Result<Self::Element, StorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some((k, v)) = self.initial.take() {
            return Some(Ok((k, v)));
        }

        // Move to next key
        type TxBytes<'a> = std::borrow::Cow<'a, [u8]>;
        match self.cursor.inner.next::<TxBytes<'_>, TxBytes<'_>>() {
            Ok(None) => return None, // End of table
            Err(e) => return Some(Err(StorageError::TxOp(e))),
            Ok(Some(_)) => {},
        }

        // Get the current value, checking prefix - returns None if prefix doesn't match
        self.cursor.get_current_checked().transpose()
    }
}

#[cfg(test)]
mod test {
    use rand::{seq::SliceRandom, thread_rng};

    use crate::{storage::db::DB, test_helpers::mock_db};

    /// A fixed-width byte array key that preserves numeric ordering
    ///
    /// Uses big-endian encoding so that lexicographic byte order matches
    /// numeric order
    type ByteKey = [u8; 8];

    /// The name of the table used for testing
    const TEST_TABLE: &str = "test-table";

    // -----------
    // | Helpers |
    // -----------

    /// Inserts 0..n into the table as big-endian [u8; 8] -> i in random order
    /// This preserves numeric ordering when used as keys
    fn insert_n_random(db: &DB, n: usize) {
        let mut values = (0..n).collect::<Vec<_>>();
        values.shuffle(&mut thread_rng());

        let tx = db.new_raw_write_tx().unwrap();
        for i in values.into_iter() {
            let key: ByteKey = (i as u64).to_be_bytes();
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
        let (k, v) = cursor.get_current().unwrap().unwrap();

        assert_eq!(*k, key);
        assert_eq!(*v, value);
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
        let mut cursor = tx.cursor::<ByteKey, usize>(TEST_TABLE).unwrap();
        cursor.seek_last().unwrap();
        let last = cursor.get_current().unwrap();

        let (key_bytes, value) = last.unwrap();
        let key = u64::from_be_bytes(*key_bytes) as usize;
        assert_eq!(key, N - 1);
        assert_eq!(*value, (N - 1) as u32);
    }

    /// Tests deleting the item under the cursor
    #[test]
    fn test_delete() {
        let db = mock_db();
        db.create_table(TEST_TABLE).unwrap();

        let (k1, v1) = ("k1".to_string(), "v1".to_string());
        let (k2, v2) = ("k2".to_string(), "v2".to_string());

        // Insert a key/value pair
        db.write(TEST_TABLE, &k1, &v1).unwrap();
        db.write(TEST_TABLE, &k2, &v2).unwrap();

        // Read the first key, it should be `Some`
        let tx = db.new_raw_write_tx().unwrap();
        {
            let mut cursor = tx.cursor::<String, String>(TEST_TABLE).unwrap();
            cursor.seek_first().unwrap();
            let (k, v) = cursor.get_current().unwrap().unwrap();
            assert_eq!(*k, k1);
            assert_eq!(*v, v1);

            // Delete the key
            cursor.delete().unwrap();
            let (k, v) = cursor.get_current().unwrap().unwrap();
            assert_eq!(*k, k2);
            assert_eq!(*v, v2);
        }
        tx.commit().unwrap();

        // Start a new transaction
        let tx = db.new_raw_read_tx().unwrap();
        let mut cursor = tx.cursor::<String, String>(TEST_TABLE).unwrap();

        // Read the first key, it should be (k2, v2)
        cursor.seek_first().unwrap();
        let (k, v) = cursor.get_current().unwrap().unwrap();
        assert_eq!(*k, k2);
        assert_eq!(*v, v2);
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
        let (k, v) = cursor.get_current().unwrap().unwrap();

        assert_eq!(*k, k2);
        assert_eq!(*v, v2);
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
        let cursor = tx.cursor::<ByteKey, usize>(TEST_TABLE).unwrap();
        for (i, pair) in cursor.into_iter().enumerate() {
            let (k_bytes, v) = pair.unwrap();
            let k = u64::from_be_bytes(*k_bytes) as usize;
            assert_eq!(k, i);
            assert_eq!(*v, i as u32);
        }
    }

    /// Tests a very simple case of a prefix cursor
    #[test]
    fn test_prefix_cursor_simple() {
        let db = mock_db();
        db.create_table(TEST_TABLE).unwrap();

        // Insert a key/value pair
        db.write(TEST_TABLE, &"order:1".to_string(), &1u32).unwrap();

        // Create a cursor with "order:" prefix
        let tx = db.new_raw_read_tx().unwrap();
        let cursor = tx.cursor::<String, u32>(TEST_TABLE).unwrap().with_key_prefix("order:");
        let elems: Vec<_> = cursor.into_iter().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(elems.len(), 1);
        assert_eq!(*elems[0].0, "order:1");
        assert_eq!(*elems[0].1, 1u32);
    }

    /// Tests a prefix-filtered cursor using string keys
    #[test]
    fn test_prefix_cursor() {
        let db = mock_db();
        db.create_table(TEST_TABLE).unwrap();

        // Insert keys with different prefixes
        let tx = db.new_raw_write_tx().unwrap();
        tx.write(TEST_TABLE, &"order:1".to_string(), &1u32).unwrap();
        tx.write(TEST_TABLE, &"order:2".to_string(), &2u32).unwrap();
        tx.write(TEST_TABLE, &"order:3".to_string(), &3u32).unwrap();
        tx.write(TEST_TABLE, &"other:1".to_string(), &10u32).unwrap();
        tx.write(TEST_TABLE, &"other:2".to_string(), &20u32).unwrap();
        tx.write(TEST_TABLE, &"zzz:1".to_string(), &100u32).unwrap();
        tx.commit().unwrap();

        // Create a cursor with "order:" prefix
        let tx = db.new_raw_read_tx().unwrap();
        let cursor = tx.cursor::<String, u32>(TEST_TABLE).unwrap().with_key_prefix("order:");

        // Iterate - should only return order: keys and stop at first non-matching
        let elems: Vec<_> = cursor.into_iter().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(elems.len(), 3);

        // Verify the keys are correct
        assert_eq!(*elems[0].0, "order:1");
        assert_eq!(*elems[0].1, 1u32);
        assert_eq!(*elems[1].0, "order:2");
        assert_eq!(*elems[1].1, 2u32);
        assert_eq!(*elems[2].0, "order:3");
        assert_eq!(*elems[2].1, 3u32);
    }

    /// Tests that prefix cursor stops at first non-matching key
    #[test]
    fn test_prefix_cursor_stops_early() {
        let db = mock_db();
        db.create_table(TEST_TABLE).unwrap();

        // Insert keys where prefix keys are in the middle
        let tx = db.new_raw_write_tx().unwrap();
        tx.write(TEST_TABLE, &"aaa".to_string(), &1u32).unwrap();
        tx.write(TEST_TABLE, &"prefix:1".to_string(), &2u32).unwrap();
        tx.write(TEST_TABLE, &"prefix:2".to_string(), &3u32).unwrap();
        tx.write(TEST_TABLE, &"zzz".to_string(), &4u32).unwrap();
        tx.commit().unwrap();

        // Create a cursor with "prefix:" prefix - should use set_range to skip "aaa"
        let tx = db.new_raw_read_tx().unwrap();
        let cursor = tx.cursor::<String, u32>(TEST_TABLE).unwrap().with_key_prefix("prefix:");

        let elems: Vec<_> = cursor.into_iter().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(elems.len(), 2);
        assert_eq!(*elems[0].0, "prefix:1");
        assert_eq!(*elems[1].0, "prefix:2");
    }

    /// Tests prefix cursor with no matching keys
    #[test]
    fn test_prefix_cursor_no_matches() {
        let db = mock_db();
        db.create_table(TEST_TABLE).unwrap();

        // Insert keys that don't match the prefix
        let tx = db.new_raw_write_tx().unwrap();
        tx.write(TEST_TABLE, &"aaa".to_string(), &1u32).unwrap();
        tx.write(TEST_TABLE, &"bbb".to_string(), &2u32).unwrap();
        tx.commit().unwrap();

        // Create a cursor with "zzz:" prefix - should find nothing
        let tx = db.new_raw_read_tx().unwrap();
        let cursor = tx.cursor::<String, u32>(TEST_TABLE).unwrap().with_key_prefix("zzz:");

        let elems: Vec<_> = cursor.into_iter().collect::<Result<Vec<_>, _>>().unwrap();
        assert!(elems.is_empty());
    }
}
