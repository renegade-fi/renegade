//! Indexing of intents by metadata
//!
//! Specifically, we build an efficiently queryable mapping from pair -> side ->
//! (matchable_amount, intent_id)
//!
//! This allows the matching engine to efficiently query a narrow set of
//! candidate intents to match against a target intent.

use circuit_types::Amount;
use darkpool_types::intent::Intent;
use dashmap::DashMap;
use types_account::account::{IntentIdentifier, pair::Pair};

/// The intent metadata index
#[derive(Default)]
pub struct IntentMetadataIndex {
    /// The mapping from pair -> (matchable_amount, intent_id)
    index: DashMap<Pair, SortedVec<(Amount, IntentIdentifier)>>,
    /// A reverse mapping from intent_id to pair and side
    ///
    /// This is used to efficiently query the index by intent_id for updates and
    /// deletion
    reverse_index: DashMap<IntentIdentifier, Pair>,
}

impl IntentMetadataIndex {
    /// Construct a new intent metadata index
    pub fn new() -> Self {
        let index = DashMap::new();
        let reverse_index = DashMap::new();
        Self { index, reverse_index }
    }

    // --- Getters --- //

    /// Get all intents for a given pair and side, sorted by matchable amount
    pub fn get_intents(&self, pair: &Pair) -> Vec<IntentIdentifier> {
        match self.index.get(pair) {
            Some(v) => v.iter().map(|(_, iid)| *iid).collect(),
            None => Vec::new(),
        }
    }

    /// Get all intents in the index
    ///
    /// No sort ordering is guaranteed, given that the units on which individual
    /// intents are sorted may differ
    pub fn get_all_intents(&self) -> Vec<IntentIdentifier> {
        self.reverse_index.iter().map(|entry| *entry.key()).collect()
    }

    /// Get the pair and side for a given intent_id
    pub fn get_pair(&self, intent_id: &IntentIdentifier) -> Option<Pair> {
        self.reverse_index.get(intent_id).map(|entry| *entry.value())
    }

    /// Returns whether an intent exists in the index synchronously
    pub fn intent_exists(&self, intent_id: &IntentIdentifier) -> bool {
        self.reverse_index.contains_key(intent_id)
    }

    // --- Setters --- //

    /// Add an intent to the index
    pub fn add_intent(
        &self,
        intent_id: IntentIdentifier,
        intent: &Intent,
        matchable_amount: Amount,
    ) {
        let pair = Pair::from_intent(intent);
        let mut entry = self.index.entry(pair).or_insert_with(SortedVec::new);
        entry.insert((matchable_amount, intent_id));

        // Update the reverse index
        self.reverse_index.insert(intent_id, pair);
    }

    /// Update the matchable amount for an intent
    ///
    /// Returns the old matchable amount if it was updated, otherwise None
    pub fn update_matchable_amount(
        &self,
        intent_id: IntentIdentifier,
        matchable_amount: Amount,
    ) -> Option<Amount> {
        let pair = self.get_pair(&intent_id).unwrap();
        let mut entry = self.index.entry(pair).or_insert_with(SortedVec::new);

        // Remove the old entry
        let old_amount = if let Some(idx) = entry.find_index(|(_, iid)| *iid == intent_id) {
            let (amt, _) = entry.remove(idx);
            Some(amt)
        } else {
            None
        };

        // Insert the new entry (this will maintain the sort order)
        entry.insert((matchable_amount, intent_id));
        old_amount
    }

    /// Remove an intent from the index
    ///
    /// Note that we do not clean up sub-index entries when their
    /// lists become empty.
    ///
    /// Returns the pair, side, and matchable amount if the intent was removed,
    /// otherwise None
    pub fn remove_intent(&self, intent_id: &IntentIdentifier) -> Option<(Pair, Amount)> {
        // Get the pair and side from the reverse index
        let pair = self.get_pair(intent_id)?;

        // Remove from the main index
        let mut entry = self.index.get_mut(&pair)?;
        let old_amount = if let Some(idx) = entry.find_index(|(_, iid)| iid == intent_id) {
            let (amt, _) = entry.remove(idx);
            Some(amt)
        } else {
            None
        };

        // Remove from the reverse index
        self.reverse_index.remove(intent_id);
        old_amount.map(|amt| (pair, amt))
    }
}

/// A vector that is kept sorted on insert
struct SortedVec<T> {
    /// The inner vector
    vec: Vec<T>,
}

impl<T: Ord> SortedVec<T> {
    /// Construct a new sorted vector
    pub fn new() -> Self {
        Self { vec: Vec::new() }
    }

    // --- Getters --- //

    /// Get the element at index i
    #[cfg(test)]
    pub fn get(&self, i: usize) -> Option<&T> {
        self.vec.get(i)
    }

    /// Find the index of an element in the vector using the given filter method
    pub fn find_index(&self, filter: impl Fn(&T) -> bool) -> Option<usize> {
        self.vec.iter().position(filter)
    }

    /// Get the vector
    #[cfg(test)]
    pub fn vec(&self) -> &Vec<T> {
        &self.vec
    }

    /// Iterate over the vector
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.vec.iter()
    }

    // --- Setters --- //

    /// Insert an element into the vector
    pub fn insert(&mut self, element: T) {
        // For descending order, we want to insert after all elements that are greater
        // than or equal to the current element
        // The `binary_search_by` returns the index at which the element can be found,
        // or an `Err` containing the index at which the element should be inserted
        let index = match self.vec.binary_search_by(|probe| element.cmp(probe)) {
            Ok(i) => i,
            Err(i) => i,
        };
        self.vec.insert(index, element);
    }

    /// Remove an element from the vector
    pub fn remove(&mut self, index: usize) -> T {
        self.vec.remove(index)
    }
}

#[cfg(test)]
mod sorted_vec_tests {
    use super::*;
    use rand::{Rng, seq::SliceRandom, thread_rng};

    #[test]
    fn test_sorted_vec_empty() {
        let vec: SortedVec<i32> = SortedVec::new();
        assert!(vec.vec().is_empty());
    }

    #[test]
    fn test_sorted_vec_basic() {
        let mut vec = SortedVec::new();
        vec.insert(3);
        vec.insert(1);
        vec.insert(4);
        vec.insert(2);

        assert_eq!(vec.vec(), &[4, 3, 2, 1]);
    }

    #[test]
    fn test_sorted_vec_duplicates() {
        let mut vec = SortedVec::new();
        vec.insert(2);
        vec.insert(2);
        vec.insert(2);
        vec.insert(1);
        vec.insert(1);

        assert_eq!(vec.vec(), &[2, 2, 2, 1, 1]);
    }

    #[test]
    fn test_sorted_vec_single_element() {
        let mut vec = SortedVec::new();
        vec.insert(1);
        assert_eq!(vec.vec(), &[1]);
    }

    #[test]
    fn test_sorted_vec_fuzz() {
        // Create a vector of 100 random numbers
        let mut rng = thread_rng();
        let mut numbers: Vec<i32> = (0..100).map(|_| rng.gen_range(-1000..1000)).collect();

        // Insert them into SortedVec
        let mut sorted_vec = SortedVec::new();
        for &n in &numbers {
            sorted_vec.insert(n);
        }

        // Sort the original vector in descending order for comparison
        numbers.sort();
        numbers.reverse();
        assert_eq!(sorted_vec.vec(), &numbers);
    }

    #[test]
    fn test_sorted_vec_random_order() {
        let mut vec = SortedVec::new();
        let mut numbers: Vec<i32> = (1..=10).collect();
        numbers.shuffle(&mut thread_rng());

        // Insert in random order
        for n in numbers {
            vec.insert(n);
        }

        // Should be sorted in descending order
        assert_eq!(vec.vec(), &[10, 9, 8, 7, 6, 5, 4, 3, 2, 1]);
    }
}

#[cfg(test)]
mod intent_index_tests {
    use darkpool_types::fuzzing::random_address;
    use types_account::mocks::mock_intent;

    use super::*;

    #[test]
    fn test_get_all_intents() {
        let index = IntentMetadataIndex::new();
        let intent_id1 = IntentIdentifier::new_v4();
        let intent_id2 = IntentIdentifier::new_v4();
        let intent_id3 = IntentIdentifier::new_v4();

        // Create mock intents
        let intent1 = mock_intent();
        let intent2 = mock_intent();
        let intent3 = mock_intent();

        // Add intents to the index
        index.add_intent(intent_id1, &intent1, 100);
        index.add_intent(intent_id2, &intent2, 200);
        index.add_intent(intent_id3, &intent3, 300);

        // Get all intents and verify
        let all_intents = index.get_all_intents();
        let mut intents: Vec<IntentIdentifier> = all_intents.into_iter().collect();
        intents.sort();

        let mut expected = vec![intent_id1, intent_id2, intent_id3];
        expected.sort();

        assert_eq!(intents, expected);
    }

    #[test]
    fn test_empty_index() {
        let index = IntentMetadataIndex::new();
        let base = random_address();
        let quote = random_address();
        let pair = Pair::new(base, quote);
        let intents = index.get_intents(&pair);
        assert!(intents.is_empty());
    }

    #[test]
    fn test_add_and_get_single_intent() {
        let index = IntentMetadataIndex::new();
        let intent_id = IntentIdentifier::new_v4();
        let intent = mock_intent();
        let pair = Pair::from_intent(&intent);

        let fillable_amount = 100;
        index.add_intent(intent_id, &intent, fillable_amount);
        let intents = index.get_intents(&pair);
        assert_eq!(intents.len(), 1);
        assert_eq!(intents[0], intent_id);
    }

    #[test]
    fn test_intents_sorted_by_amount() {
        let index = IntentMetadataIndex::new();
        let intent = mock_intent();
        let pair = Pair::from_intent(&intent);

        // Add intents with different matchable amounts
        let intent_id1 = IntentIdentifier::new_v4();
        let intent_id2 = IntentIdentifier::new_v4();
        let intent_id3 = IntentIdentifier::new_v4();
        let intent_id4 = IntentIdentifier::new_v4();

        index.add_intent(intent_id1, &intent, 300);
        index.add_intent(intent_id2, &intent, 100);
        index.add_intent(intent_id3, &intent, 200);
        index.add_intent(intent_id4, &intent, 400);

        let intents = index.get_intents(&pair);
        assert_eq!(intents.len(), 4);
        assert_eq!(intents[0], intent_id4); // 400
        assert_eq!(intents[1], intent_id1); // 300
        assert_eq!(intents[2], intent_id3); // 200
        assert_eq!(intents[3], intent_id2); // 100
    }

    #[test]
    fn test_different_pairs() {
        let index = IntentMetadataIndex::new();
        let intent1 = mock_intent();
        let intent2 = mock_intent();
        let pair1 = Pair::from_intent(&intent1);
        let pair2 = Pair::from_intent(&intent2);

        let intent_id1 = IntentIdentifier::new_v4();
        let intent_id2 = IntentIdentifier::new_v4();
        let intent_id3 = IntentIdentifier::new_v4();
        let intent_id4 = IntentIdentifier::new_v4();

        index.add_intent(intent_id1, &intent1, 100);
        index.add_intent(intent_id2, &intent2, 200);
        index.add_intent(intent_id3, &intent1, 300);
        index.add_intent(intent_id4, &intent2, 400);

        let intents1 = index.get_intents(&pair1);
        let intents2 = index.get_intents(&pair2);

        assert_eq!(intents1.len(), 2);
        assert_eq!(intents2.len(), 2);
    }

    #[test]
    fn test_update_matchable_amount() {
        let index = IntentMetadataIndex::new();
        let intent_id = IntentIdentifier::new_v4();
        let intent = mock_intent();
        let pair = Pair::from_intent(&intent);

        // Add an intent with an initial matchable amount
        let initial_amount = 100;
        index.add_intent(intent_id, &intent, initial_amount);

        // Update the matchable amount
        let updated_amount = 200;
        let old_amount = index.update_matchable_amount(intent_id, updated_amount);

        // Get the intents and verify the intent is in the correct position
        let intents = index.get_intents(&pair);
        assert_eq!(intents.len(), 1);
        assert_eq!(intents[0], intent_id);

        // Verify the updated amount by checking the internal state
        let side_index = index.index.get(&pair).unwrap();
        let sorted_vec = side_index.get(0).unwrap();
        assert_eq!(sorted_vec.0, updated_amount);

        // Verify the returned old amount
        assert_eq!(old_amount, Some(initial_amount));
    }

    #[test]
    fn test_update_matchable_amount_sort_order() {
        let index = IntentMetadataIndex::new();
        let intent = mock_intent();
        let pair = Pair::from_intent(&intent);

        // Add two intents with initial amounts
        let intent_id1 = IntentIdentifier::new_v4();
        let intent_id2 = IntentIdentifier::new_v4();

        index.add_intent(intent_id1, &intent, 200);
        index.add_intent(intent_id2, &intent, 100);

        // Verify initial sort order (descending by amount)
        let intents = index.get_intents(&pair);
        assert_eq!(intents.len(), 2);
        assert_eq!(intents[0], intent_id1); // 200
        assert_eq!(intents[1], intent_id2); // 100

        // Update intent2's amount to be larger than intent1
        let old_amount = index.update_matchable_amount(intent_id2, 300);

        // Verify the sort order has changed
        let intents = index.get_intents(&pair);
        assert_eq!(intents.len(), 2);
        assert_eq!(intents[0], intent_id2); // 300
        assert_eq!(intents[1], intent_id1); // 200

        // Verify the returned old amount
        assert_eq!(old_amount, Some(100));
    }

    #[test]
    fn test_remove_intent() {
        let index = IntentMetadataIndex::new();
        let intent_id = IntentIdentifier::new_v4();
        let intent = mock_intent();
        let pair = Pair::from_intent(&intent);

        // Add an intent
        index.add_intent(intent_id, &intent, 100);

        // Verify it was added
        let intents = index.get_intents(&pair.clone());
        assert_eq!(intents.len(), 1);
        assert_eq!(intents[0], intent_id);

        // Remove the intent
        let result = index.remove_intent(&intent_id);
        assert_eq!(result, Some((pair, 100)));

        // Verify it was removed
        let intents = index.get_intents(&pair.clone());
        assert!(intents.is_empty());

        // Verify it was removed from reverse index
        let pair_and_side = index.get_pair(&intent_id);
        assert!(pair_and_side.is_none());
    }

    #[test]
    fn test_remove_nonexistent_intent() {
        let index = IntentMetadataIndex::new();
        let intent_id = IntentIdentifier::new_v4();

        // Try to remove a nonexistent intent
        let result = index.remove_intent(&intent_id);
        assert!(result.is_none());
    }

    #[test]
    fn test_remove_intent_maintains_sort() {
        let index = IntentMetadataIndex::new();
        let intent = mock_intent();
        let pair = Pair::from_intent(&intent);

        // Add three intents
        let intent_id1 = IntentIdentifier::new_v4();
        let intent_id2 = IntentIdentifier::new_v4();
        let intent_id3 = IntentIdentifier::new_v4();

        index.add_intent(intent_id1, &intent, 300);
        index.add_intent(intent_id2, &intent, 200);
        index.add_intent(intent_id3, &intent, 100);

        // Remove the middle intent
        let result = index.remove_intent(&intent_id2);
        assert_eq!(result, Some((pair, 200)));

        // Verify remaining intents are still sorted
        let intents = index.get_intents(&pair.clone());
        assert_eq!(intents.len(), 2);
        assert_eq!(intents[0], intent_id1); // 300
        assert_eq!(intents[1], intent_id3); // 100
    }
}
