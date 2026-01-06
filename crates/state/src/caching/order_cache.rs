//! A cache for common predicates evaluated on the intent book
//!
//! E.g. querying intents which are (externally) matchable, or querying open
//! intents on a given asset

use circuit_types::Amount;
use darkpool_types::intent::Intent;
use dashmap::DashSet;
use tracing::instrument;
use types_account::account::{IntentIdentifier, pair::Pair};

use crate::storage::{db::DB, error::StorageError};

use super::{matchable_amount::MatchableAmountMap, order_metadata_index::IntentMetadataIndex};

/// A filter for querying the order book cache
#[derive(Clone, Debug)]
pub struct OrderBookFilter {
    /// The pair to filter on
    ///
    /// In order (input_token, output_token)
    pair: Pair,
    /// Whether to only accept externally matchable intents
    external: bool,
}

impl OrderBookFilter {
    /// Construct a new order book filter
    pub fn new(pair: Pair, external: bool) -> Self {
        Self { pair, external }
    }
}

/// The order book cache
#[derive(Default)]
pub struct OrderBookCache {
    /// The set of local intents which have external matches enabled
    ///
    /// This may not be a subset of `matchable_intents`, some externally
    /// matchable intents may not be yet matchable, e.g. if they are waiting for
    /// validity proofs
    externally_enabled_intents: DashSet<IntentIdentifier>,
    /// The index of intent metadata
    intent_metadata_index: IntentMetadataIndex,
    /// Mapping of matchable amount at the midpoint of a pair
    matchable_amount_map: MatchableAmountMap,
}

impl OrderBookCache {
    /// Construct a new order book cache
    pub fn new() -> Self {
        Self {
            externally_enabled_intents: DashSet::new(),
            intent_metadata_index: IntentMetadataIndex::new(),
            matchable_amount_map: MatchableAmountMap::new(),
        }
    }

    // --- Getters --- //

    /// Get intents matching a filter
    pub fn get_intents(&self, filter: &OrderBookFilter) -> Vec<IntentIdentifier> {
        let intents = self.intent_metadata_index.get_intents(&filter.pair);
        if filter.external {
            intents.into_iter().filter(|id| self.externally_enabled_intents.contains(id)).collect()
        } else {
            intents
        }
    }

    /// Returns whether an intent exists in the cache
    pub fn intent_exists(&self, id: IntentIdentifier) -> bool {
        self.intent_metadata_index.intent_exists(&id)
    }

    /// Get all intents that match any filter
    pub fn get_all_intents(&self) -> Vec<IntentIdentifier> {
        self.intent_metadata_index.get_all_intents()
    }

    /// Get the matchable amount for both sides of a pair
    ///
    /// Returns (buy_amount, sell_amount) where buy amount is denominated in the
    /// quote token, sell amount is denominated in the base token
    pub fn get_matchable_amount(&self, pair: &Pair) -> (Amount, Amount) {
        self.matchable_amount_map.get(pair)
    }

    // --- Setters --- //

    /// Add an intent to the cache
    pub fn add_intent(&self, id: IntentIdentifier, intent: &Intent, matchable_amount: Amount) {
        self.intent_metadata_index.add_intent(id, intent, matchable_amount);
        // TODO: Implement externally enabled intents
        // if intent.allow_external_matches {
        //     self.externally_enabled_intents.write().await.insert(id);
        //     let pair = Pair::from_intent(intent);
        //     self.matchable_amount_map.add_amount(pair,
        // matchable_amount).await; }
    }

    /// Update an intent in the cache
    pub fn update_intent(&self, id: IntentIdentifier, matchable_amount: Amount) {
        let pair = self.intent_metadata_index.get_pair(&id).unwrap();

        // Update the index and get the previous matchable amount
        let old_amount =
            self.intent_metadata_index.update_matchable_amount(id, matchable_amount).unwrap_or(0);

        if self.externally_enabled_intents.contains(&id) {
            // Update the matchable amount map with the delta
            if old_amount > matchable_amount {
                let delta = old_amount.saturating_sub(matchable_amount);
                self.matchable_amount_map.sub_amount(pair, delta);
            } else {
                let delta = matchable_amount.saturating_sub(old_amount);
                self.matchable_amount_map.add_amount(pair, delta);
            }
        }
    }

    /// Mark an intent as externally matchable
    pub fn mark_intent_externally_matchable(&self, intent: IntentIdentifier) {
        self.externally_enabled_intents.insert(intent);
    }

    /// Remove an intent from the cache entirely
    pub fn remove_intent(&self, intent: IntentIdentifier) {
        let maybe_info = self.intent_metadata_index.remove_intent(&intent);
        if maybe_info.is_none() {
            return;
        }
        let (pair, matchable_amount) = maybe_info.unwrap();

        if self.externally_enabled_intents.remove(&intent).is_some() {
            self.matchable_amount_map.sub_amount(pair, matchable_amount);
        }
    }

    /// Remove an externally enabled intent
    pub fn remove_externally_enabled_intent(&self, intent: IntentIdentifier) {
        self.externally_enabled_intents.remove(&intent);
    }

    /// Backfill the intent cache from a DB
    ///
    /// This method may be used to populate the cache on startup
    #[instrument(skip(self, db))]
    pub fn hydrate_from_db(&self, db: &DB) -> Result<(), StorageError> {
        // TODO: Implement intent book storage
        // let tx = db.new_read_tx()?;
        // let intents = tx.get_local_intents()?;
        // for intent_id in intents.into_iter() {
        //     // Fetch intent info and check if the intent is ready for matching
        //     let info = match tx.get_intent_info(&intent_id)? {
        //         Some(info) => info,
        //         None => continue,
        //     };

        //     if info.local && info.ready_for_match() {
        //         // Get the intent itself
        //         let wallet = match tx.get_wallet_for_intent(&intent_id)? {
        //             Some(wallet) => wallet,
        //             None => continue,
        //         };

        //         let intent = match wallet.get_intent(&intent_id) {
        //             Some(intent) => intent,
        //             None => continue,
        //         };

        //         let matchable_amount =
        //             wallet.get_balance_for_intent(intent).map(|b|
        // b.amount).unwrap_or_default();         self.add_intent(intent_id,
        // intent, matchable_amount).await;     }
        // }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use types_account::mocks::mock_intent;

    use super::*;

    /// Tests getting an intent by pair
    #[test]
    fn test_get_intents_basic() {
        let cache = OrderBookCache::new();
        let intent_id = IntentIdentifier::new_v4();
        let intent = mock_intent();
        let pair = Pair::from_intent(&intent);

        // Add an intent to the cache
        cache.add_intent(intent_id, &intent, 100 /* matchable_amount */);

        let filter = OrderBookFilter::new(pair, false /* external */);
        let intents = cache.get_intents(&filter);
        assert_eq!(intents.len(), 1);
        assert_eq!(intents[0], intent_id);

        // Remove the intent from the cache
        cache.remove_intent(intent_id);
        let intents = cache.get_intents(&filter);
        assert_eq!(intents.len(), 0);
    }

    /// Tests getting multiple intents by their pair
    #[test]
    fn test_get_intents_multiple() {
        let cache = OrderBookCache::new();
        let intent_id1 = IntentIdentifier::new_v4();
        let intent_id2 = IntentIdentifier::new_v4();
        let intent_id3 = IntentIdentifier::new_v4();
        let intent = mock_intent();
        let pair = Pair::from_intent(&intent);

        cache.add_intent(intent_id1, &intent, 100 /* matchable_amount */);
        cache.add_intent(intent_id2, &intent, 300 /* matchable_amount */);
        cache.add_intent(intent_id3, &intent, 200 /* matchable_amount */);

        let filter = OrderBookFilter::new(pair, false /* external */);
        let intents = cache.get_intents(&filter);
        assert_eq!(intents.len(), 3);
        assert_eq!(intents, vec![intent_id2, intent_id3, intent_id1]);

        // Remove the middle intent
        cache.remove_intent(intent_id3);
        let intents = cache.get_intents(&filter);
        assert_eq!(intents.len(), 2);
        assert_eq!(intents, vec![intent_id2, intent_id1]);
    }

    // TODO: Implement external intents
    // /// Tests getting external intents only
    // #[test]
    // fn test_get_intents_external() {
    //     let cache = IntentBookCache::new();
    //     let intent_id1 = IntentIdentifier::new_v4();
    //     let intent_id2 = IntentIdentifier::new_v4();
    //     let intent_id3 = IntentIdentifier::new_v4();
    //     let mut intent1 = mock_intent();
    //     let mut intent2 = intent1.clone();
    //     let mut intent3 = intent1.clone();
    //     intent1.allow_external_matches = true;
    //     intent2.allow_external_matches = false;
    //     intent3.allow_external_matches = true;

    //     cache.add_intent(intent_id1, &intent1, 100 /* matchable_amount */).await;
    //     cache.add_intent(intent_id2, &intent2, 200 /* matchable_amount */).await;
    //     cache.add_intent(intent_id3, &intent3, 300 /* matchable_amount */).await;

    //     let filter = IntentBookFilter::new(intent1.pair(), intent1.side, true /*
    // external */);     let intents = cache.get_intents(filter.clone()).await;
    //     assert_eq!(intents.len(), 2);
    //     assert_eq!(intents, vec![intent_id3, intent_id1]);

    //     // Remove the first intent
    //     cache.remove_intent(intent_id1).await;
    //     let intents = cache.get_intents(filter).await;
    //     assert_eq!(intents.len(), 1);
    //     assert_eq!(intents, vec![intent_id3]);
    // }

    /// Tests getting intents on different pairs
    #[test]
    fn test_get_intents_different_pairs() {
        let cache = OrderBookCache::new();
        let intent_id1 = IntentIdentifier::new_v4();
        let intent_id2 = IntentIdentifier::new_v4();
        let intent_id3 = IntentIdentifier::new_v4();
        let intent1 = mock_intent();
        let intent2 = mock_intent();
        let intent3 = intent1.clone();
        let pair1 = Pair::from_intent(&intent1);
        let pair2 = Pair::from_intent(&intent2);

        cache.add_intent(intent_id1, &intent1, 300 /* matchable_amount */);
        cache.add_intent(intent_id2, &intent2, 100 /* matchable_amount */);
        cache.add_intent(intent_id3, &intent3, 200 /* matchable_amount */);

        // Check the first pair
        let filter1 = OrderBookFilter::new(pair1, false /* external */);
        let intents = cache.get_intents(&filter1);
        assert_eq!(intents.len(), 2);
        assert_eq!(intents, vec![intent_id1, intent_id3]);

        // Check the second pair
        let filter2 = OrderBookFilter::new(pair2, false /* external */);
        let intents = cache.get_intents(&filter2);
        assert_eq!(intents.len(), 1);
        assert_eq!(intents, vec![intent_id2]);

        // Remove from the first pair
        cache.remove_intent(intent_id1);
        let intents = cache.get_intents(&filter1);
        assert_eq!(intents.len(), 1);
        assert_eq!(intents, vec![intent_id3]);

        // Remove from the second pair
        cache.remove_intent(intent_id2);
        let intents = cache.get_intents(&filter2);
        assert_eq!(intents.len(), 0);
    }
}
