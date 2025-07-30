//! Concurrency primitives for the PriceReporter manager's shared streams

use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use atomic_float::AtomicF64;
use common::types::{
    exchange::{Exchange, PriceReporterState},
    price::Price,
    token::{Token, default_exchange_stable, is_pair_named},
};
use itertools::Itertools;

use crate::{
    StreamTuple,
    util::{
        compute_price_reporter_state, eligible_for_stable_quote_conversion, get_listing_exchanges,
    },
};

// ---------------------------
// | Individual Stream State |
// ---------------------------

/// The state of a price stream for a given (exchange, base, quote).
/// Uses atomic primitives to allow for hardware synchronized update streaming
#[derive(Debug, Default)]
pub struct AtomicPriceStreamState {
    /// The price of the pair on the exchange
    price: AtomicF64,
    /// The time at which the last price was received from the exchange
    last_received: AtomicU64,
}

impl AtomicPriceStreamState {
    /// Read the price and timestamp
    pub fn read_price(&self) -> (Price, u64) {
        (self.price.load(Ordering::Relaxed), self.last_received.load(Ordering::Relaxed))
    }

    /// Update the state of the price stream
    pub fn new_price(&self, price: Price, timestamp: u64) {
        // These operations are not transactionally related, so there is a chance
        // for a race in between updating the timestamp and the price. This is
        // generally okay as the timestamp is only used for determining staleness
        // and given a race the timestamp will be very close to correct
        self.price.store(price, Ordering::Relaxed);
        self.last_received.store(timestamp, Ordering::Relaxed);
    }

    /// Clear the state of the price stream
    pub fn clear(&self) {
        self.price.store(0.0, Ordering::Relaxed);
        self.last_received.store(0, Ordering::Relaxed);
    }
}

// -----------------------
// | Price Stream States |
// -----------------------

/// A set of price stream states
///
/// Wraps the inner type in an `Arc` to facilitate efficient clones throughout
/// the relayer by individual workers
#[derive(Clone, Debug)]
pub struct PriceStreamStates(Arc<PriceStreamStatesInner>);

/// A shareable mapping between (exchange, base, quote) and the most recent
/// state of the associated price stream
#[derive(Clone, Debug)]
pub struct PriceStreamStatesInner {
    /// The mapping between (exchange, base, quote) and the most recent
    states: Arc<HashMap<StreamTuple, AtomicPriceStreamState>>,
    /// The set of disabled exchanges
    disabled_exchanges: HashSet<Exchange>,
}

impl PriceStreamStates {
    /// Create a new shared price stream state map
    ///
    /// This inserts a default state for each (exchange, base, quote) pair
    /// which is supported by the given config
    pub fn new(streams: Vec<StreamTuple>, disabled_exchanges: Vec<Exchange>) -> Self {
        let states = streams
            .into_iter()
            .map(|(exchange, base, quote)| {
                ((exchange, base, quote), AtomicPriceStreamState::default())
            })
            .collect();

        let inner = PriceStreamStatesInner {
            states: Arc::new(states),
            disabled_exchanges: disabled_exchanges.into_iter().collect(),
        };
        Self(Arc::new(inner))
    }

    /// Get a reference to the inner states
    fn states(&self) -> &HashMap<StreamTuple, AtomicPriceStreamState> {
        &self.0.states
    }

    /// Returns whether a given exchange is disabled
    fn is_exchange_disabled(&self, exchange: &Exchange) -> bool {
        self.0.disabled_exchanges.contains(exchange)
    }

    // --- Getters --- //

    /// Get the state of the price reporter for the given token pair
    pub async fn get_state(&self, base_token: Token, quote_token: Token) -> PriceReporterState {
        // We don't currently support unnamed pairs
        if !is_pair_named(&base_token, &quote_token) {
            return PriceReporterState::UnsupportedPair(base_token, quote_token);
        }

        // Fetch the most recent price from the canonical exchange
        let (price, ts) =
            match self.get_latest_price(Exchange::Renegade, &base_token, &quote_token).await {
                None => return PriceReporterState::NotEnoughDataReported(0),
                Some((price, ts)) => (price, ts),
            };

        // Fetch the most recent prices from all other exchanges
        let mut exchange_prices = Vec::new();
        let supported_exchanges = self.get_supported_exchanges(&base_token, &quote_token);
        for exchange in supported_exchanges {
            if let Some((price, ts)) =
                self.get_latest_price(exchange, &base_token, &quote_token).await
            {
                exchange_prices.push((exchange, (price, ts)));
            }
        }

        // Compute the state of the price reporter
        compute_price_reporter_state(base_token, quote_token, price, ts, &exchange_prices)
    }

    // --- Setters --- //

    /// Clear all price states, returning the keys that were cleared
    pub async fn clear_states(&self) -> Vec<(Exchange, Token, Token)> {
        // Iterate over the elements, clear the values and clone the keys
        self.states()
            .iter()
            .map(|(k, v)| {
                v.clear();
                k.clone()
            })
            .collect()
    }

    /// Update the price state for the given (exchange, base, quote)
    pub async fn new_price(
        &self,
        exchange: Exchange,
        base: Token,
        quote: Token,
        price: Price,
        timestamp: u64,
    ) -> Result<(), String> {
        let stream_tuple = (exchange, base.clone(), quote.clone());
        let price_state = self
            .states()
            .get(&stream_tuple)
            .ok_or(format!("Price stream state not found for ({exchange}, {base}, {quote})",))?;
        price_state.new_price(price, timestamp);

        Ok(())
    }

    // --- Helpers --- //

    /// Get the latest price for the given exchange and token pair.
    ///
    /// If the pair is eligible, we convert the price through the default stable
    /// quote for the exchange.
    async fn get_latest_price(
        &self,
        exchange: Exchange,
        base_token: &Token,
        quote_token: &Token,
    ) -> Option<(Price, u64)> {
        if eligible_for_stable_quote_conversion(base_token, quote_token, &exchange) {
            self.convert_through_default_stable(base_token, quote_token, exchange).await
        } else {
            let stream_tuple = (exchange, base_token.clone(), quote_token.clone());
            self.states().get(&stream_tuple).map(|state| state.read_price())
        }
    }

    /// Returns the set of exchanges that support both tokens in the pair.
    ///
    /// Note: This does not mean that each exchange has a market for the pair,
    /// just that it separately lists both tokens.
    fn get_supported_exchanges(&self, base_token: &Token, quote_token: &Token) -> Vec<Exchange> {
        // Get the exchanges that list both tokens, and filter out the ones that
        // are not configured
        let listing_exchanges = get_listing_exchanges(base_token, quote_token);
        listing_exchanges
            .into_iter()
            .filter(|exchange| !self.is_exchange_disabled(exchange))
            .collect_vec()
    }

    /// Converts the price for the given pair through the default stable quote
    /// asset for the exchange
    async fn convert_through_default_stable(
        &self,
        base_token: &Token,
        quote_token: &Token,
        exchange: Exchange,
    ) -> Option<(Price, u64)> {
        let default_stable = default_exchange_stable(&exchange);

        // Get the base / default stable price
        let default_tuple = (exchange, base_token.clone(), default_stable.clone());
        let (base_price, base_ts) = self.states().get(&default_tuple)?.read_price();

        // Get the quote / default stable price
        let conversion_tuple = (exchange, quote_token.clone(), default_stable.clone());
        let (quote_price, quote_ts) = self.states().get(&conversion_tuple)?.read_price();

        // The converted price = (base / default stable) / (quote / default stable)
        let price = base_price / quote_price;

        // We take the minimum of the two timestamps, so we err on the side of safety
        // and call a price stale if one of the two price streams is stale
        let ts = base_ts.min(quote_ts);

        Some((price, ts))
    }
}
