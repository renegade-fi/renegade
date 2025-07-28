//! Concurrency primitives for the PriceReporter manager's shared streams

use std::{
    collections::HashMap,
    sync::atomic::{AtomicU64, Ordering},
};

use atomic_float::AtomicF64;
use common::types::{
    exchange::{Exchange, PriceReporterState},
    price::Price,
    token::{Token, default_exchange_stable, is_pair_named},
};
use external_api::bus_message::{SystemBusMessage, price_report_topic};
use util::concurrency::{AsyncShared, new_async_shared};

use crate::{
    manager::utils::{
        compute_price_reporter_state, eligible_for_stable_quote_conversion, get_all_stream_tuples,
        get_supported_exchanges,
    },
    worker::PriceReporterConfig,
};

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
    /// Update the state of the price stream
    pub fn new_price(&self, price: Price, timestamp: u64) {
        // These operations are not transactionally related, so there is a chance
        // for a race in between updating the timestamp and the price. This is
        // generally okay as the timestamp is only used for determining staleness
        // and given a race the timestamp will be very close to correct
        self.price.store(price, Ordering::Relaxed);
        self.last_received.store(timestamp, Ordering::Relaxed);
    }

    /// Read the price and timestamp
    pub fn read_price(&self) -> (Price, u64) {
        (self.price.load(Ordering::Relaxed), self.last_received.load(Ordering::Relaxed))
    }
}

/// A shareable mapping between (exchange, base, quote) and the most recent
/// state of the associated price stream
#[derive(Clone, Debug)]
pub struct SharedPriceStreamStates(
    AsyncShared<HashMap<(Exchange, Token, Token), AtomicPriceStreamState>>,
);

impl SharedPriceStreamStates {
    /// Create a new shared price stream state map
    ///
    /// This inserts a default state for each (exchange, base, quote) pair
    /// which is supported by the given config
    pub fn new(cfg: &PriceReporterConfig) -> Self {
        let all_stream_tuples = get_all_stream_tuples(cfg);
        let states = all_stream_tuples
            .into_iter()
            .map(|(exchange, base, quote)| {
                ((exchange, base, quote), AtomicPriceStreamState::default())
            })
            .collect();

        Self(new_async_shared(states))
    }

    /// Clear all price states, returning the keys that were cleared
    pub async fn clear_states(&self) -> Vec<(Exchange, Token, Token)> {
        let mut price_stream_states = self.0.write().await;

        let keys = price_stream_states.keys().cloned().collect();
        price_stream_states.clear();

        keys
    }

    /// Remove the state for the given (exchange, base, quote) price stream
    pub async fn remove_state(&self, exchange: Exchange, base: Token, quote: Token) {
        let mut price_stream_states = self.0.write().await;

        price_stream_states.remove(&(exchange, base, quote));
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
        let price_stream_states = self.0.read().await;

        let price_state = price_stream_states
            .get(&(exchange, base.clone(), quote.clone()))
            .ok_or(format!("Price stream state not found for ({exchange}, {base}, {quote})",))?;

        price_state.new_price(price, timestamp);

        Ok(())
    }

    /// Get the state of the price reporter for the given token pair
    pub async fn get_state(
        &self,
        base_token: Token,
        quote_token: Token,
        config: &PriceReporterConfig,
    ) -> PriceReporterState {
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
        let supported_exchanges = get_supported_exchanges(&base_token, &quote_token, config);
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

    /// Compute a price report for the given token pair and publish it to the
    /// system bus
    pub async fn publish_price_report(
        &self,
        base: Token,
        quote: Token,
        config: &PriceReporterConfig,
    ) {
        let topic_name = price_report_topic(&base, &quote);
        if config.system_bus.has_listeners(&topic_name) {
            if let PriceReporterState::Nominal(report) = self.get_state(base, quote, config).await {
                config.system_bus.publish(topic_name, SystemBusMessage::PriceReport(report));
            }
        }
    }

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
            self.0
                .read()
                .await
                .get(&(exchange, base_token.clone(), quote_token.clone()))
                .map(|state| state.read_price())
        }
    }

    /// Converts the price for the given pair through the default stable quote
    /// asset for the exchange
    async fn convert_through_default_stable(
        &self,
        base_token: &Token,
        quote_token: &Token,
        exchange: Exchange,
    ) -> Option<(Price, u64)> {
        let states = self.0.read().await;

        let default_stable = default_exchange_stable(&exchange);

        // Get the base / default stable price
        let (base_price, base_ts) =
            states.get(&(exchange, base_token.clone(), default_stable.clone()))?.read_price();

        // Get the quote / default stable price
        let (quote_price, quote_ts) =
            states.get(&(exchange, quote_token.clone(), default_stable.clone()))?.read_price();

        // The converted price = (base / default stable) / (quote / default stable)
        let price = base_price / quote_price;

        // We take the minimum of the two timestamps, so we err on the side of safety
        // and call a price stale if one of the two price streams is stale
        let ts = base_ts.min(quote_ts);

        Some((price, ts))
    }
}
