//! Samples order-cancellation-related metrics at a fixed interval

use std::time::Duration;

use common::types::{
    network_order::NetworkOrderState, price::Price, token::Token,
    wallet::order_metadata::OrderMetadata,
};
use futures::future::join_all;
use num_bigint::BigUint;
use price_state::PriceStreamStates;
use state::State;
use util::hex::biguint_to_hex_addr;

use crate::sampler::AsyncMetricSampler;

/// The name of the sampler for cancellation metrics
const CANCELLATION_METRICS_SAMPLER_NAME: &str = "cancellation-metrics-sampler";
/// The interval at which to sample cancellation metrics
const CANCELLATION_METRICS_SAMPLE_INTERVAL_MS: u64 = 3_600_000; // 1 hour

/// Metric describing the number of orders cancelled
const NUM_ORDERS_CANCELLED_METRIC: &str = "num_orders_cancelled";
/// Metric describing the value of a cancelled order
const CANCELLED_ORDER_VALUE_METRIC: &str = "cancelled_order_value";
/// Metric describing the % filled of a cancelled order
const CANCELLED_ORDER_FILL_PERCENT_METRIC: &str = "cancelled_order_fill_percent";

/// Metric tag denoting the order ID
const ORDER_ID_METRIC_TAG: &str = "order_id";
/// Metric tag denoting the base ticker
const BASE_TICKER_METRIC_TAG: &str = "base_ticker";
/// Metric tag denoting the quote ticker
const QUOTE_TICKER_METRIC_TAG: &str = "quote_ticker";

/// Samples cancellation metrics at a fixed interval
#[derive(Clone)]
pub struct CancellationMetricsSampler {
    /// A handle to the global state
    state: State,
    /// A handle to the price streams
    price_streams: PriceStreamStates,
}

impl CancellationMetricsSampler {
    /// Create a new `CancellationMetricsSampler`
    pub fn new(state: State, price_streams: PriceStreamStates) -> Self {
        Self { state, price_streams }
    }

    // -------------------
    // | Private Helpers |
    // -------------------

    /// Get the metadata for all cancelled orders
    async fn get_cancelled_orders(&self) -> Result<Vec<OrderMetadata>, String> {
        let orders = self.state.get_all_orders().await?;
        let cancelled_orders =
            orders.into_iter().filter(|o| matches!(o.state, NetworkOrderState::Cancelled));

        let cancelled_orders_meta = join_all(
            cancelled_orders.map(|o| async move { self.state.get_order_metadata(&o.id).await }),
        )
        .await
        .into_iter()
        .filter_map(Result::ok)
        .map(|o| o.unwrap())
        .collect();

        Ok(cancelled_orders_meta)
    }

    /// Get the price for the pair that the given order trades
    fn get_price_for_order(&self, order: &OrderMetadata) -> Option<Price> {
        let base = Token::from_addr_biguint(&order.data.base_mint);
        self.price_streams.peek_price(&base).ok()
    }

    /// Get the tickers for the given pair of tokens
    fn get_pair_tickers(base_mint: &BigUint, quote_mint: &BigUint) -> (String, String) {
        let base = Token::from_addr_biguint(base_mint);
        let quote = Token::from_addr_biguint(quote_mint);

        let base_ticker =
            base.get_ticker().map(|t| t.to_string()).unwrap_or(biguint_to_hex_addr(base_mint));

        let quote_ticker =
            quote.get_ticker().map(|t| t.to_string()).unwrap_or(biguint_to_hex_addr(quote_mint));

        (base_ticker, quote_ticker)
    }

    /// Record the cancellation metrics for the given orders
    fn record_cancellation_metrics(
        &self,
        cancelled_orders: &[OrderMetadata],
    ) -> Result<(), String> {
        let num_orders_cancelled = cancelled_orders.len();
        metrics::gauge!(NUM_ORDERS_CANCELLED_METRIC).set(num_orders_cancelled as f64);

        for order in cancelled_orders {
            let (base_ticker, quote_ticker) =
                Self::get_pair_tickers(&order.data.base_mint, &order.data.quote_mint);

            self.record_cancelled_value(order, base_ticker.clone(), quote_ticker.clone());
            Self::record_fill_percent(order, base_ticker.clone(), quote_ticker.clone());
        }

        Ok(())
    }

    /// Record the remaining value of a cancelled order, if a price is available
    fn record_cancelled_value(
        &self,
        order: &OrderMetadata,
        base_ticker: String,
        quote_ticker: String,
    ) {
        let price = match self.get_price_for_order(order) {
            Some(price) => price,
            None => return,
        };

        let base = Token::from_addr_biguint(&order.data.base_mint);
        let remaining_amount = order.data.amount - order.total_filled();
        let remaining_amount_float = base.convert_to_decimal(remaining_amount);
        let cancelled_value = remaining_amount_float * price;

        metrics::gauge!(
            CANCELLED_ORDER_VALUE_METRIC,
            ORDER_ID_METRIC_TAG => order.id.to_string(),
            BASE_TICKER_METRIC_TAG => base_ticker,
            QUOTE_TICKER_METRIC_TAG => quote_ticker,
        )
        .set(cancelled_value);
    }

    /// Record the fill percent of a cancelled order
    fn record_fill_percent(order: &OrderMetadata, base_ticker: String, quote_ticker: String) {
        let fill_proportion = order.total_filled() as f64 / order.data.amount as f64;
        metrics::gauge!(
            CANCELLED_ORDER_FILL_PERCENT_METRIC,
            ORDER_ID_METRIC_TAG => order.id.to_string(),
            BASE_TICKER_METRIC_TAG => base_ticker,
            QUOTE_TICKER_METRIC_TAG => quote_ticker,
        )
        .set(fill_proportion);
    }
}

impl AsyncMetricSampler for CancellationMetricsSampler {
    fn name(&self) -> &str {
        CANCELLATION_METRICS_SAMPLER_NAME
    }

    fn interval(&self) -> Duration {
        Duration::from_millis(CANCELLATION_METRICS_SAMPLE_INTERVAL_MS)
    }

    async fn sample(&self) -> Result<(), String> {
        // Only sample on the leader to avoid duplicate metrics
        if !self.state.is_leader() {
            return Ok(());
        }

        let cancelled_orders = self.get_cancelled_orders().await?;
        self.record_cancellation_metrics(&cancelled_orders)?;

        Ok(())
    }
}
