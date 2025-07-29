//! A mock price reporter used for testing

use common::types::chain::Chain;
use common::types::price::Price;
use common::types::token::{
    USD_TICKER, USDC_TICKER, USDT_TICKER, set_default_chain, write_token_remaps,
};
use price_state::PriceStreamStates;
use util::get_current_time_millis;

use crate::manager::utils::get_all_stream_tuples;
use crate::worker::PriceReporterConfig;

/// Ticker names to use in setting up the mock token remap
const MOCK_TICKER_NAMES: &[&str] = &[
    USDC_TICKER,
    USDT_TICKER,
    USD_TICKER,
    "WBTC",
    "WETH",
    "ARB",
    "GMX",
    "PENDLE",
    "LDO",
    "LINK",
    "CRV",
    "UNI",
    "ZRO",
    "LPT",
    "GRT",
    "COMP",
    "AAVE",
    "XAI",
    "RDNT",
    "ETHFI",
];

/// Setup the static token remap as a mock for testing
#[allow(unused_must_use)]
pub fn setup_mock_token_remap() {
    // Setup the mock token map
    let mut all_maps = write_token_remaps();
    let chain = Chain::ArbitrumOne;
    let token_map = all_maps.entry(chain).or_default();
    token_map.clear();
    for (i, &ticker) in MOCK_TICKER_NAMES.iter().enumerate() {
        let addr = format!("{i:x}");

        token_map.insert(addr, ticker.to_string());
    }

    set_default_chain(chain);
}

/// The mock price reporter, reports a constant price
pub struct MockPriceReporter {
    /// The price to report for all pairs
    price: Price,
    /// The queue on which to accept jobs
    price_streams: PriceStreamStates,
    /// The config for the price reporter
    config: PriceReporterConfig,
}

impl MockPriceReporter {
    /// Create a new mock price reporter
    pub fn new(
        price: Price,
        price_streams: PriceStreamStates,
        config: PriceReporterConfig,
    ) -> Self {
        Self { price, price_streams, config }
    }

    /// Get the price streams
    pub fn build_price_streams(config: &PriceReporterConfig) -> PriceStreamStates {
        let all_streams = get_all_stream_tuples(config);
        let disabled_exchanges = vec![];
        PriceStreamStates::new(all_streams, disabled_exchanges)
    }

    /// Start the mock price reporter
    pub fn run(self) {
        // Place a dummy value for each price stream
        let all_streams = get_all_stream_tuples(&self.config);
        for (exchange, base, quote) in all_streams {
            let price = self.price;
            let ts = get_current_time_millis();
            self.price_streams.new_price(exchange, base, quote, price, ts).unwrap();
        }
    }
}
