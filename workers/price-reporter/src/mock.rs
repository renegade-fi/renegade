//! A mock price reporter used for testing

use std::thread;

use common::types::chain::Chain;
use common::types::exchange::{PriceReport, PriceReporterState};
use common::types::token::{write_token_remaps, Token, USDC_TICKER, USDT_TICKER, USD_TICKER};
use common::types::Price;
use job_types::price_reporter::{PriceReporterJob, PriceReporterReceiver};
use tokio::runtime::Runtime as TokioRuntime;
use tokio::sync::oneshot::Sender as OneshotSender;
use tracing::{debug, error};
use util::get_current_time_millis;

use crate::errors::PriceReporterError;

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
    let chain = Chain::Mainnet;
    let token_map = all_maps.entry(chain).or_default();
    token_map.clear();
    for (i, &ticker) in MOCK_TICKER_NAMES.iter().enumerate() {
        let addr = format!("{i:x}");

        token_map.insert(addr, ticker.to_string());
    }
}

/// The mock price reporter, reports a constant price
pub struct MockPriceReporter {
    /// The price to report for all pairs
    price: Price,
    /// The queue on which to accept jobs
    job_queue: PriceReporterReceiver,
}

impl MockPriceReporter {
    /// Create a new mock price reporter
    pub fn new(price: Price, job_queue: PriceReporterReceiver) -> Self {
        Self { price, job_queue }
    }

    /// Start the mock price reporter
    pub fn run(self) {
        thread::spawn(move || {
            let rt = TokioRuntime::new().unwrap();
            rt.block_on(self.execution_loop());
        });
    }

    /// The execution loop of the mock price reporter
    async fn execution_loop(mut self) {
        loop {
            let job = self.job_queue.recv().await;
            if let Some(job) = job {
                if let Err(e) = self.handle_job(job) {
                    error!("error in mock price reporter: {e:?}");
                }
            }
        }
    }

    /// Handle a job
    fn handle_job(&self, job: PriceReporterJob) -> Result<(), PriceReporterError> {
        match job {
            PriceReporterJob::StreamPrice { .. } => {
                debug!("mock price reporter got `StartPriceReporter` job");
                Ok(())
            },
            PriceReporterJob::PeekPrice { base_token, quote_token, channel } => {
                self.handle_peek_price(base_token, quote_token, channel)
            },
        }
    }

    /// Handle a peek price job
    fn handle_peek_price(
        &self,
        base_token: Token,
        quote_token: Token,
        channel: OneshotSender<PriceReporterState>,
    ) -> Result<(), PriceReporterError> {
        // Construct a state and send it back on the queue
        let timestamp = get_current_time_millis();
        let state = PriceReporterState::Nominal(PriceReport {
            base_token,
            quote_token,
            price: self.price,
            local_timestamp: timestamp,
        });

        if let Err(e) = channel.send(state) {
            error!("error sending price report: {e:?}");
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use common::types::token::Token;
    use job_types::price_reporter::new_price_reporter_queue;

    use crate::mock::{setup_mock_token_remap, MockPriceReporter};

    /// Test the price reporter from the mock
    #[tokio::test]
    async fn test_peek_price() {
        const PRICE: f64 = 100.9;
        setup_mock_token_remap();

        // Start a price reporter
        let (price_sender, price_recv) = new_price_reporter_queue();

        let reporter = MockPriceReporter::new(PRICE, price_recv);
        reporter.run();

        // Request a price
        let base = Token::from_ticker("WETH");
        let quote = Token::from_ticker("USDC");
        let resp = price_sender.peek_price(base, quote).await.unwrap();

        assert_eq!(resp.price, PRICE);
    }
}
