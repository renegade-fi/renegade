//! A mock price reporter used for testing

use std::thread;

use bimap::BiMap;
use common::types::exchange::{PriceReport, PriceReporterState};
use common::types::token::{Token, TICKER_NAMES, TOKEN_REMAPS};
use common::types::Price;
use job_types::price_reporter::{PriceReporterJob, PriceReporterReceiver};
use tokio::runtime::Runtime as TokioRuntime;
use tokio::sync::oneshot::Sender as OneshotSender;
use tracing::{debug, error};
use util::get_current_time_seconds;

use crate::errors::PriceReporterError;

/// Setup the static token remap as a mock for testing
#[allow(unused_must_use)]
pub fn setup_mock_token_remap() {
    // Setup the mock token map
    let mut token_map = BiMap::new();
    for (i, token_data) in TICKER_NAMES.iter().enumerate() {
        // Pull the ticker, the index 0 field
        let ticker = token_data.0.to_string();
        let addr = format!("{i:x}");

        token_map.insert(addr, ticker);
    }

    // Do not unwrap in case another test set the remap
    TOKEN_REMAPS.set(token_map);
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
        let timestamp = get_current_time_seconds();
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
    use common::types::{exchange::PriceReporterState, token::Token};
    use job_types::price_reporter::{new_price_reporter_queue, PriceReporterJob};
    use tokio::sync::oneshot::channel;

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
        let (resp_send, resp_recv) = channel();
        let job = PriceReporterJob::PeekPrice {
            base_token: Token::from_ticker("WETH"),
            quote_token: Token::from_ticker("USDC"),
            channel: resp_send,
        };

        price_sender.send(job).unwrap();

        // Check the response
        let resp = resp_recv.await.unwrap();
        match resp {
            PriceReporterState::Nominal(report) => {
                assert_eq!(report.price, PRICE);
            },
            _ => panic!("unexpected response: {resp:?}"),
        };
    }
}
