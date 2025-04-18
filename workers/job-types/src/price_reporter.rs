//! Defines all possible jobs for the PriceReporter.
use common::types::TimestampedPrice;
use common::types::{exchange::PriceReporterState, token::Token};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender as TokioUnboundedSender};
use tokio::sync::oneshot::{self, Receiver as TokioReceiver, Sender as TokioSender};
use util::metered_channels::MeteredTokioReceiver;

/// The name of the price reporter queue, used to label queue length metrics
const PRICE_REPORTER_QUEUE_NAME: &str = "price_reporter";

/// The queue receiver type for the price reporter
pub type PriceReporterReceiver = MeteredTokioReceiver<PriceReporterJob>;

/// Create a new price reporter queue and receiver
pub fn new_price_reporter_queue() -> (PriceReporterQueue, PriceReporterReceiver) {
    let (send, recv) = unbounded_channel();
    (send.into(), MeteredTokioReceiver::new(recv, PRICE_REPORTER_QUEUE_NAME))
}

/// The queue type for the price reporter
#[derive(Clone)]
pub struct PriceReporterQueue {
    /// The inner sender
    inner: TokioUnboundedSender<PriceReporterJob>,
}

impl From<TokioUnboundedSender<PriceReporterJob>> for PriceReporterQueue {
    fn from(inner: TokioUnboundedSender<PriceReporterJob>) -> Self {
        Self { inner }
    }
}

impl PriceReporterQueue {
    /// Send a job to the price reporter
    pub fn send(&self, job: PriceReporterJob) -> Result<(), String> {
        self.inner.send(job).map_err(|e| format!("failed to send price reporter job: {e}"))
    }

    /// Peek a timestamped price from the price reporter
    pub async fn peek_price(
        &self,
        base_token: Token,
        quote_token: Token,
    ) -> Result<TimestampedPrice, String> {
        let report = self.peek_price_report(base_token, quote_token).await?;
        report.price()
    }

    /// Peek a timestamped price from the price reporter using usdc as the quote
    /// token
    pub async fn peek_price_usdc(&self, base_token: Token) -> Result<TimestampedPrice, String> {
        let usdc = Token::usdc();
        self.peek_price(base_token, usdc).await
    }

    /// Peek a full price report from the price reporter
    pub async fn peek_price_report(
        &self,
        base_token: Token,
        quote_token: Token,
    ) -> Result<PriceReporterState, String> {
        let (job, recv) = PriceReporterJob::peek_price(base_token, quote_token);
        self.send(job)?;
        recv.await.map_err(|e| format!("failed to receive price report: {e}"))
    }

    /// Stream a price for the given token pair
    pub fn stream_price(&self, base_token: Token, quote_token: Token) -> Result<(), String> {
        let job = PriceReporterJob::StreamPrice { base_token, quote_token };
        self.send(job)
    }
}

/// All possible jobs that the PriceReporter accepts.
#[derive(Debug)]
pub enum PriceReporterJob {
    /// Stream prices for the given token pair.
    ///
    /// If using the external executor, this will send a subscription request
    /// for the pair across all exchanges.
    ///
    /// If using the native executor, this will create and start a new
    /// PriceReporter for the pair.
    ///
    /// If the PriceReporter does not yet exist, spawn it and begin publication
    /// to the global system bus. If the PriceReporter already exists and id
    /// is None, this is a no-op.
    ///
    /// If the PriceReporter already exists and id is Some, register this ID as
    /// a listener. This prevents tear-down of the PriceReporter, even if
    /// subscribers on the system bus stop listening. Cleanup is done via
    /// DropListenerID, and callees are responsible for dropping all
    /// listener IDs.
    StreamPrice {
        /// The base Token
        base_token: Token,
        /// The quote Token
        quote_token: Token,
    },
    /// Peek at the price report
    PeekPrice {
        /// The base Token
        base_token: Token,
        /// The quote Token
        quote_token: Token,
        /// The return channel for the price report
        channel: TokioSender<PriceReporterState>,
    },
}

impl PriceReporterJob {
    /// A new job to peek at a price report
    pub fn peek_price(
        base_token: Token,
        quote_token: Token,
    ) -> (Self, TokioReceiver<PriceReporterState>) {
        let (send, recv) = oneshot::channel();
        (Self::PeekPrice { base_token, quote_token, channel: send }, recv)
    }
}
