//! Defines the PriceReporterExecutor, a handler that is responsible
//! for executing individual PriceReporterJobs. This is used when the
//! relayer opts for natively streaming price data from exchanges.

use common::default_wrapper::{DefaultOption, DefaultWrapper};
use common::types::CancelChannel;
use common::types::exchange::{Exchange, PriceReporterState};
use common::types::token::Token;
use constants::in_bootstrap_mode;
use job_types::price_reporter::{PriceReporterJob, PriceReporterReceiver};
use tokio::sync::oneshot::Sender as TokioSender;
use tracing::{Instrument, error, info, info_span, instrument, warn};
use util::channels::TracedMessage;
use util::concurrency::runtime::sleep_forever_async;

use crate::{
    errors::{ExchangeConnectionError, PriceReporterError},
    exchange::connection::ExchangeConnectionManager,
    manager::SharedPriceStreamStates,
    worker::PriceReporterConfig,
};

/// The actual executor that handles incoming jobs, to create and destroy
/// PriceReporters, and peek at PriceReports.
#[derive(Clone)]
pub struct PriceReporterExecutor {
    /// The latest states of all price streams from exchange connections
    price_stream_states: SharedPriceStreamStates,
    /// The manager config
    config: PriceReporterConfig,
    /// The channel along which jobs are passed to the price reporter
    job_receiver: DefaultOption<PriceReporterReceiver>,
    /// The channel on which the coordinator may cancel execution
    cancel_channel: DefaultOption<CancelChannel>,
}

impl PriceReporterExecutor {
    /// Creates the executor for the PriceReporter worker.
    pub(crate) fn new(
        job_receiver: PriceReporterReceiver,
        config: PriceReporterConfig,
        cancel_channel: CancelChannel,
    ) -> Self {
        Self {
            job_receiver: DefaultWrapper::new(Some(job_receiver)),
            cancel_channel: DefaultWrapper::new(Some(cancel_channel)),
            price_stream_states: SharedPriceStreamStates::default(),
            config,
        }
    }

    /// The execution loop for the price reporter
    pub(crate) async fn execution_loop(mut self) -> Result<(), PriceReporterError> {
        // If the relayer is in bootstrap mode, sleep forever
        if in_bootstrap_mode() {
            sleep_forever_async().await;
        }

        let mut job_receiver = self.job_receiver.take().unwrap();
        let mut cancel_channel = self.cancel_channel.take().unwrap();

        loop {
            tokio::select! {
                // Dequeue the next job from elsewhere in the local node
                Some(job) = job_receiver.recv() => {
                    if self.config.disabled {
                        warn!("PriceReporter received job while disabled, ignoring...");
                        continue;
                    }

                    tokio::spawn({
                        let self_clone = self.clone();
                        async move {
                            if let Err(e) = self_clone.handle_job(job).await {
                                error!("Error in PriceReporter execution loop: {e}");
                            }
                        }.instrument(info_span!("handle_job"))
                    });
                },

                // Await cancellation by the coordinator
                _ = cancel_channel.changed() => {
                    info!("PriceReporter cancelled, shutting down...");
                    return Err(PriceReporterError::Cancelled("received cancel signal".to_string()));
                }
            }
        }
    }

    /// Handles a job for the PriceReporter worker.
    #[instrument(name = "handle_price_reporter_job", skip(self, job))]
    pub(super) async fn handle_job(
        &self,
        job: TracedMessage<PriceReporterJob>,
    ) -> Result<(), PriceReporterError> {
        match job.consume() {
            PriceReporterJob::StreamPrice { base_token, quote_token } => {
                self.stream_price(base_token, quote_token).await
            },

            PriceReporterJob::PeekPrice { base_token, quote_token, channel } => {
                self.peek_price(base_token, quote_token, channel).await
            },
        }
    }

    // ----------------
    // | Job Handlers |
    // ----------------

    /// Handler for StreamPrice job
    async fn stream_price(
        &self,
        base_token: Token,
        quote_token: Token,
    ) -> Result<(), PriceReporterError> {
        let req_streams = self
            .price_stream_states
            .missing_streams_for_pair(base_token, quote_token, &self.config)
            .await;

        for (exchange, base, quote) in req_streams {
            self.start_exchange_connection(exchange, base, quote)
                .map_err(PriceReporterError::ExchangeConnection)?;
        }

        Ok(())
    }

    /// Handler for PeekPrice job
    async fn peek_price(
        &self,
        base_token: Token,
        quote_token: Token,
        channel: TokioSender<PriceReporterState>,
    ) -> Result<(), PriceReporterError> {
        // Spawn a task to stream the price. If all of the required streams are already
        // initialized, this will be a no-op.
        tokio::spawn({
            let self_clone = self.clone();
            let base_token = base_token.clone();
            let quote_token = quote_token.clone();
            async move { self_clone.stream_price(base_token, quote_token).await }
        });

        channel
            .send(self.price_stream_states.get_state(base_token, quote_token, &self.config).await)
            .unwrap();

        Ok(())
    }

    // -----------
    // | Helpers |
    // -----------

    /// Initializes a connection to an exchange for the given token pair
    /// by spawning a new ExchangeConnectionManager.
    fn start_exchange_connection(
        &self,
        exchange: Exchange,
        base_token: Token,
        quote_token: Token,
    ) -> Result<(), ExchangeConnectionError> {
        let conn_manager = ExchangeConnectionManager::new(
            exchange,
            base_token,
            quote_token,
            self.config.clone(),
            self.price_stream_states.clone(),
        );

        tokio::spawn(async move {
            if let Err(e) = conn_manager.execution_loop().await {
                error!("Error in PriceReporter execution loop: {e}");
            }
        });
        Ok(())
    }
}
