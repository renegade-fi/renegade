//! Defines the PriceReporterExecutor, the handler that is responsible
//! for executing individual PriceReporterJobs.
use common::default_wrapper::{DefaultOption, DefaultWrapper};
use common::types::exchange::PriceReporterState;
use common::types::token::Token;
use common::types::CancelChannel;
use common::{new_async_shared, AsyncShared};
use job_types::price_reporter::{PriceReporterJob, PriceReporterReceiver};
use std::{collections::HashMap, thread::JoinHandle};
use tokio::runtime::Runtime;
use tokio::sync::oneshot::Sender as TokioSender;
use tracing::{error, info, info_span, warn, Instrument};
use util::err_str;

use crate::errors::{ExchangeConnectionError, PriceReporterError};

use super::{reporter::Reporter, worker::PriceReporterConfig};

/// The PriceReporter worker is a wrapper around the
/// PriceReporterExecutor, handling and dispatching jobs to the executor
/// for spin-up and shut-down of individual PriceReporters.
pub struct PriceReporter {
    /// The config for the PriceReporter
    pub(super) config: PriceReporterConfig,
    /// The single thread that joins all individual PriceReporter threads
    pub(super) manager_executor_handle: Option<JoinHandle<PriceReporterError>>,
    /// The tokio runtime that the manager runs inside of
    pub(super) manager_runtime: Option<Runtime>,
}

/// The actual executor that handles incoming jobs, to create and destroy
/// PriceReporters, and peek at PriceReports.
#[derive(Clone)]
pub struct PriceReporterExecutor {
    /// The map between base/quote token pairs and the instantiated
    /// PriceReporter
    active_price_reporters: AsyncShared<HashMap<(Token, Token), Reporter>>,
    /// The manager config
    config: PriceReporterConfig,
    /// The channel along which jobs are passed to the price reporter
    job_receiver: DefaultOption<PriceReporterReceiver>,
    /// The channel on which the coordinator may cancel execution
    cancel_channel: DefaultOption<CancelChannel>,
}

impl PriceReporterExecutor {
    /// Creates the executor for the PriceReporter worker.
    pub(super) fn new(
        job_receiver: PriceReporterReceiver,
        config: PriceReporterConfig,
        cancel_channel: CancelChannel,
    ) -> Self {
        Self {
            job_receiver: DefaultWrapper::new(Some(job_receiver)),
            cancel_channel: DefaultWrapper::new(Some(cancel_channel)),
            active_price_reporters: new_async_shared(HashMap::new()),
            config,
        }
    }

    /// The execution loop for the price reporter
    pub(super) async fn execution_loop(mut self) -> Result<(), PriceReporterError> {
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
                        let mut self_clone = self.clone();
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
    pub(super) async fn handle_job(
        &mut self,
        job: PriceReporterJob,
    ) -> Result<(), PriceReporterError> {
        match job {
            PriceReporterJob::StartPriceReporter { base_token, quote_token } => {
                self.start_price_reporter(base_token, quote_token).await
            },

            PriceReporterJob::PeekMedian { base_token, quote_token, channel } => {
                self.peek_median(base_token, quote_token, channel).await
            },
        }
    }

    // ----------------
    // | Job Handlers |
    // ----------------

    /// Handler for StartPriceReporter job
    async fn start_price_reporter(
        &mut self,
        base_token: Token,
        quote_token: Token,
    ) -> Result<(), PriceReporterError> {
        let mut locked_reporters = self.active_price_reporters.write().await;
        if locked_reporters.contains_key(&(base_token.clone(), quote_token.clone())) {
            return Ok(());
        }

        // Create the price reporter
        let reporter =
            match Reporter::new(base_token.clone(), quote_token.clone(), self.config.clone()) {
                Ok(reporter) => reporter,
                Err(ExchangeConnectionError::NoSupportedExchanges(base, quote)) => {
                    return Err(PriceReporterError::UnsupportedPair(base, quote));
                },
                Err(e) => {
                    return Err(e).map_err(err_str!(PriceReporterError::PriceReporterCreation))
                },
            };

        locked_reporters.insert((base_token.clone(), quote_token.clone()), reporter);

        Ok(())
    }

    /// Handler for PeekMedian job
    async fn peek_median(
        &mut self,
        base_token: Token,
        quote_token: Token,
        channel: TokioSender<PriceReporterState>,
    ) -> Result<(), PriceReporterError> {
        match self.get_price_reporter_or_create(base_token, quote_token).await {
            Ok(reporter) => channel.send(reporter.peek_median()).unwrap(),
            Err(PriceReporterError::UnsupportedPair(base, quote)) => {
                channel.send(PriceReporterState::UnsupportedPair(base, quote)).unwrap()
            },
            Err(e) => return Err(e),
        };

        Ok(())
    }

    // -----------
    // | Helpers |
    // -----------

    /// Internal helper function to get a (base_token, quote_token)
    /// PriceReporter
    async fn get_price_reporter(
        &self,
        base_token: Token,
        quote_token: Token,
    ) -> Result<Reporter, PriceReporterError> {
        let locked_reporters = self.active_price_reporters.read().await;
        locked_reporters.get(&(base_token.clone(), quote_token.clone())).cloned().ok_or_else(|| {
            PriceReporterError::PriceReporterNotCreated(format!("{:?}", (base_token, quote_token)))
        })
    }

    /// Internal helper function to get a (base_token, quote_token)
    /// PriceReporter. If the PriceReporter does not already exist, first
    /// creates it.
    async fn get_price_reporter_or_create(
        &mut self,
        base_token: Token,
        quote_token: Token,
    ) -> Result<Reporter, PriceReporterError> {
        let reporter_exists = {
            self.active_price_reporters
                .read()
                .await
                .contains_key(&(base_token.clone(), quote_token.clone()))
        };

        if !reporter_exists {
            self.start_price_reporter(base_token.clone(), quote_token.clone()).await?;
        }
        self.get_price_reporter(base_token, quote_token).await
    }
}
