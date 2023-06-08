//! Defines the PriceReporterManagerExecutor, the handler that is responsible for executing
//! individual PriceReporterManagerJobs.
use std::{collections::HashMap, thread::JoinHandle};
use tokio::sync::oneshot::{channel, Sender as TokioSender};
use tokio::{runtime::Runtime, sync::mpsc::UnboundedReceiver as TokioReceiver};
use tracing::log;

use crate::{system_bus::SystemBus, types::SystemBusMessage, CancelChannel};

use super::{
    errors::PriceReporterManagerError,
    exchange::{Exchange, ExchangeConnectionState},
    jobs::PriceReporterManagerJob,
    reporter::{PriceReporter, PriceReporterState},
    tokens::Token,
    worker::PriceReporterManagerConfig,
};

/// The PriceReporterManager worker is a wrapper around the PriceReporterManagerExecutor, handling
/// and dispatching jobs to the executor for spin-up and shut-down of individual PriceReporters.
pub struct PriceReporterManager {
    /// The config for the PriceReporterManager
    pub(super) config: PriceReporterManagerConfig,
    /// The single thread that joins all individual PriceReporter threads
    pub(super) manager_executor_handle: Option<JoinHandle<PriceReporterManagerError>>,
    /// The tokio runtime that the manager runs inside of
    pub(super) manager_runtime: Option<Runtime>,
}

/// The actual executor that handles incoming jobs, to create and destroy PriceReporters, and peek
/// at PriceReports.
pub struct PriceReporterManagerExecutor {
    /// The map between base/quote token pairs and the instantiated PriceReporter
    active_price_reporters: HashMap<(Token, Token), PriceReporter>,
    /// The manager config
    config: PriceReporterManagerConfig,
    /// The channel along which jobs are passed to the price reporter
    job_receiver: TokioReceiver<PriceReporterManagerJob>,
    /// The channel on which the coordinator may cancel execution
    cancel_channel: CancelChannel,
    /// The global system bus
    system_bus: SystemBus<SystemBusMessage>,
}

impl PriceReporterManagerExecutor {
    /// Creates the executor for the PriceReporterManager worker.
    pub(super) fn new(
        job_receiver: TokioReceiver<PriceReporterManagerJob>,
        config: PriceReporterManagerConfig,
        cancel_channel: CancelChannel,
        system_bus: SystemBus<SystemBusMessage>,
    ) -> Self {
        Self {
            job_receiver,
            cancel_channel,
            system_bus,
            active_price_reporters: HashMap::new(),
            config,
        }
    }

    /// The execution loop for the price reporter
    pub(super) async fn execution_loop(mut self) -> Result<(), PriceReporterManagerError> {
        loop {
            tokio::select! {
                // Dequeue the next job from elsewhere in the local node
                Some(job) = self.job_receiver.recv() => {
                    if let Err(e) = self.handle_job(job).await {
                        log::error!("Error in PriceReporterManager execution loop: {e}");
                    }
                },

                // Await cancellation by the coordinator
                _ = self.cancel_channel.changed() => {
                    log::info!("PriceReporterManager cancelled, shutting down...");
                    return Err(PriceReporterManagerError::Cancelled("received cancel signal".to_string()));
                }
            }
        }
    }

    /// Handles a job for the PriceReporterManager worker.
    pub(super) async fn handle_job(
        &mut self,
        job: PriceReporterManagerJob,
    ) -> Result<(), PriceReporterManagerError> {
        match job {
            PriceReporterManagerJob::StartPriceReporter {
                base_token,
                quote_token,
                channel,
            } => {
                self.start_price_reporter(base_token, quote_token, channel)
                    .await
            }

            PriceReporterManagerJob::PeekMedian {
                base_token,
                quote_token,
                channel,
            } => self.peek_median(base_token, quote_token, channel).await,

            PriceReporterManagerJob::PeekAllExchanges {
                base_token,
                quote_token,
                channel,
            } => {
                self.peek_all_exchanges(base_token, quote_token, channel)
                    .await
            }
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
        channel: TokioSender<()>,
    ) -> Result<(), PriceReporterManagerError> {
        if self
            .active_price_reporters
            .contains_key(&(base_token.clone(), quote_token.clone()))
        {
            // Send an ack indicating the reporter is created
            if channel.send(()).is_err() {
                log::error!("Error sending ACK for PriceReporterManager job",);
            }

            return Ok(());
        }

        // Create the price reporter
        let reporter =
            PriceReporter::new(base_token.clone(), quote_token.clone(), self.config.clone())
                .await
                .map_err(|err| PriceReporterManagerError::PriceReporterCreation(err.to_string()))?;
        self.active_price_reporters
            .insert((base_token.clone(), quote_token.clone()), reporter);

        Ok(())
    }

    /// Handler for PeekMedian job
    async fn peek_median(
        &mut self,
        base_token: Token,
        quote_token: Token,
        channel: TokioSender<PriceReporterState>,
    ) -> Result<(), PriceReporterManagerError> {
        let price_reporter = self
            .get_price_reporter_or_create(base_token, quote_token)
            .await?;
        channel.send(price_reporter.peek_median()).unwrap();
        Ok(())
    }

    /// Handler for PeekAllExchanges job
    async fn peek_all_exchanges(
        &mut self,
        base_token: Token,
        quote_token: Token,
        channel: TokioSender<HashMap<Exchange, ExchangeConnectionState>>,
    ) -> Result<(), PriceReporterManagerError> {
        let price_reporter = self
            .get_price_reporter_or_create(base_token, quote_token)
            .await?;
        channel.send(price_reporter.peek_all_exchanges()).unwrap();
        Ok(())
    }

    // -----------
    // | Helpers |
    // -----------

    /// Internal helper function to get a (base_token, quote_token) PriceReporter
    fn get_price_reporter(
        &self,
        base_token: Token,
        quote_token: Token,
    ) -> Result<&PriceReporter, PriceReporterManagerError> {
        self.active_price_reporters
            .get(&(base_token.clone(), quote_token.clone()))
            .ok_or_else(|| {
                PriceReporterManagerError::PriceReporterNotCreated(format!(
                    "{:?}",
                    (base_token, quote_token)
                ))
            })
    }

    /// Internal helper function to get a (base_token, quote_token) PriceReporter. If the
    /// PriceReporter does not already exist, first creates it.
    async fn get_price_reporter_or_create(
        &mut self,
        base_token: Token,
        quote_token: Token,
    ) -> Result<&PriceReporter, PriceReporterManagerError> {
        if self
            .active_price_reporters
            .get(&(base_token.clone(), quote_token.clone()))
            .is_none()
        {
            let (channel_sender, _channel_receiver) = channel();
            self.start_price_reporter(base_token.clone(), quote_token.clone(), channel_sender)
                .await?;
        }

        self.get_price_reporter(base_token, quote_token)
    }
}
