//! Defines the PriceReporterManagerExecutor, the handler that is responsible for executing
//! individual PriceReporterManagerJobs.
use crossbeam::channel::{self, Sender};
use futures::StreamExt;
use ring_channel::RingReceiver;
use std::{
    collections::{HashMap, HashSet},
    thread::JoinHandle,
};
use tokio::runtime::{Handle, Runtime};
use uuid::Uuid;

use crate::{system_bus::SystemBus, types::SystemBusMessage};

use super::{
    errors::PriceReporterManagerError,
    exchanges::{Exchange, ExchangeConnectionState},
    jobs::PriceReporterManagerJob,
    reporter::{PriceReport, PriceReporter, PriceReporterState},
    tokens::Token,
    worker::PriceReporterManagerConfig,
};

/// A listener ID on a PriceReporter is just a UUID.
pub type PriceReporterListenerID = Uuid;

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
    /// The global system bus
    pub(super) system_bus: SystemBus<SystemBusMessage>,
    /// A handle to the tokio runtime that the manager runs inside of
    pub(super) tokio_handle: Handle,
    /// The map between base/quote token pairs and the instantiated PriceReporter
    pub(super) spawned_price_reporters: HashMap<(Token, Token), PriceReporter>,
    /// The map between base/quote token pairs and the set of registered listeners
    pub(super) registered_listeners: HashMap<(Token, Token), HashSet<PriceReporterListenerID>>,
    /// The manager config
    config: PriceReporterManagerConfig,
}
impl PriceReporterManagerExecutor {
    /// Creates the executor for the PriceReporterManager worker.
    pub(super) fn new(
        system_bus: SystemBus<SystemBusMessage>,
        tokio_handle: Handle,
        config: PriceReporterManagerConfig,
    ) -> Result<Self, PriceReporterManagerError> {
        let spawned_price_reporters = HashMap::new();
        let registered_listeners = HashMap::new();
        Ok(Self {
            system_bus,
            tokio_handle,
            spawned_price_reporters,
            registered_listeners,
            config,
        })
    }

    /// Handles a job for the PriceReporterManager worker.
    pub(super) fn handle_job(
        &mut self,
        job: PriceReporterManagerJob,
    ) -> Result<(), PriceReporterManagerError> {
        match job {
            PriceReporterManagerJob::StartPriceReporter {
                base_token,
                quote_token,
                id,
                channel,
            } => self.start_price_reporter(base_token, quote_token, id, channel),
            PriceReporterManagerJob::DropListenerID {
                base_token,
                quote_token,
                id,
                channel,
            } => self.drop_listener_id(base_token, quote_token, id, channel),
            PriceReporterManagerJob::PeekMedian {
                base_token,
                quote_token,
                channel,
            } => self.peek_median(base_token, quote_token, channel),
            PriceReporterManagerJob::PeekAllExchanges {
                base_token,
                quote_token,
                channel,
            } => self.peek_all_exchanges(base_token, quote_token, channel),
            PriceReporterManagerJob::CreateNewMedianReceiver {
                base_token,
                quote_token,
                channel,
            } => self.create_new_median_receiver(base_token, quote_token, channel),
            PriceReporterManagerJob::GetSupportedExchanges {
                base_token,
                quote_token,
                channel,
            } => self.get_supported_exchanges(base_token, quote_token, channel),
            PriceReporterManagerJob::GetHealthyExchanges {
                base_token,
                quote_token,
                channel,
            } => self.get_healthy_exchanges(base_token, quote_token, channel),
        }
    }

    /// Internal helper function to get a (base_token, quote_token) PriceReporter
    fn get_price_reporter(
        &self,
        base_token: Token,
        quote_token: Token,
    ) -> Result<&PriceReporter, PriceReporterManagerError> {
        self.spawned_price_reporters
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
    fn get_price_reporter_or_create(
        &mut self,
        base_token: Token,
        quote_token: Token,
    ) -> Result<&PriceReporter, PriceReporterManagerError> {
        if self
            .spawned_price_reporters
            .get(&(base_token.clone(), quote_token.clone()))
            .is_none()
        {
            let (channel_sender, _channel_receiver) = channel::unbounded();
            self.start_price_reporter(
                base_token.clone(),
                quote_token.clone(),
                None,
                channel_sender,
            )?;
        }
        self.get_price_reporter(base_token, quote_token)
    }

    /// Handler for StartPriceReporter job.
    fn start_price_reporter(
        &mut self,
        base_token: Token,
        quote_token: Token,
        id: Option<PriceReporterListenerID>,
        channel: Sender<()>,
    ) -> Result<(), PriceReporterManagerError> {
        // If the PriceReporter does not already exist, create it
        let system_bus = self.system_bus.clone();
        let tokio_handle = self.tokio_handle.clone();
        let median_price_report_topic = format!(
            "median-price-report-{}-{}",
            base_token.get_addr(),
            quote_token.get_addr()
        );
        let config_clone = self.config.clone();
        self.spawned_price_reporters
            .entry((base_token.clone(), quote_token.clone()))
            .or_insert_with(|| {
                // Create the PriceReporter
                let price_reporter = PriceReporter::new(
                    base_token.clone(),
                    quote_token.clone(),
                    tokio_handle.clone(),
                    config_clone,
                );
                // Stream all median PriceReports to the system bus, only if the midpoint price
                // changes
                let mut median_receiver = price_reporter.create_new_median_receiver();
                let system_bus_clone = system_bus.clone();
                tokio_handle.spawn(async move {
                    let mut last_median_price_report = PriceReport::default();
                    loop {
                        let median_price_report = median_receiver.next().await.unwrap();
                        if median_price_report.midpoint_price
                            != last_median_price_report.midpoint_price
                        {
                            system_bus_clone.publish(
                                median_price_report_topic.clone(),
                                SystemBusMessage::PriceReportMedian(median_price_report.clone()),
                            );
                            last_median_price_report = median_price_report;
                        }
                    }
                });
                // Stream all individual Exchange PriceReports to the system bus, only if the
                // midpoint price changes
                for exchange in price_reporter.supported_exchanges.iter() {
                    let mut exchange_receiver =
                        price_reporter.create_new_exchange_receiver(*exchange);
                    let exchange_price_report_topic = format!(
                        "{}-price-report-{}-{}",
                        exchange,
                        base_token.get_addr(),
                        quote_token.get_addr()
                    );
                    let system_bus_clone = system_bus.clone();
                    tokio_handle.spawn(async move {
                        let mut last_price_report = PriceReport::default();
                        loop {
                            let price_report = exchange_receiver.next().await.unwrap();
                            if price_report.midpoint_price != last_price_report.midpoint_price {
                                system_bus_clone.publish(
                                    exchange_price_report_topic.clone(),
                                    SystemBusMessage::PriceReportExchange(price_report.clone()),
                                );
                                last_price_report = price_report;
                            }
                        }
                    });
                }
                price_reporter
            });

        // If there is no specified listener ID, we do not register any new IDs
        if id.is_none() {
            channel.send(()).unwrap();
            return Ok(());
        }

        // If the registered_listeners set does not already exist, create it
        self.registered_listeners
            .entry((base_token.clone(), quote_token.clone()))
            .or_insert_with(HashSet::new);

        // Register the new listener ID, asserting that it does not already exist
        let newly_inserted = self
            .registered_listeners
            .get_mut(&(base_token, quote_token))
            .unwrap()
            .insert(id.unwrap());
        if !newly_inserted {
            return Err(PriceReporterManagerError::AlreadyListening(
                id.unwrap().to_string(),
            ));
        }

        // Send a response that we have handled the job
        channel.send(()).unwrap();

        Ok(())
    }

    /// Handler for DropListenerID job.
    fn drop_listener_id(
        &mut self,
        base_token: Token,
        quote_token: Token,
        id: PriceReporterListenerID,
        channel: Sender<()>,
    ) -> Result<(), PriceReporterManagerError> {
        let was_present = self
            .registered_listeners
            .get_mut(&(base_token, quote_token))
            .ok_or_else(|| PriceReporterManagerError::ListenerNotFound(id.to_string()))?
            .remove(&id);

        // If the listener ID was not present, throw an error
        if !was_present {
            return Err(PriceReporterManagerError::ListenerNotFound(id.to_string()));
        }

        // Send a response that we have handled the job
        channel.send(()).unwrap();

        Ok(())
    }

    /// Handler for PeekMedian job.
    fn peek_median(
        &mut self,
        base_token: Token,
        quote_token: Token,
        channel: Sender<PriceReporterState>,
    ) -> Result<(), PriceReporterManagerError> {
        let price_reporter = self.get_price_reporter_or_create(base_token, quote_token)?;
        channel.send(price_reporter.peek_median()).unwrap();
        Ok(())
    }

    /// Handler for PeekAllExchanges job.
    fn peek_all_exchanges(
        &mut self,
        base_token: Token,
        quote_token: Token,
        channel: Sender<HashMap<Exchange, ExchangeConnectionState>>,
    ) -> Result<(), PriceReporterManagerError> {
        let price_reporter = self.get_price_reporter_or_create(base_token, quote_token)?;
        channel.send(price_reporter.peek_all_exchanges()).unwrap();
        Ok(())
    }

    /// Handler for CreateNewMedianReceiver job.
    fn create_new_median_receiver(
        &mut self,
        base_token: Token,
        quote_token: Token,
        channel: Sender<RingReceiver<PriceReport>>,
    ) -> Result<(), PriceReporterManagerError> {
        let price_reporter = self.get_price_reporter_or_create(base_token, quote_token)?;
        channel
            .send(price_reporter.create_new_median_receiver())
            .unwrap();
        Ok(())
    }

    /// Handler for GetSupportedExchanges job.
    fn get_supported_exchanges(
        &mut self,
        base_token: Token,
        quote_token: Token,
        channel: Sender<HashSet<Exchange>>,
    ) -> Result<(), PriceReporterManagerError> {
        let price_reporter = self.get_price_reporter_or_create(base_token, quote_token)?;
        channel
            .send(price_reporter.get_supported_exchanges())
            .unwrap();
        Ok(())
    }

    /// Handler for GetHealthyExchanges job.
    fn get_healthy_exchanges(
        &mut self,
        base_token: Token,
        quote_token: Token,
        channel: Sender<HashSet<Exchange>>,
    ) -> Result<(), PriceReporterManagerError> {
        let price_reporter = self.get_price_reporter_or_create(base_token, quote_token)?;
        channel
            .send(price_reporter.get_healthy_exchanges())
            .unwrap();
        Ok(())
    }
}
