use crossbeam::channel::Sender;
use ring_channel::RingReceiver;
use std::{
    collections::{HashMap, HashSet},
    thread::JoinHandle,
};
use uuid::Uuid;

use super::{
    errors::PriceReporterManagerError,
    exchanges::Exchange,
    jobs::PriceReporterManagerJob,
    reporter::{PriceReport, PriceReporter, PriceReporterState},
    tokens::Token,
    worker::PriceReporterManagerConfig,
};

pub type PriceReporterListenerID = Uuid;

/// The PriceReporterManager worker is a wrapper around the PriceReporterManagerExecutor, handling
/// and dispatching jobs to the executor for spin-up and shut-down of individual PriceReporters.
pub struct PriceReporterManager {
    /// The config for the PriceReporterManager
    pub(super) config: PriceReporterManagerConfig,
    /// The single thread that joins all individual PriceReporter threads
    pub(super) manager_executor_handle: Option<JoinHandle<PriceReporterManagerError>>,
}

/// The actual executor that handles incoming jobs, to create and destroy PriceReporters, and peek
/// at PriceReports.
pub struct PriceReporterManagerExecutor {
    /// The map between base/quote token pairs and the instantiated PriceReporter
    pub(super) spawned_price_reporters: HashMap<(Token, Token), PriceReporter>,
    /// The map between base/quote token pairs and the set of registered listeners
    pub(super) registered_listeners: HashMap<(Token, Token), HashSet<PriceReporterListenerID>>,
}
impl PriceReporterManagerExecutor {
    pub(super) fn new() -> Result<Self, PriceReporterManagerError> {
        let spawned_price_reporters = HashMap::new();
        let registered_listeners = HashMap::new();
        Ok(Self {
            spawned_price_reporters,
            registered_listeners,
        })
    }

    pub(super) fn handle_job(
        &self,
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

    fn start_price_reporter(
        &self,
        base_token: Token,
        quote_token: Token,
        id: Option<PriceReporterListenerID>,
        channel: Sender<()>,
    ) -> Result<(), PriceReporterManagerError> {
        unimplemented!();
    }

    fn drop_listener_id(
        &self,
        base_token: Token,
        quote_token: Token,
        id: PriceReporterListenerID,
        channel: Sender<()>,
    ) -> Result<(), PriceReporterManagerError> {
        unimplemented!();
    }

    fn peek_median(
        &self,
        base_token: Token,
        quote_token: Token,
        channel: Sender<PriceReporterState>,
    ) -> Result<(), PriceReporterManagerError> {
        unimplemented!();
    }

    fn create_new_median_receiver(
        &self,
        base_token: Token,
        quote_token: Token,
        channel: Sender<RingReceiver<PriceReport>>,
    ) -> Result<(), PriceReporterManagerError> {
        unimplemented!();
    }

    fn get_supported_exchanges(
        &self,
        base_token: Token,
        quote_token: Token,
        channel: Sender<HashSet<Exchange>>,
    ) -> Result<(), PriceReporterManagerError> {
        unimplemented!();
    }

    fn get_healthy_exchanges(
        &self,
        base_token: Token,
        quote_token: Token,
        channel: Sender<HashSet<Exchange>>,
    ) -> Result<(), PriceReporterManagerError> {
        unimplemented!();
    }
}
