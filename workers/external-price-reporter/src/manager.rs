//! Defines the ExternalPriceReporterExecutor, the handler that is responsible
//! for executing individual ExternalPriceReporterJobs.

use std::{collections::HashSet, thread::JoinHandle};

use common::{
    default_wrapper::{DefaultOption, DefaultWrapper},
    new_async_shared,
    types::CancelChannel,
    AsyncShared,
};
use job_types::price_reporter::PriceReporterReceiver;

use crate::{errors::ExternalPriceReporterError, worker::ExternalPriceReporterConfig};

/// The ExternalPriceReporter worker is a wrapper around the
/// ExternalPriceReporterExecutor, handling and dispatching jobs to the executor
/// for subscription to price streams and peeking at price reports.
pub struct ExternalPriceReporter {
    /// The config for the ExternalPriceReporter
    pub(super) config: ExternalPriceReporterConfig,
    /// The single thread that joins all individual PriceReporter threads
    pub(super) manager_executor_handle: Option<JoinHandle<ExternalPriceReporterError>>,
}

/// The actual executor that handles incoming jobs, to subscribe to price
/// streams and peek at PriceReports
#[derive(Clone)]
pub struct ExternalPriceReporterExecutor {
    /// The manager config
    config: ExternalPriceReporterConfig,
    /// The set of topics that the executor is subscribed to
    /// on the external price reporter service
    subscriptions: AsyncShared<HashSet<String>>,
    /// The channel along which jobs are passed to the price reporter
    job_receiver: DefaultOption<PriceReporterReceiver>,
    /// The channel on which the coordinator may cancel execution
    cancel_channel: DefaultOption<CancelChannel>,
}

impl ExternalPriceReporterExecutor {
    /// Creates the executor for the ExternalPriceReporter worker.
    pub(super) fn new(
        job_receiver: PriceReporterReceiver,
        config: ExternalPriceReporterConfig,
        cancel_channel: CancelChannel,
    ) -> Self {
        Self {
            job_receiver: DefaultWrapper::new(Some(job_receiver)),
            cancel_channel: DefaultWrapper::new(Some(cancel_channel)),
            subscriptions: new_async_shared(HashSet::new()),
            config,
        }
    }

    /// The execution loop for the external price reporter
    pub(super) async fn execution_loop(mut self) -> Result<(), ExternalPriceReporterError> {
        todo!()
    }
}
