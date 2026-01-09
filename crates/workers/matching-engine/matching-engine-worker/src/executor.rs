//! The matching engine module handles the execution of matching orders
//! a pair of orders to match, all the way through settling any resulting match

use circuit_types::Amount;
use constants::in_bootstrap_mode;
use job_types::{
    matching_engine::{MatchingEngineWorkerJob, MatchingEngineWorkerReceiver},
    task_driver::TaskDriverQueue,
};
use matching_engine_core::MatchingEngine;
use price_state::PriceStreamStates;
use state::State;
use system_bus::SystemBus;
use tracing::{Instrument, error, info, info_span, instrument};
use types_account::{account::OrderId, pair::Pair};
use types_runtime::CancelChannel;
use util::{DefaultOption, channels::TracedMessage, concurrency::runtime::sleep_forever_async};

use crate::error::MatchingEngineError;

// -------------
// | Constants |
// -------------

/// The number of threads executing matching engine jobs
pub(super) const MATCHING_ENGINE_EXECUTOR_N_THREADS: usize = 8;

// ----------------------------
// | Matching Engine Executor |
// ----------------------------

/// Manages the threaded execution of the matching engine
#[derive(Clone)]
pub struct MatchingEngineExecutor {
    /// The minimum amount of the quote asset that the relayer should settle
    /// matches on
    pub(crate) min_fill_size: Amount,
    /// The channel on which other workers enqueue jobs for the protocol
    /// executor
    pub(crate) job_channel: DefaultOption<MatchingEngineWorkerReceiver>,
    /// The price streams from the price reporter
    pub(crate) price_streams: PriceStreamStates,
    /// The global relayer state
    pub(crate) state: State,
    /// The matching engine instance
    pub(crate) matching_engine: MatchingEngine,
    /// The queue used to send tasks to the task driver
    pub(crate) task_queue: TaskDriverQueue,
    /// The system bus used to publish internal broadcast messages
    pub(crate) system_bus: SystemBus,
    /// The channel on which the coordinator thread may cancel matching engine
    /// execution
    pub(crate) cancel: CancelChannel,
}

impl MatchingEngineExecutor {
    /// Create a new protocol executor
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        min_fill_size: Amount,
        job_channel: MatchingEngineWorkerReceiver,
        price_streams: PriceStreamStates,
        state: State,
        matching_engine: MatchingEngine,
        task_queue: TaskDriverQueue,
        system_bus: SystemBus,
        cancel: CancelChannel,
    ) -> Result<Self, MatchingEngineError> {
        Ok(Self {
            min_fill_size,
            job_channel: DefaultOption::new(Some(job_channel)),
            price_streams,
            state,
            matching_engine,
            task_queue,
            system_bus,
            cancel,
        })
    }

    /// The main loop: dequeues jobs and forwards them to the thread pool
    pub async fn execution_loop(mut self) -> MatchingEngineError {
        // If the node is running in bootstrap mode, sleep forever
        if in_bootstrap_mode() {
            sleep_forever_async().await;
        }

        let mut job_channel = self.job_channel.take().unwrap();

        loop {
            // Await the next job from the scheduler or elsewhere
            tokio::select! {
                Some(job) = job_channel.recv() => {
                    let self_clone = self.clone();
                    tokio::task::spawn(async move {
                        if let Err(e) = self_clone.handle_job(job).await {
                            error!("error executing matching engine job: {e}")
                        }
                    }.instrument(info_span!("handle_matching_engine_job")));
                },

                // Await cancellation by the coordinator
                _ = self.cancel.changed() => {
                    info!("Matching engine manager received cancel signal, shutting down...");
                    return MatchingEngineError::Cancelled("received cancel signal".to_string());
                }
            }
        }
    }
}

/// Main event handler implementations; each of these methods are run inside the
/// threadpool
impl MatchingEngineExecutor {
    /// Handle a matching engine job
    #[instrument(name = "handle_handshake_job", skip_all)]
    pub async fn handle_job(
        &self,
        job: TracedMessage<MatchingEngineWorkerJob>,
    ) -> Result<(), MatchingEngineError> {
        match job.consume() {
            // An order has been updated, the executor should run the internal engine on the
            // new order to check for matches
            MatchingEngineWorkerJob::InternalMatchingEngine { order } => {
                todo!()
                // self.run_internal_matching_engine(order).await
            },

            // A request to run the external matching engine
            MatchingEngineWorkerJob::ExternalMatchingEngine { order, response_topic, options } => {
                todo!()
                // self.run_external_matching_engine(order, response_topic,
                // options).await
            },
        }
    }

    // -----------
    // | Helpers |
    // -----------

    /// Converts the token pair of the given order to one that price
    /// data can be found for
    ///
    /// This involves both converting the address into an Eth mainnet analog
    /// and casting this to a `Token`
    async fn token_pair_for_order(&self, order_id: &OrderId) -> Result<Pair, MatchingEngineError> {
        let order = self
            .state
            .get_managed_order(order_id)
            .await?
            .ok_or_else(|| MatchingEngineError::state(format!("order_id: {order_id:?}")))?;

        Ok(order.pair())
    }
}
