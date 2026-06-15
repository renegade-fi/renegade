//! The matching engine module handles the execution of matching orders
//! a pair of orders to match, all the way through settling any resulting match

use std::collections::HashSet;

use alloy::primitives::Address;
use circuit_types::Amount;
use constants::in_bootstrap_mode;
use job_types::{
    matching_engine::{MatchingEngineWorkerJob, MatchingEngineWorkerReceiver},
    task_driver::TaskDriverQueue,
};
use matching_engine_core::MatchingEngine;
use price_state::PriceStreamStates;
use renegade_metrics::{record_matching_engine_job_finished, record_matching_engine_job_started};
use state::State;
use std::time::Duration;
use system_bus::{SystemBus, SystemBusMessage};
use tracing::{Instrument, info_span, instrument};
use util::get_current_time_millis;
use util::log_task;
use util::logging::Outcome;

use crate::logging::Task;
use types_runtime::CancelChannel;
use util::{DefaultOption, channels::TracedMessage, concurrency::runtime::sleep_forever_async};

use crate::error::MatchingEngineError;

// -------------
// | Constants |
// -------------

/// The number of threads executing matching engine jobs
pub(super) const MATCHING_ENGINE_EXECUTOR_N_THREADS: usize = 8;

/// The per-job timeout for a matching engine job
///
/// Must be strictly less than the api-server's 30s wait on the response topic
/// so that a stuck job returns a clean no-match response to the caller rather
/// than a 30s hang followed by a catch-all 500.
const MATCHING_ENGINE_JOB_TIMEOUT: Duration = Duration::from_secs(25);

/// The threshold above which a matching engine job is logged as slow
///
/// Diagnostic only: surfaces jobs that run long but have not yet timed out, so
/// a wedging engine is visible before it crosses the hard timeout.
const MATCHING_ENGINE_SLOW_JOB_THRESHOLD: Duration = Duration::from_secs(10);

/// RAII guard that records job-finished metrics (decrements the in-flight gauge
/// and records duration) on drop, so the metrics are emitted even if the job
/// panics while executing.
struct JobMetricsGuard {
    /// The time at which the job started, in milliseconds since the epoch
    started_ms: u64,
}

impl Drop for JobMetricsGuard {
    fn drop(&mut self) {
        let elapsed_ms = get_current_time_millis().saturating_sub(self.started_ms);
        record_matching_engine_job_finished(elapsed_ms as f64);
    }
}

// ----------------------------
// | Matching Engine Executor |
// ----------------------------

/// Manages the threaded execution of the matching engine
#[derive(Clone)]
pub struct MatchingEngineExecutor {
    /// The minimum amount of the quote asset that the relayer should settle
    /// matches on
    pub(crate) min_fill_size: Amount,
    /// The number of blocks an external match bundle remains valid
    pub(crate) external_match_validity_window: u64,
    /// Assets for which matching is disabled
    pub(crate) disabled_assets: HashSet<Address>,
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
        external_match_validity_window: u64,
        disabled_assets: HashSet<Address>,
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
            external_match_validity_window,
            disabled_assets,
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
                    // Track engine saturation: sample the channel length and mark the job
                    // in-flight before spawning. Jobs are spawned as async tasks onto this
                    // runtime's worker threads, so a wedge manifests as in-flight jobs piling
                    // up and long job durations rather than channel backlog.
                    record_matching_engine_job_started(job_channel.len());
                    let started_ms = get_current_time_millis();
                    let self_clone = self.clone();

                    // Peek the external response topic (if any) before consuming the job, so
                    // that on a per-job timeout we can publish a clean no-match response to the
                    // waiting caller instead of letting it hang for the full api-server timeout.
                    let response_topic = match &job.message {
                        MatchingEngineWorkerJob::ExternalMatchingEngine { response_topic, .. } => {
                            Some(response_topic.clone())
                        },
                        MatchingEngineWorkerJob::InternalMatchingEngine { .. } => None,
                    };
                    let system_bus = self.system_bus.clone();

                    tokio::task::spawn(async move {
                        // Record job-finished metrics on drop so the in-flight gauge is
                        // decremented and the duration is recorded even if the job panics.
                        let _metrics_guard = JobMetricsGuard { started_ms };

                        // Bound the job execution. A stuck job (e.g. a wedged downstream
                        // dependency) otherwise pins a worker-thread slot indefinitely and the
                        // external-match caller waits the full 30s before a catch-all 500.
                        match tokio::time::timeout(MATCHING_ENGINE_JOB_TIMEOUT, self_clone.handle_job(job)).await {
                            Ok(Ok(())) => {},
                            Ok(Err(e)) => {
                                log_task!(Task::RunMatchingEngine, Outcome::Failed, error = %e, "error executing matching engine job");
                            },
                            Err(_elapsed) => {
                                let elapsed_ms = get_current_time_millis().saturating_sub(started_ms);
                                log_task!(
                                    Task::RunMatchingEngine,
                                    Outcome::Failed,
                                    timeout_ms = MATCHING_ENGINE_JOB_TIMEOUT.as_millis() as u64,
                                    elapsed_ms = elapsed_ms,
                                    "matching-engine job timed out"
                                );
                                // Unblock the waiting external-match caller with a clean no-match
                                // response. Publish is a no-op for internal jobs (no topic).
                                if let Some(topic) = response_topic {
                                    system_bus.publish(topic, SystemBusMessage::NoExternalMatchFound);
                                }
                            },
                        }
                        let elapsed_ms = get_current_time_millis().saturating_sub(started_ms);
                        if elapsed_ms >= MATCHING_ENGINE_SLOW_JOB_THRESHOLD.as_millis() as u64 {
                            log_task!(
                                Task::RunMatchingEngine,
                                Outcome::Skipped,
                                elapsed_ms = elapsed_ms,
                                threshold_ms = MATCHING_ENGINE_SLOW_JOB_THRESHOLD.as_millis() as u64,
                                "matching-engine job exceeded slow-job threshold"
                            );
                        }
                    }.instrument(info_span!("handle_matching_engine_job")));
                },

                // Await cancellation by the coordinator
                _ = self.cancel.changed() => {
                    log_task!(Task::RunMatchingEngine, Outcome::Skipped, "matching engine manager received cancel signal, shutting down");
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
            MatchingEngineWorkerJob::InternalMatchingEngine { account_id, order } => {
                self.run_internal_matching_engine(account_id, order).await
            },

            // A request to run the external matching engine
            MatchingEngineWorkerJob::ExternalMatchingEngine { order, response_topic, options } => {
                self.run_external_matching_engine(order, response_topic, options).await
            },
        }
    }
}
