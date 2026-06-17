//! Static metric instances that can be accessed from anywhere in the codebase

use lazy_static::lazy_static;

use crate::{
    gauge::Gauge,
    labels::{MATCHING_ENGINE_INFLIGHT_JOBS_METRIC, NUM_INFLIGHT_TASKS_METRIC},
};

lazy_static! {
    /// In-flight tasks gauge
    pub static ref IN_FLIGHT_TASKS: Gauge = Gauge::new(NUM_INFLIGHT_TASKS_METRIC.to_string(), vec![] /* tags */);

    /// Matching engine in-flight jobs gauge.
    ///
    /// Backed by the atomic [`Gauge`] wrapper rather than a raw
    /// `metrics::gauge!(...).increment()` because the StatsD exporter does not
    /// emit gauge increment/decrement deltas, only absolute `.set()` values.
    pub static ref MATCHING_ENGINE_INFLIGHT_JOBS: Gauge = Gauge::new(MATCHING_ENGINE_INFLIGHT_JOBS_METRIC.to_string(), vec![] /* tags */);
}
