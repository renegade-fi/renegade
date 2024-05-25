//! Static metric instances that can be accessed from anywhere in the codebase

use lazy_static::lazy_static;

use crate::{
    gauge::Gauge,
    labels::{NUM_INFLIGHT_PROOFS_METRIC, NUM_INFLIGHT_TASKS_METRIC, NUM_INFLIGHT_TXS_METRIC},
};

lazy_static! {
    /// In-flight tasks gauge
    pub static ref IN_FLIGHT_TASKS: Gauge = Gauge::new(NUM_INFLIGHT_TASKS_METRIC.to_string(), vec![] /* tags */);

    /// In-flight proofs gauge
    pub static ref IN_FLIGHT_PROOFS: Gauge = Gauge::new(NUM_INFLIGHT_PROOFS_METRIC.to_string(), vec![] /* tags */);

    /// In-flight Arbitrum transactions gauge
    pub static ref IN_FLIGHT_ARBITRUM_TXS: Gauge = Gauge::new(NUM_INFLIGHT_TXS_METRIC.to_string(), vec![] /* tags */);
}
