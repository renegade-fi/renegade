//! Records raft metrics snapshots at a fixed interval

use std::time::Duration;

use state::State;

use crate::sampler::MetricSampler;

/// The name of the sampler for raft metrics
pub const RAFT_METRICS_SAMPLER_NAME: &str = "raft-metrics-sampler";
/// The interval at which to sample raft metrics
pub const RAFT_METRICS_SAMPLE_INTERVAL_MS: u64 = 10_000;

/// Metric describing the size of the raft cluster
pub const RAFT_CLUSTER_SIZE_METRIC: &str = "raft_cluster_size";
/// Metric describing if the local node is the leader of the raft cluster
pub const RAFT_LEADER_METRIC: &str = "raft_leader";

/// Samples raft metrics at a fixed interval
pub struct RaftMetricsSampler {
    /// A handle to the global state
    state: State,
}

impl RaftMetricsSampler {
    /// Create a new `RaftMetricsSampler`
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

impl MetricSampler for RaftMetricsSampler {
    fn name(&self) -> &str {
        RAFT_METRICS_SAMPLER_NAME
    }

    fn interval(&self) -> Duration {
        Duration::from_millis(RAFT_METRICS_SAMPLE_INTERVAL_MS)
    }

    fn sample(&self) -> Result<(), String> {
        let raft_cluster_size = self.state.cluster_size();
        let is_leader = if self.state.is_leader() { 1 } else { 0 };

        metrics::gauge!(RAFT_CLUSTER_SIZE_METRIC).set(raft_cluster_size as f64);
        metrics::gauge!(RAFT_LEADER_METRIC).set(is_leader as f64);

        Ok(())
    }
}
