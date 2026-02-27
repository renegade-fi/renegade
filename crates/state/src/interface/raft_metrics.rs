//! Periodic raft metrics sampling for state.

use std::time::Duration;

use system_clock::SystemClock;

use crate::{StateInner, error::StateError};

/// The frequency with which to sample raft cluster metrics.
const RAFT_METRICS_SAMPLE_INTERVAL_MS: u64 = 10_000; // 10 seconds
/// Metric describing the size of the raft cluster.
const RAFT_CLUSTER_SIZE_METRIC: &str = "raft_cluster_size";
/// Metric describing whether the local node is raft leader.
const RAFT_LEADER_METRIC: &str = "raft_leader";

impl StateInner {
    /// Periodically samples raft state and emits gauge metrics.
    pub(super) async fn setup_raft_metrics_timer(
        &self,
        clock: &SystemClock,
    ) -> Result<(), StateError> {
        let duration = Duration::from_millis(RAFT_METRICS_SAMPLE_INTERVAL_MS);
        let name = "raft-metrics-sampler-loop".to_string();
        let this = self.clone();

        clock
            .add_async_timer(name, duration, move || {
                let this = this.clone();
                async move {
                    let cluster_size = this.cluster_size();
                    let is_leader = if this.is_leader() { 1.0 } else { 0.0 };

                    metrics::gauge!(RAFT_CLUSTER_SIZE_METRIC).set(cluster_size as f64);
                    metrics::gauge!(RAFT_LEADER_METRIC).set(is_leader);
                    Ok(())
                }
            })
            .await
            .map_err(StateError::Clock)
    }
}
