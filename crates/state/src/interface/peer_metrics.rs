//! Periodic peer metrics sampling for state.

use std::time::Duration;

use renegade_metrics::labels::{NUM_LOCAL_PEERS_METRIC, NUM_REMOTE_PEERS_METRIC};
use system_clock::SystemClock;

use crate::{StateInner, error::StateError};

/// The frequency with which to sample peer metrics.
const PEER_METRICS_SAMPLE_INTERVAL_MS: u64 = 10_000; // 10 seconds

impl StateInner {
    /// Periodically samples peer index state and emits gauge metrics for the
    /// number of local (in-cluster) and remote (non-cluster) peers.
    pub(super) async fn setup_peer_metrics_timer(
        &self,
        clock: &SystemClock,
    ) -> Result<(), StateError> {
        let duration = Duration::from_millis(PEER_METRICS_SAMPLE_INTERVAL_MS);
        let name = "peer-metrics-sampler-loop".to_string();
        let this = self.clone();

        clock
            .add_async_timer(name, duration, move || {
                let this = this.clone();
                async move {
                    let cluster_id =
                        this.get_cluster_id().map_err(|e| format!("get_cluster_id: {e}"))?;
                    let num_local_peers = this
                        .get_cluster_peers(&cluster_id)
                        .await
                        .map_err(|e| format!("get_cluster_peers: {e}"))?
                        .len();
                    let num_remote_peers = this
                        .get_non_cluster_peers(&cluster_id)
                        .await
                        .map_err(|e| format!("get_non_cluster_peers: {e}"))?
                        .len();

                    metrics::gauge!(NUM_LOCAL_PEERS_METRIC).set(num_local_peers as f64);
                    metrics::gauge!(NUM_REMOTE_PEERS_METRIC).set(num_remote_peers as f64);
                    Ok(())
                }
            })
            .await
            .map_err(StateError::Clock)
    }
}
