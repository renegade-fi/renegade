//! Helpers for tracking peer metrics

use renegade_metrics::labels::{NUM_LOCAL_PEERS_METRIC, NUM_REMOTE_PEERS_METRIC};
use state::{State, error::StateError};
use tracing::error;

/// Get the number of local and remote peers the cluster is connected to
async fn get_num_peers(state: &State) -> Result<(usize, usize), StateError> {
    let cluster_id = state.get_cluster_id()?;
    let num_local_peers = state.get_cluster_peers(&cluster_id).await?.len();
    let num_remote_peers = state.get_non_cluster_peers(&cluster_id).await?.len();

    Ok((num_local_peers, num_remote_peers))
}

/// Record the number of local and remote peers the cluster is connected to
pub async fn record_num_peers_metrics(state: &State) {
    let (num_local_peers, num_remote_peers) = match get_num_peers(state).await {
        Ok(peers) => peers,
        Err(e) => {
            error!("Error getting number of peers: {}", e);
            return;
        },
    };

    metrics::gauge!(NUM_LOCAL_PEERS_METRIC).set(num_local_peers as f64);
    metrics::gauge!(NUM_REMOTE_PEERS_METRIC).set(num_remote_peers as f64);
}
