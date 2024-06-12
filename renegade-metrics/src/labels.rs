//! Metric names and tags

// ----------------
// | METRIC NAMES |
// ----------------

// Trading metrics

/// Metric describing the number of new wallets created
pub const NUM_NEW_WALLETS_METRIC: &str = "num_new_wallets";
/// Metric describing the number of deposits made
pub const NUM_DEPOSITS_METRICS: &str = "num_deposits";
/// Metric describing the volume of deposits made
pub const DEPOSIT_VOLUME_METRIC: &str = "deposit_volume";
/// Metric describing the number of withdrawals made
pub const NUM_WITHDRAWALS_METRICS: &str = "num_withdrawals";
/// Metric describing the volume of withdrawals made
pub const WITHDRAWAL_VOLUME_METRIC: &str = "withdrawal_volume";
/// Metric describing the volume of the base asset in a match
pub const MATCH_BASE_VOLUME_METRIC: &str = "match_base_volume";
/// Metric describing the volume of the quote asset in a match
pub const MATCH_QUOTE_VOLUME_METRIC: &str = "match_quote_volume";
/// Metric describing the total fees collected by asset
pub const FEES_COLLECTED_METRIC: &str = "fees_collected";

// P2P metrics

/// Metric describing the number of local peers the relayer
/// is connected to
pub const NUM_LOCAL_PEERS_METRIC: &str = "num_local_peers";
/// Metric describing the number of remote peers the relayer
/// is connected to
pub const NUM_REMOTE_PEERS_METRIC: &str = "num_remote_peers";
/// Metric describing the size of the raft cluster
pub const RAFT_CLUSTER_SIZE_METRIC: &str = "raft_cluster_size";

// Task metrics

/// Metric describing the number of in-flight tasks
pub const NUM_INFLIGHT_TASKS_METRIC: &str = "num_inflight_tasks";
/// Metric describing the number of tasks completed
pub const NUM_COMPLETED_TASKS_METRIC: &str = "num_completed_tasks";

// Proof metrics

/// Metric describing the number of in-flight proofs
pub const NUM_INFLIGHT_PROOFS_METRIC: &str = "num_inflight_proofs";

// Transaction metrics

/// Metric describing the number of in-flight Arbitrum transactions
pub const NUM_INFLIGHT_TXS_METRIC: &str = "num_inflight_txs";

// ---------------
// | METRIC TAGS |
// ---------------

/// Metric tag for the asset of a deposit/withdrawal
pub const ASSET_METRIC_TAG: &str = "asset";
