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

// Task metrics

/// Metric describing the number of in-flight tasks
pub const NUM_INFLIGHT_TASKS_METRIC: &str = "num_inflight_tasks";
/// Metric describing the number of tasks completed
pub const NUM_COMPLETED_TASKS_METRIC: &str = "num_completed_tasks";

// Event metrics

/// Metric describing the number of events failed to be sent to the event
/// manager
pub const NUM_EVENT_SEND_FAILURES_METRIC: &str = "num_event_send_failures";
/// Metric describing the number of events failed to be exported from the event
/// manager
pub const NUM_EVENT_EXPORT_FAILURES_METRIC: &str = "num_event_export_failures";

// ---------------
// | METRIC TAGS |
// ---------------

/// Metric tag for the asset of a deposit/withdrawal
pub const ASSET_METRIC_TAG: &str = "asset";
/// Metric tag for whether a match is external
pub const EXTERNAL_MATCH_METRIC_TAG: &str = "is_external_match";
/// Metric tag for the wallet ID of the first wallet in a match
pub const WALLET_ID1_METRIC_TAG: &str = "wallet_id1";
/// Metric tag for the wallet ID of the second wallet in a match
pub const WALLET_ID2_METRIC_TAG: &str = "wallet_id2";
