//! Samples onboarding-related metrics at a fixed interval

use std::time::Duration;

use common::types::{
    tasks::{HistoricalTaskDescription, WalletUpdateType},
    wallet::{Wallet, WalletIdentifier},
};
use state::State;

use crate::sampler::AsyncMetricSampler;

/// The name of the sampler for onboarding metrics
const ONBOARDING_METRICS_SAMPLER_NAME: &str = "onboarding-metrics-sampler";
/// The interval at which to sample onboarding metrics
const ONBOARDING_METRICS_SAMPLE_INTERVAL_MS: u64 = 3_600_000; // 1 hour

/// Metric describing the number of wallets
const NUM_WALLETS_METRIC: &str = "num_wallets";
/// Metric describing the number of wallets with at least one deposit
const NUM_WALLETS_WITH_DEPOSITS_METRIC: &str = "num_wallets_with_deposits";
/// Metric describing the number of wallets with at least one order placement
const NUM_WALLETS_WITH_ORDERS_METRIC: &str = "num_wallets_with_orders";
/// Metric describing the number of wallets with at least one match
const NUM_WALLETS_WITH_MATCHES_METRIC: &str = "num_wallets_with_matches";

/// Samples onboarding metrics at a fixed interval
#[derive(Clone)]
pub struct OnboardingMetricsSampler {
    /// A handle to the global state
    state: State,
}

impl OnboardingMetricsSampler {
    /// Create a new `OnboardingMetricsSampler`
    pub fn new(state: State) -> Self {
        Self { state }
    }

    // -------------------
    // | Private Helpers |
    // -------------------

    /// Processes the onboarding progress of a given wallet
    async fn process_wallet_onboarding_progress(
        &self,
        wallet: Wallet,
    ) -> Result<(bool, bool, bool), String> {
        // Short-circuit state queries for task history by checking if the wallet has
        // outstanding fees. This implies that the wallet has experienced at
        // least one match, which itself implies that that the wallet has
        // had deposits and orders.
        if wallet.has_outstanding_fees() {
            Ok((
                true, // has_deposited
                true, // has_placed_order
                true, // has_matched
            ))
        } else {
            // If the wallet does not have outstanding fees, we must query
            // its task history to see if it has deposited /
            // placed an order / matched.
            self.scan_tasks_for_onboarding_progress(&wallet.wallet_id).await
        }
    }

    /// Scans the task history of a given wallet to determine its onboarding
    /// progress
    async fn scan_tasks_for_onboarding_progress(
        &self,
        wallet_id: &WalletIdentifier,
    ) -> Result<(bool, bool, bool), String> {
        let mut has_deposited = false;
        let mut has_placed_order = false;
        let mut has_matched = false;

        // We fetch only the last 50 tasks for the wallet. This should be
        // a sufficient sample to determine the wallet's onboarding state.
        let tasks = self.state.get_task_history(50, wallet_id).await?;

        for task in tasks {
            match task.task_info {
                HistoricalTaskDescription::UpdateWallet(WalletUpdateType::Deposit { .. }) => {
                    has_deposited = true;
                },
                HistoricalTaskDescription::UpdateWallet(WalletUpdateType::PlaceOrder {
                    ..
                })
                | HistoricalTaskDescription::UpdateWallet(WalletUpdateType::CancelOrder {
                    ..
                }) => {
                    has_placed_order = true;
                },
                HistoricalTaskDescription::SettleMatch(_) => {
                    has_matched = true;
                },
                _ => {},
            }

            // If the wallet has deposited, placed an order, and matched, we can
            // break early
            if has_deposited && has_placed_order && has_matched {
                break;
            }
        }

        Ok((has_deposited, has_placed_order, has_matched))
    }
}

impl AsyncMetricSampler for OnboardingMetricsSampler {
    fn name(&self) -> &str {
        ONBOARDING_METRICS_SAMPLER_NAME
    }

    fn interval(&self) -> Duration {
        Duration::from_millis(ONBOARDING_METRICS_SAMPLE_INTERVAL_MS)
    }

    async fn sample(&self) -> Result<(), String> {
        // Only sample on the leader to avoid duplicate metrics
        if !self.state.is_leader() {
            return Ok(());
        }

        let wallets = self.state.get_all_wallets().await?;
        let num_wallets = wallets.len();

        let mut num_wallets_with_deposits = 0;
        let mut num_wallets_with_orders = 0;
        let mut num_wallets_with_matches = 0;

        for wallet in wallets {
            let (has_deposited, has_placed_order, has_matched) =
                self.process_wallet_onboarding_progress(wallet).await?;

            if has_deposited {
                num_wallets_with_deposits += 1;
            }
            if has_placed_order {
                num_wallets_with_orders += 1;
            }
            if has_matched {
                num_wallets_with_matches += 1;
            }
        }

        metrics::gauge!(NUM_WALLETS_METRIC).set(num_wallets as f64);
        metrics::gauge!(NUM_WALLETS_WITH_DEPOSITS_METRIC).set(num_wallets_with_deposits as f64);
        metrics::gauge!(NUM_WALLETS_WITH_ORDERS_METRIC).set(num_wallets_with_orders as f64);
        metrics::gauge!(NUM_WALLETS_WITH_MATCHES_METRIC).set(num_wallets_with_matches as f64);

        Ok(())
    }
}
