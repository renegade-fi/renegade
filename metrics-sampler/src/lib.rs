//! Metrics registered with timers on the system clock that record various
//! "snapshots" of the system on an interval.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![deny(clippy::missing_docs_in_private_items)]
#![allow(async_fn_in_trait)]

use churn_metrics_sampler::CancellationMetricsSampler;
use onboarding_metrics_sampler::OnboardingMetricsSampler;
use price_state::PriceStreamStates;
use raft_metrics_sampler::RaftMetricsSampler;
use sampler::{AsyncMetricSampler, MetricSampler};
use state::State;
use system_clock::{SystemClock, SystemClockError};
use util::err_str;

pub mod churn_metrics_sampler;
pub mod onboarding_metrics_sampler;
pub mod raft_metrics_sampler;
pub mod sampler;

/// Registers all the metrics samplers with the system clock.
pub async fn setup_metrics_samplers(
    state: State,
    system_clock: &SystemClock,
    price_streams: PriceStreamStates,
) -> Result<(), SystemClockError> {
    RaftMetricsSampler::new(state.clone()).register(system_clock).await?;
    if state.historical_state_enabled().await.map_err(err_str!(SystemClockError))? {
        OnboardingMetricsSampler::new(state.clone()).register(system_clock).await?;
        CancellationMetricsSampler::new(state, price_streams).register(system_clock).await?;
    }

    Ok(())
}
