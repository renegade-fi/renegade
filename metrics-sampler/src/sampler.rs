//! Defines a "sampler" trait that encapsulates the logic for registering
//! a job that samples metrics at a fixed interval

use std::{future::Future, time::Duration};
use system_clock::{SystemClock, SystemClockError};

/// Samples metrics at a fixed interval, using a synchronous sampling method
pub trait MetricSampler: Sized + Send + Sync + 'static {
    /// Returns the name of the sampler
    fn name(&self) -> &str;

    /// Returns the duration between recording samples
    fn interval(&self) -> Duration;

    /// Samples the metrics
    fn sample(&self) -> Result<(), String>;

    /// Registers the sampler with the system clock
    async fn register(self, clock: &SystemClock) -> Result<(), SystemClockError> {
        let name = self.name().to_string();
        let interval = self.interval();
        let sample = move || self.sample();

        clock.add_timer(name, interval, sample).await
    }
}

/// Samples metrics at a fixed interval, using an asynchronous sampling method
pub trait AsyncMetricSampler: Sized + Send + Sync + 'static + Clone {
    /// Returns the name of the sampler
    fn name(&self) -> &str;

    /// Returns the duration between recording samples
    fn interval(&self) -> Duration;

    /// Samples the metrics
    fn sample(&self) -> impl Future<Output = Result<(), String>> + Send;

    /// Registers the sampler with the system clock
    async fn register(self, clock: &SystemClock) -> Result<(), SystemClockError> {
        let name = self.name().to_string();
        let interval = self.interval();
        let sample = move || {
            let sampler = self.clone();

            async move { sampler.sample().await }
        };

        clock.add_async_timer(name, interval, sample).await
    }
}
