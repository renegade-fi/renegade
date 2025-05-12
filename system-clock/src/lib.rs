//! A system clock that workers may use to enqueue periodic jobs
//!
//! Currently this implementation does not allow sub-second precision, as the
//! underlying implementation does not support it. If we determine a need for
//! sub-second precision we can implement a more custom clock implementation

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(unsafe_code)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![feature(inherent_associated_types)]

use std::{future::Future, time::Duration};

use tokio_cron_scheduler::{Job, JobScheduler};
use tracing::error;
use util::err_str;

/// The error type returned by the clock
#[derive(Debug, Clone)]
pub struct SystemClockError(pub String);

/// The system clock allows workers to schedule periodic notifications delivered
/// to a callback of choice
#[derive(Clone)]
pub struct SystemClock {
    /// The underlying timer
    scheduler: JobScheduler,
}

impl SystemClock {
    /// Create a new system clock
    pub async fn new() -> Self {
        let scheduler = JobScheduler::new().await.expect("could not build system clock");
        scheduler.start().await.expect("could not start system clock");
        Self { scheduler }
    }

    /// Add a job to the clock
    pub async fn add_timer<F>(
        &self,
        name: String,
        run_every: Duration,
        mut callback: F,
    ) -> Result<(), SystemClockError>
    where
        F: 'static,
        F: FnMut() -> Result<(), String> + Send + Sync,
    {
        assert!(
            Self::check_duration_precision(run_every),
            "`run_every` must not specify a sub-second precision"
        );

        let job = Job::new_repeated(run_every, move |_, _| {
            if let Err(e) = callback() {
                error!("error in clock callback {name}: {e}")
            }
        })
        .map_err(err_str!(SystemClockError))?;
        self.scheduler.add(job).await.map_err(err_str!(SystemClockError)).map(|_| ())
    }

    /// Add an asynchronous job to the clock
    pub async fn add_async_timer<F, R>(
        &self,
        name: String,
        run_every: Duration,
        mut callback: F,
    ) -> Result<(), SystemClockError>
    where
        F: 'static,
        F: FnMut() -> R + Send + Sync,
        R: Future<Output = Result<(), String>> + Send + 'static,
    {
        assert!(
            Self::check_duration_precision(run_every),
            "`run_every` must not specify a sub-second precision"
        );

        let job = Job::new_repeated_async(run_every, move |_, _| {
            let fut = callback();
            let name = name.clone();
            Box::pin(async move {
                if let Err(e) = fut.await {
                    error!("error in clock callback {name}: {e}")
                }
            })
        })
        .map_err(err_str!(SystemClockError))?;
        self.scheduler.add(job).await.map_err(err_str!(SystemClockError)).map(|_| ())
    }

    /// Check if the duration does not specify a sub-second precision
    fn check_duration_precision(duration: Duration) -> bool {
        duration.subsec_nanos() == 0
    }
}

#[cfg(test)]
mod test {
    use std::{
        sync::{Arc, RwLock},
        time::{Duration, Instant},
    };

    use tokio::sync::RwLock as TokioRwLock;

    use crate::SystemClock;

    /// The tolerance in milliseconds for the expected duration
    ///
    /// Relatively high compared to the precision the underlying implementation
    /// can give, some overhead is paid in the test setup
    const TOLERANCE_MS: u64 = 10;

    /// Check whether a vector of sequential timestamps are within the expected
    /// duration of one another
    fn check_sequential_timestamps(times: &[Instant], expected: Duration) -> bool {
        let mut within_tolerance = true;
        for i in 1..times.len() {
            let dur = times[i].duration_since(times[i - 1]);
            within_tolerance = within_tolerance && is_within_tolerance_ms(dur, expected);
        }

        within_tolerance
    }

    /// Check whether two durations are within the default tolerance of one
    /// another
    fn is_within_tolerance_ms(actual: Duration, expected: Duration) -> bool {
        is_within_tolerance(actual, expected, Duration::from_millis(TOLERANCE_MS))
    }

    /// Check if the actual duration is within the expected duration plus or
    /// minus the tolerance
    fn is_within_tolerance(actual: Duration, expected: Duration, tolerance: Duration) -> bool {
        let lower_bound = expected - tolerance;
        let upper_bound = expected + tolerance;
        actual >= lower_bound && actual <= upper_bound
    }

    #[cfg_attr(feature = "ci", ignore)]
    #[tokio::test]
    async fn test_system_clock() {
        const SECONDS: u64 = 1;
        let clock = SystemClock::new().await;
        let times = Arc::new(RwLock::new(vec![]));

        let times_clone = times.clone();
        clock
            .add_timer("test-timer".to_string(), Duration::from_secs(SECONDS), move || {
                let mut times = times_clone.write().unwrap();
                times.push(Instant::now());

                Ok(())
            })
            .await
            .expect("could not add timer");

        // Check the spacing of the times
        tokio::time::sleep(Duration::from_secs(SECONDS * 5)).await;
        let final_times = times.read().unwrap().clone();
        assert!(final_times.len() >= 4);
        assert!(check_sequential_timestamps(&final_times, Duration::from_secs(SECONDS)));
    }

    #[cfg_attr(feature = "ci", ignore)]
    #[tokio::test]
    async fn test_async_system_clock() {
        const SECONDS: u64 = 1;
        let clock = SystemClock::new().await;
        let times = Arc::new(TokioRwLock::new(vec![]));

        let times_clone = times.clone();
        clock
            .add_async_timer(
                "async-test-timer".to_string(),
                Duration::from_secs(SECONDS),
                move || {
                    let times = times_clone.clone();
                    async move {
                        let mut times = times.write().await;
                        times.push(Instant::now());

                        Ok(())
                    }
                },
            )
            .await
            .expect("could not add async timer");

        // Check the spacing of the times
        tokio::time::sleep(Duration::from_secs(SECONDS * 5)).await;
        let final_times = times.read().await.clone();
        assert!(final_times.len() >= 4);
        assert!(check_sequential_timestamps(&final_times, Duration::from_secs(SECONDS)));
    }
}
