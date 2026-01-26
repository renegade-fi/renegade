//! Per wallet task rate limiting implementation

use crate::error::ApiServerError;
use ratelimit_meter::{DirectRateLimiter, LeakyBucket};
use std::{collections::HashMap, num::NonZeroU32, time::Duration};
use types_core::AccountId;
use util::concurrency::{AsyncShared, new_async_shared};

/// The rate limiter type for a single wallet
type WalletLimiter = DirectRateLimiter<LeakyBucket>;
/// A thread-safe rate limiter for a single wallet
type SharedWalletLimiter = AsyncShared<WalletLimiter>;
/// The number of seconds in an hour
const SECONDS_PER_HOUR: u64 = 3600;

/// A leaky bucket rate limiter on a per-wallet basis
#[derive(Clone)]
pub struct WalletTaskRateLimiter {
    /// The map of account IDs to their rate limiters
    limiters: AsyncShared<HashMap<AccountId, SharedWalletLimiter>>,
    /// The maximum number of requests per duration
    max_rate: NonZeroU32,
    /// The duration over which the maximum number of requests is allowed
    per_duration: Duration,
}

impl WalletTaskRateLimiter {
    /// Create a new wallet task rate limiter
    pub fn new(max_rate: u32, per_duration: Duration) -> Self {
        let max_rate = NonZeroU32::new(max_rate).expect("max_rate must be non-zero");
        let limiters = new_async_shared(HashMap::new());
        Self { limiters, max_rate, per_duration }
    }

    /// Create a new wallet task rate limiter with an hour long duration
    pub fn new_hourly(max_rate: u32) -> Self {
        Self::new(max_rate, Duration::from_secs(SECONDS_PER_HOUR))
    }

    /// Check the rate limit for a given wallet
    pub async fn check_rate_limit(&self, account: AccountId) -> Result<(), ApiServerError> {
        let limiter = self.get_or_create_limiter(account).await;
        let mut locked_limiter = limiter.write().await;
        locked_limiter.check().map_err(|_| ApiServerError::RateLimitExceeded)
    }

    /// Get or create a rate limiter for a given wallet
    async fn get_or_create_limiter(&self, account: AccountId) -> SharedWalletLimiter {
        // Check if the limiter already exists
        let limiters_read = self.limiters.read().await;
        if let Some(limiter) = limiters_read.get(&account) {
            return limiter.clone();
        }
        drop(limiters_read); // Drop the read lock to escalate to a write lock

        // Create a new limiter if it doesn't exist
        let mut limiters_write = self.limiters.write().await;
        limiters_write
            .entry(account)
            .or_insert_with(|| {
                let limiter = self.new_rate_limiter();
                new_async_shared(limiter)
            })
            .clone()
    }

    /// Create a new rate limiter
    fn new_rate_limiter(&self) -> WalletLimiter {
        DirectRateLimiter::new(self.max_rate, self.per_duration)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    /// Test that the rate limiter correctly handles rate limiting
    #[tokio::test]
    async fn test_rate_limit_success_and_failure() {
        let limiter = WalletTaskRateLimiter::new(2, Duration::from_secs(1));
        let account = AccountId::new_v4();

        assert!(limiter.check_rate_limit(account).await.is_ok());
        assert!(limiter.check_rate_limit(account).await.is_ok());
        assert!(limiter.check_rate_limit(account).await.is_err());
    }

    /// Test the rate limiter after its duration has passed
    #[tokio::test]
    async fn test_rate_limit_reset() {
        let limiter = WalletTaskRateLimiter::new(1, Duration::from_millis(100));
        let account = AccountId::new_v4();

        assert!(limiter.check_rate_limit(account).await.is_ok());
        assert!(limiter.check_rate_limit(account).await.is_err());
        sleep(Duration::from_millis(100)).await;
        assert!(limiter.check_rate_limit(account).await.is_ok());
    }

    /// Test the rate limiter with multiple accounts
    #[tokio::test]
    async fn test_multiple_accounts() {
        let limiter = WalletTaskRateLimiter::new(1, Duration::from_secs(1));
        let account1 = AccountId::new_v4();
        let account2 = AccountId::new_v4();

        assert!(limiter.check_rate_limit(account1).await.is_ok());
        assert!(limiter.check_rate_limit(account1).await.is_err());
        assert!(limiter.check_rate_limit(account2).await.is_ok());
    }
}
