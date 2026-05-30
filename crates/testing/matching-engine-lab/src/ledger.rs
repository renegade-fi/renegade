//! A lightweight in-memory accounting of mock settlements, used to measure
//! per-counterparty throughput without touching real balances.

use std::sync::Mutex;

use types_core::AccountId;

/// Records mock settlement outcomes for metrics. Cheap and thread-safe so many
/// concurrent strategy invocations can record into it.
#[derive(Default)]
pub struct MockBalanceLedger {
    /// The counterparty account of each settled fill, in settle order.
    settled: Mutex<Vec<AccountId>>,
}

impl MockBalanceLedger {
    /// Create an empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a settled fill against `counterparty`.
    pub fn record_settled(&self, counterparty: AccountId) {
        self.settled.lock().unwrap().push(counterparty);
    }

    /// Total settled fills across all counterparties.
    pub fn settled_count(&self) -> usize {
        self.settled.lock().unwrap().len()
    }

    /// Settled fills against a specific counterparty.
    pub fn settled_for(&self, counterparty: &AccountId) -> usize {
        self.settled.lock().unwrap().iter().filter(|a| *a == counterparty).count()
    }
}
