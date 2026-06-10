//! A divergence oracle comparing simulated task effects against actual state
//!
//! When enabled (env var `RENEGADE_SIMULATION_ORACLE=1`), the task driver
//! captures each affected account BEFORE a task runs, projects the task's
//! effect with the simulator, and after the task completes successfully
//! compares the projection against the actual account state, logging a
//! structured warning per divergent field.
//!
//! Motivation (2026-06-09 incident): the hardest relayer bugs are silent
//! state divergences between the local view, the indexer, and the chain --
//! e.g. a lagging refresh re-inflating `amount_in` that local settles had
//! decremented (phantom liquidity -> `InvalidObligationAmountIn`). Those were
//! reconstructed by hand from production logs; this oracle makes the class
//! self-announcing.
//!
//! The oracle is best-effort and must never affect task execution: capture
//! and verification failures are logged at debug level and otherwise ignored.
//! Divergence warnings are LEADS, not alarms: state changes from concurrent
//! activity (chain events, bypass-queue tasks) can interleave between capture
//! and verification.

use std::sync::OnceLock;

use state::State;
use types_account::Account;
use types_core::AccountId;
use types_tasks::{QueuedTask, TaskIdentifier};
use util::log_task;
use util::logging::Outcome;

use super::account_tasks::simulate_single_account_task;
use crate::logging::Task;

/// The environment variable enabling the oracle
const ORACLE_ENV_VAR: &str = "RENEGADE_SIMULATION_ORACLE";

/// Whether the oracle is enabled, read once per process
fn oracle_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var(ORACLE_ENV_VAR).map(|v| v == "1" || v == "true").unwrap_or(false)
    })
}

/// A captured projection for one task, verified after the task completes
pub struct SimulationOracle {
    /// The id of the projected task
    task_id: TaskIdentifier,
    /// A human-readable description of the task
    task_type: String,
    /// The projected post-task state of each affected account
    projections: Vec<(AccountId, Account)>,
}

impl SimulationOracle {
    /// Capture projections for a task about to run.
    ///
    /// Returns `None` when the oracle is disabled, the task is not
    /// simulatable, or capture fails for every affected account. Never
    /// errors: the oracle must not perturb task execution.
    pub async fn capture(
        state: &State,
        task: &QueuedTask,
        affected_accounts: &[AccountId],
    ) -> Option<Self> {
        if !oracle_enabled() {
            return None;
        }

        let mut projections = Vec::new();
        for account_id in affected_accounts.iter().copied() {
            let account = match state.get_account(&account_id).await {
                Ok(Some(account)) => account,
                // A missing account (e.g. first NewAccount task) or a state
                // error is simply not projectable
                _ => continue,
            };

            let mut projected = account;
            match simulate_single_account_task(&mut projected, task.descriptor.clone(), state) {
                Ok(()) => projections.push((account_id, projected)),
                Err(e) => {
                    log_task!(
                        Task::TaskSimulation,
                        Outcome::Skipped,
                        subject = %task.id,
                        account_id = %account_id,
                        error = %e,
                        "oracle could not project task; skipping verification"
                    );
                },
            }
        }

        if projections.is_empty() {
            return None;
        }

        Some(Self {
            task_id: task.id,
            task_type: task.descriptor.display_description(),
            projections,
        })
    }

    /// Compare the captured projections against actual post-task state,
    /// logging a warning per divergent field
    pub async fn verify(self, state: &State) {
        for (account_id, projected) in self.projections {
            let actual = match state.get_account(&account_id).await {
                Ok(Some(account)) => account,
                _ => continue,
            };

            let divergences = diff_accounts(&projected, &actual);
            if divergences.is_empty() {
                log_task!(
                    Task::TaskSimulation,
                    Outcome::Ok,
                    subject = %self.task_id,
                    task_type = %self.task_type,
                    account_id = %account_id,
                    "projection verified against post-task state"
                );
                continue;
            }

            for divergence in divergences {
                log_task!(
                    Task::TaskSimulation,
                    Outcome::Failed,
                    subject = %self.task_id,
                    task_type = %self.task_type,
                    account_id = %account_id,
                    "projection diverged from post-task state (lead, not alarm -- \
                     concurrent activity may interleave): {divergence}"
                );
            }
        }
    }
}

/// Compute field-level divergences between a projected and an actual account.
///
/// Compares the fields the simulator models: per-order `amount_in` and
/// `has_been_filled`, and per-balance amounts. Orders/balances missing on
/// either side are reported as such.
fn diff_accounts(projected: &Account, actual: &Account) -> Vec<String> {
    let mut divergences = Vec::new();

    for (order_id, projected_order) in &projected.orders {
        match actual.orders.get(order_id) {
            None => divergences.push(format!("order {order_id}: projected but absent")),
            Some(actual_order) => {
                let (p_amt, a_amt) = (projected_order.amount_in(), actual_order.amount_in());
                if p_amt != a_amt {
                    divergences
                        .push(format!("order {order_id}: amount_in projected {p_amt} actual {a_amt}"));
                }

                let (p_fill, a_fill) = (
                    projected_order.metadata.has_been_filled,
                    actual_order.metadata.has_been_filled,
                );
                if p_fill != a_fill {
                    divergences.push(format!(
                        "order {order_id}: has_been_filled projected {p_fill} actual {a_fill}"
                    ));
                }
            },
        }
    }
    for order_id in actual.orders.keys() {
        if !projected.orders.contains_key(order_id) {
            divergences.push(format!("order {order_id}: present but not projected"));
        }
    }

    for (mint, loc_map) in &projected.balances {
        for (location, projected_balance) in loc_map {
            let actual_amount = actual
                .get_balance(mint, *location)
                .map(|balance| balance.amount())
                .unwrap_or_default();
            let projected_amount = projected_balance.amount();
            if projected_amount != actual_amount {
                divergences.push(format!(
                    "balance {mint} ({location:?}): projected {projected_amount} actual {actual_amount}"
                ));
            }
        }
    }

    divergences
}

#[cfg(test)]
mod test {
    use types_account::account::mocks::mock_empty_account;

    use super::*;

    /// Identical accounts produce no divergences; a mutated order does
    #[test]
    fn test_diff_accounts() {
        let account = mock_empty_account();
        assert!(diff_accounts(&account, &account).is_empty());

        let mut other = account.clone();
        use types_account::account::mocks::mock_intent;
        use types_account::order::{OrderMetadata, PrivacyRing};
        let order_id = types_account::OrderId::new_v4();
        other.place_order(order_id, mock_intent(), PrivacyRing::Ring0, OrderMetadata::default());

        let diffs = diff_accounts(&account, &other);
        assert_eq!(diffs.len(), 1);
        assert!(diffs[0].contains("present but not projected"));
    }
}
