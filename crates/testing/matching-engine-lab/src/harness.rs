//! Strategy-level load harness (the settlement-level micro-bench).
//!
//! Fires a stream of settlements at a target rate across a tunable number of
//! counterparties and measures how the chosen [`SettlementStrategy`] copes.
//! Counterparty assignment is round-robin, so **fewer counterparties = hotter**
//! — the concentration knob.
//!
//! Safety: in-flight settlements are bounded by `max_in_flight` (semaphore
//! admission) and every settle is wrapped in `settle_timeout`. So even if the
//! backend (in-memory raft) stalls under concurrency, the run always completes
//! — stalls surface as `TimedOut`, never as a hang.

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use tokio::sync::Semaphore;
use types_core::AccountId;
use types_tasks::mocks::mock_task_descriptor;

use crate::{
    backend::Backend,
    strategy::{SettleOutcome, SettlementStrategy},
};

/// A synthetic settlement workload.
#[derive(Debug, Clone)]
pub struct Workload {
    /// Number of distinct counterparty accounts (quoters/MMs). Fewer = hotter.
    pub n_counterparties: usize,
    /// Offered settlements per second.
    pub target_rate_per_sec: f64,
    /// Maximum settlements in flight at once (offered concurrency / backpressure).
    pub max_in_flight: usize,
    /// How long to offer load.
    pub duration: Duration,
    /// Mocked settlement latency (on-chain + proof + raft), held per settle.
    pub hold: Duration,
    /// Per-settle timeout (safety net against a stalled backend).
    pub settle_timeout: Duration,
}

impl Workload {
    /// A small, safe default; override fields as needed.
    pub fn new(n_counterparties: usize, target_rate_per_sec: f64, hold: Duration) -> Self {
        Self {
            n_counterparties,
            target_rate_per_sec,
            max_in_flight: 8,
            duration: Duration::from_millis(800),
            hold,
            settle_timeout: Duration::from_secs(3),
        }
    }
}

/// Aggregated outcome of a load run.
#[derive(Debug, Clone)]
pub struct RunReport {
    /// Strategy name.
    pub strategy: &'static str,
    /// Counterparty count for the run.
    pub n_counterparties: usize,
    /// Max in-flight for the run.
    pub max_in_flight: usize,
    /// Total settlements offered.
    pub offered: usize,
    /// Settled successfully.
    pub settled: usize,
    /// Lost the serial-preemption race.
    pub conflicts: usize,
    /// Genuine failures.
    pub failed: usize,
    /// Timed out (backend stall).
    pub timed_out: usize,
    /// Wall-clock duration of the run.
    pub wall: Duration,
    /// Settled per second over the wall clock.
    pub settled_per_sec: f64,
    /// Settled count against the single hottest counterparty.
    pub hottest_cp_settled: usize,
    /// Median settle latency (queue wait + hold).
    pub settle_p50: Duration,
    /// p99 settle latency.
    pub settle_p99: Duration,
}

impl fmt::Display for RunReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pct = |n: usize| {
            if self.offered > 0 { 100.0 * n as f64 / self.offered as f64 } else { 0.0 }
        };
        write!(
            f,
            "[{:<18}] cps={:<3} inflight={:<3} offered={:<4} settled={:<4} conflicts={:<4}({:>3.0}%) \
             failed={:<3} timeouts={:<3}({:>3.0}%) | settled/s={:>6.1} hottest={:<4} p50={:>7?} p99={:>7?}",
            self.strategy,
            self.n_counterparties,
            self.max_in_flight,
            self.offered,
            self.settled,
            self.conflicts,
            pct(self.conflicts),
            self.failed,
            self.timed_out,
            pct(self.timed_out),
            self.settled_per_sec,
            self.hottest_cp_settled,
            self.settle_p50,
            self.settle_p99,
        )
    }
}

#[derive(Default)]
struct Metrics {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    offered: usize,
    settled: usize,
    conflicts: usize,
    failed: usize,
    timed_out: usize,
    per_cp_settled: HashMap<usize, usize>,
    settled_latencies: Vec<Duration>,
}

impl Metrics {
    fn record(&self, rank: usize, outcome: SettleOutcome, latency: Duration) {
        let mut g = self.inner.lock().unwrap();
        g.offered += 1;
        match outcome {
            SettleOutcome::Settled => {
                g.settled += 1;
                *g.per_cp_settled.entry(rank).or_default() += 1;
                g.settled_latencies.push(latency);
            },
            SettleOutcome::PreemptionConflict => g.conflicts += 1,
            SettleOutcome::Failed(_) => g.failed += 1,
            SettleOutcome::TimedOut => g.timed_out += 1,
        }
    }

    fn report(
        &self,
        strategy: &'static str,
        wall: Duration,
        n_counterparties: usize,
        max_in_flight: usize,
    ) -> RunReport {
        let g = self.inner.lock().unwrap();
        let mut lats = g.settled_latencies.clone();
        lats.sort_unstable();
        let pct = |p: f64| -> Duration {
            if lats.is_empty() {
                Duration::ZERO
            } else {
                let idx = ((lats.len() as f64 - 1.0) * p).round() as usize;
                lats[idx]
            }
        };
        let hottest = g.per_cp_settled.values().copied().max().unwrap_or(0);
        let secs = wall.as_secs_f64().max(f64::MIN_POSITIVE);
        RunReport {
            strategy,
            n_counterparties,
            max_in_flight,
            offered: g.offered,
            settled: g.settled,
            conflicts: g.conflicts,
            failed: g.failed,
            timed_out: g.timed_out,
            wall,
            settled_per_sec: g.settled as f64 / secs,
            hottest_cp_settled: hottest,
            settle_p50: pct(0.50),
            settle_p99: pct(0.99),
        }
    }
}

/// Run a load workload against a strategy + state, returning the report.
///
/// In-flight settlements are capped at `wl.max_in_flight` and each settle is
/// bounded by `wl.settle_timeout`, so this never hangs.
pub async fn run_load(
    strategy: Arc<dyn SettlementStrategy>,
    backend: Arc<dyn Backend>,
    wl: &Workload,
) -> RunReport {
    let name = strategy.name();
    let cps: Vec<AccountId> = (0..wl.n_counterparties).map(|_| AccountId::new_v4()).collect();
    let interval_dur = Duration::from_secs_f64(1.0 / wl.target_rate_per_sec);
    let metrics = Arc::new(Metrics::default());
    let sem = Arc::new(Semaphore::new(wl.max_in_flight));

    let start = Instant::now();
    let mut ticker = tokio::time::interval(interval_dur);
    let mut handles = Vec::new();
    let mut i = 0usize;
    while start.elapsed() < wl.duration {
        ticker.tick().await;
        // Bound in-flight: blocks here when at capacity (released after each
        // settle completes or times out, so this can never deadlock).
        let permit = sem.clone().acquire_owned().await.unwrap();
        let rank = i % wl.n_counterparties;
        let desc = mock_task_descriptor(cps[rank]);
        let s = strategy.clone();
        let b = backend.clone();
        let m = metrics.clone();
        let to = wl.settle_timeout;
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            let t0 = Instant::now();
            let outcome = match tokio::time::timeout(to, s.settle(b.as_ref(), desc)).await {
                Ok(o) => o,
                Err(_) => SettleOutcome::TimedOut,
            };
            m.record(rank, outcome, t0.elapsed());
        }));
        i += 1;
    }
    for h in handles {
        let _ = h.await;
    }
    metrics.report(name, start.elapsed(), wl.n_counterparties, wl.max_in_flight)
}

#[cfg(test)]
mod test {
    use std::{sync::Arc, time::Duration};

    use state::test_helpers::mock_state;

    use super::{Workload, run_load};
    use crate::{
        backend::{DirectApplicatorBackend, RaftBackend},
        ledger::MockBalanceLedger,
        strategies::{
            BatchedPerCounterpartyMock, PipelinedOptimisticMock, RetrySerialPerAccountMock,
            SerialPerAccountMock,
        },
    };

    fn strat(hold: Duration) -> Arc<SerialPerAccountMock> {
        Arc::new(SerialPerAccountMock::new(hold, Arc::new(MockBalanceLedger::new())))
    }

    async fn raft() -> Arc<RaftBackend> {
        Arc::new(RaftBackend::new(mock_state().await))
    }

    /// Diagnostic: how much concurrent settlement load does the in-memory raft
    /// backend tolerate before settles start timing out? Sweeps `max_in_flight`
    /// at a single hot account. Prints numbers; the only hard assertion is that
    /// the run *completes* (no hang) and low concurrency works. Run with
    /// `--nocapture` to see where timeouts appear.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrency_sweep() {
        let hold = Duration::from_millis(50);
        println!("\n--- concurrency sweep (1 hot counterparty, hold=50ms) ---");
        let mut low_ok = false;
        for inflight in [1usize, 2, 4, 8, 16] {
            let wl = Workload {
                max_in_flight: inflight,
                duration: Duration::from_millis(500),
                settle_timeout: Duration::from_secs(2),
                ..Workload::new(1, 60.0, hold)
            };
            let rep = run_load(strat(hold), raft().await, &wl).await;
            println!("{rep}");
            if inflight <= 2 {
                low_ok = low_ok || (rep.settled > 0 && rep.timed_out == 0);
            }
        }
        assert!(low_ok, "low-concurrency load should settle with no timeouts");
    }

    /// Diagnostic: how much *true parallelism* (many distinct accounts settling
    /// at once) does the in-memory raft backend tolerate before settles time
    /// out? Each level uses `cps == inflight` so every in-flight settle is on a
    /// different account (no preemption conflicts) — pure parallel proposal
    /// load. Reveals the backend's parallel-settle ceiling (the original
    /// unbounded run hung here). Prints; asserts only that it completes.
    ///
    /// FINDING (2026-05-30): the `mock_state` raft backend stalls at ~16
    /// concurrent distinct-account proposals (≥89% timeouts), and raising the
    /// runtime to 16 worker threads does NOT move the ceiling — so it's the raft
    /// consensus transport, not executor starvation. The lab must drive the
    /// state-machine applicator directly (bypass raft consensus) to study
    /// realistic parallelism. See the ticket.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn parallelism_sweep() {
        let hold = Duration::from_millis(50);
        println!("\n--- parallelism sweep: DirectApplicator (cps==inflight, distinct accounts) ---");
        let mut at32 = None;
        for n in [4usize, 16, 32, 64] {
            let wl = Workload {
                max_in_flight: n,
                duration: Duration::from_millis(500),
                settle_timeout: Duration::from_secs(3),
                ..Workload::new(n, 200.0, hold)
            };
            let rep = run_load(strat(hold), Arc::new(DirectApplicatorBackend::new()), &wl).await;
            println!("{rep}");
            if n == 32 {
                at32 = Some(rep);
            }
        }
        // The raft backend stalls at ~16 concurrent proposals (≥89% timeouts);
        // the direct applicator removes that consensus ceiling — high
        // parallelism settles cleanly.
        let at32 = at32.unwrap();
        assert_eq!(at32.timed_out, 0, "direct applicator should not stall at 32 concurrent: {at32}");
        assert!(at32.settled > 0, "direct applicator should settle at high concurrency: {at32}");
    }

    /// Thesis: a single hot counterparty saturates (conflicts dominate, low
    /// settle rate) while the same offered load spread across many
    /// counterparties settles freely. Bounded + timed-out so it can't hang.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn hot_account_ceiling_vs_spread() {
        let hold = Duration::from_millis(80);
        let base = Workload {
            max_in_flight: 4,
            duration: Duration::from_millis(800),
            settle_timeout: Duration::from_secs(2),
            ..Workload::new(1, 40.0, hold)
        };

        let hot = run_load(strat(hold), Arc::new(DirectApplicatorBackend::new()), &base).await;
        let spread = run_load(
            strat(hold),
            Arc::new(DirectApplicatorBackend::new()),
            &Workload { n_counterparties: 20, ..base },
        )
        .await;

        println!("\n{hot}\n{spread}\n");

        assert_eq!(hot.timed_out, 0, "hot run should not time out (backend stall): {hot}");
        assert_eq!(spread.timed_out, 0, "spread run should not time out: {spread}");
        assert!(hot.conflicts > hot.settled, "hot account should shed most load: {hot}");
        assert!(spread.settled > hot.settled, "spread should settle more: {spread} vs {hot}");
        assert!(
            spread.conflicts < hot.conflicts,
            "spread should have far fewer conflicts: {spread} vs {hot}"
        );
    }

    /// PHASE 6 — the payoff: baseline vs retry vs batched under a concentrated
    /// quoter/MM-shaped workload (few hot counterparties, high offered
    /// concurrency). Retry recovers dropped conflicts but cannot beat the
    /// per-account serial ceiling; batching amortizes the hold and does. Run
    /// with `--nocapture` for the comparison table — the evidence for the
    /// relayer fix decision.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn strategy_comparison() {
        let hold = Duration::from_millis(50);
        let wl = Workload {
            n_counterparties: 4,
            target_rate_per_sec: 300.0,
            max_in_flight: 32,
            duration: Duration::from_millis(1000),
            hold,
            settle_timeout: Duration::from_secs(5),
        };
        let led = || Arc::new(MockBalanceLedger::new());
        let direct = || Arc::new(DirectApplicatorBackend::new());

        let baseline =
            run_load(Arc::new(SerialPerAccountMock::new(hold, led())), direct(), &wl).await;
        let retry = run_load(
            Arc::new(RetrySerialPerAccountMock::new(
                hold,
                led(),
                8,
                Duration::from_millis(5),
                Duration::from_millis(200),
            )),
            direct(),
            &wl,
        )
        .await;
        let batched =
            run_load(Arc::new(BatchedPerCounterpartyMock::new(hold, led())), direct(), &wl).await;

        println!("\n=== strategy comparison: 4 hot counterparties, hold=50ms ===");
        println!("{baseline}");
        println!("{retry}");
        println!("{batched}");

        // Retry recovers conflicts the baseline drops...
        assert!(
            retry.conflicts < baseline.conflicts,
            "retry should drop fewer than baseline: {retry} vs {baseline}"
        );
        // ...but cannot beat the per-account serial ceiling; batching can.
        assert!(
            batched.settled_per_sec > baseline.settled_per_sec,
            "batching should beat the serial ceiling: {batched} vs {baseline}"
        );
        assert!(
            batched.settled_per_sec > retry.settled_per_sec,
            "batching should beat retry throughput: {batched} vs {retry}"
        );
    }

    /// PIPELINING — quantify optimistic chaining against the serial baseline and
    /// the batched ceiling, under the same concentrated quoter/MM workload as
    /// `strategy_comparison`. Pipelining splits the 50ms settlement into a 5ms
    /// account-held submit + a 45ms off-lock confirm (same 50ms total latency),
    /// with an 8-deep optimistic chain per counterparty. Because only the 5ms
    /// submit serializes per account (confirms overlap), per-wallet throughput
    /// rises far above the serial `1/hold` ceiling **without** batching's circuit
    /// change. Run with `--nocapture` for the table — the evidence for shipping
    /// pipelining (Track P) first.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pipelined_quantify() {
        let hold = Duration::from_millis(50);
        let submit = Duration::from_millis(5);
        let confirm = Duration::from_millis(45); // submit + confirm == hold
        let depth = 8;
        let wl = Workload {
            n_counterparties: 4,
            target_rate_per_sec: 300.0,
            max_in_flight: 32,
            duration: Duration::from_millis(1000),
            hold,
            settle_timeout: Duration::from_secs(5),
        };
        let led = || Arc::new(MockBalanceLedger::new());
        let direct = || Arc::new(DirectApplicatorBackend::new());

        let serial =
            run_load(Arc::new(SerialPerAccountMock::new(hold, led())), direct(), &wl).await;
        let pipelined = run_load(
            Arc::new(PipelinedOptimisticMock::new(submit, confirm, led(), depth)),
            direct(),
            &wl,
        )
        .await;
        let pipelined_reverts = run_load(
            Arc::new(
                PipelinedOptimisticMock::new(submit, confirm, led(), depth).with_revert_every(10),
            ),
            direct(),
            &wl,
        )
        .await;
        let batched =
            run_load(Arc::new(BatchedPerCounterpartyMock::new(hold, led())), direct(), &wl).await;

        println!("\n=== pipelining: 4 hot counterparties, hold=50ms (submit=5ms + confirm=45ms), depth=8 ===");
        println!("{serial}");
        println!("{pipelined}");
        println!("{pipelined_reverts} (10% revert)");
        println!("{batched}");

        // The core win is structural (CPU-independent, unlike the throughput
        // ratio which the printed table reports): pipelining converts the serial
        // drop-most-load regime into settle-(nearly)-all.
        //   - serial sheds most offered load to conflicts (success rate < 50%),
        assert!(
            serial.settled * 2 < serial.offered,
            "serial baseline should shed most load: {serial}"
        );
        //   - pipelining eliminates the conflict storm and settles most offered,
        assert!(
            pipelined.conflicts * 10 < serial.conflicts,
            "pipelining should eliminate the conflict storm: {pipelined} vs {serial}"
        );
        assert!(
            pipelined.settled * 2 > pipelined.offered,
            "pipelining should settle most offered load: {pipelined}"
        );
        // No genuine failures or backend stalls on the happy path.
        assert_eq!(pipelined.failed, 0, "pipelining happy path should not fail: {pipelined}");
        assert_eq!(pipelined.timed_out, 0, "pipelining should not stall: {pipelined}");
        // A modest revert rate still beats the serial baseline (rollback is cheap
        // at shallow depth).
        assert!(
            pipelined_reverts.settled_per_sec > serial.settled_per_sec,
            "pipelining w/ reverts should still beat serial: {pipelined_reverts} vs {serial}"
        );
    }

    /// Sharding sweep: hold the *total demand* for one base fixed and vary the
    /// number of sub-wallets (shards) it's split across (the quoter `-N` index
    /// mechanism). Per-shard serial throughput is `1/hold`, so clearing demand
    /// `λ` needs about `N = λ·hold` shards. Quantifies how many indices a hot
    /// base needs to stop dropping settlements.
    ///
    /// NOTE: settlement-throughput dimension only — this does NOT model
    /// liquidity fragmentation (each shard holds 1/N of the depth), which bounds
    /// N from above. So this gives the *lower* bound on N (enough to clear load).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn sharding_sweep() {
        let hold = Duration::from_millis(100);
        let rate = 60.0; // fixed total demand for one base (settles/s)
        let per_shard = 1.0 / hold.as_secs_f64();
        let need = (rate * hold.as_secs_f64()).ceil() as usize;
        println!(
            "\n=== sharding sweep: demand={rate}/s, settle={hold:?}, per-shard ceiling={per_shard:.0}/s, N_needed≈{need} ==="
        );

        let mut one = None;
        let mut many = None;
        for shards in [1usize, 2, 4, 6, 8, 12] {
            let wl = Workload {
                n_counterparties: shards,
                target_rate_per_sec: rate,
                max_in_flight: 48,
                duration: Duration::from_millis(1200),
                hold,
                settle_timeout: Duration::from_secs(5),
            };
            let rep = run_load(strat(hold), Arc::new(DirectApplicatorBackend::new()), &wl).await;
            println!("N={shards:<2} {rep}");
            if shards == 1 {
                one = Some(rep.clone());
            }
            if shards == 12 {
                many = Some(rep);
            }
        }
        let one = one.unwrap();
        let many = many.unwrap();
        // One shard saturates (drops most); enough shards clear the demand.
        assert!(one.conflicts > one.settled, "1 shard should saturate: {one}");
        assert!(
            many.conflicts * 10 < one.conflicts.max(1),
            "enough shards should clear most conflicts: N=12 [{many}] vs N=1 [{one}]"
        );
    }
}
