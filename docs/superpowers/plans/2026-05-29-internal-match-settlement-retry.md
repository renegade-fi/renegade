# Internal-Match Settlement Retry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make internal-match settlement reliably complete under concurrent settlement attempts on the same wallet by retrying the transient `serial preemption not allowed` reject (re-evaluating the match each attempt), instead of failing on first collision.

**Architecture:** When the internal matching engine settles a match it enqueues a *serial* (exclusive) preemptive task on both matched wallets' queues. If a wallet already holds a serial preemption — or a *committed* (on-chain, irreversible) task — the enqueue is rejected by design (deadlock + committed-task protection; see `is_serial_preemption_safe`). Today the engine logs an `error!` and gives up, with no automatic re-trigger, so the order strands until an incidental event re-runs matching. We add a bounded retry loop in `run_internal_matching_engine` that **re-finds** the match each attempt and retries only on the preemption conflict. We do **not** change the reject/queue semantics. We also downgrade the conflict log to `warn` (completing the precedent set for the external engine in commit `0539005d65`).

**Tech Stack:** Rust, tokio, the `metrics` crate, renegade `state` + `matching-engine-worker` crates.

---

## File Structure

- `crates/state/src/storage/tx/task_queue/storage.rs` — make `ERR_CANNOT_SERIALLY_PREEMPT` visible to the crate (classifier needs it).
- `crates/state/src/error.rs` — add `StateError::is_serial_preemption_conflict()` predicate + its unit test.
- `crates/workers/matching-engine/matching-engine-worker/src/error.rs` — add `MatchingEngineError::PreemptionConflict` variant.
- `crates/workers/matching-engine/matching-engine-worker/src/manager/matching/internal_engine.rs` — retry config + pure `next_backoff` + its unit test; the retry loop + log downgrade + metric in `run_internal_matching_engine`.
- `crates/workers/matching-engine/matching-engine-worker/src/manager/tasks.rs` — map the conflict `StateError` → `MatchingEngineError::PreemptionConflict` at the enqueue site.

**Constraint (do not violate):** Do NOT change `preempt_queue_with_serial` / `is_serial_preemption_safe` / `TaskQueuePreemptionState`. The reject guards committed settlements and prevents the two-wallet deadlock. The fix is retry-side only.

**Note on testing:** the `matching-engine-worker` crate has **no existing unit-test harness** for `MatchingEngineExecutor` (no mock state/task-queue). So we unit-test the *pure* pieces (the error classifier and the backoff function) and the retry loop's control flow is validated end-to-end on testnet via `mm-resting-flow-v2`. Do not invent an executor mock — that is out of scope.

---

### Task 1: Expose the reject constant + add `StateError` classifier

**Files:**
- Modify: `crates/state/src/storage/tx/task_queue/storage.rs:24`
- Modify: `crates/state/src/error.rs`
- Test: `crates/state/src/error.rs` (inline `#[cfg(test)]`)

- [ ] **Step 1: Make the reject message constant crate-visible**

In `crates/state/src/storage/tx/task_queue/storage.rs`, change line 24 from:

```rust
const ERR_CANNOT_SERIALLY_PREEMPT: &str = "serial preemption not allowed";
```

to:

```rust
pub(crate) const ERR_CANNOT_SERIALLY_PREEMPT: &str = "serial preemption not allowed";
```

- [ ] **Step 2: Write the failing test for the classifier**

Append to `crates/state/src/error.rs` (inside an existing or new `#[cfg(test)] mod test`):

```rust
#[cfg(test)]
mod test {
    use super::StateError;

    #[test]
    fn test_is_serial_preemption_conflict() {
        let conflict = StateError::TransitionRejected(
            "serial preemption not allowed".to_string(),
        );
        assert!(conflict.is_serial_preemption_conflict());

        let other_reject = StateError::TransitionRejected("nullifier spent".to_string());
        assert!(!other_reject.is_serial_preemption_conflict());

        let unrelated = StateError::Proposal("raft down".to_string());
        assert!(!unrelated.is_serial_preemption_conflict());
    }
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `RUSTC_BOOTSTRAP=1 cargo test -p state is_serial_preemption_conflict`
Expected: FAIL — `no method named is_serial_preemption_conflict`.

- [ ] **Step 4: Implement the predicate**

In `crates/state/src/error.rs`, add an `impl StateError` block (or extend the existing one). Reference the storage constant as the single source of truth:

```rust
use crate::storage::tx::task_queue::storage::ERR_CANNOT_SERIALLY_PREEMPT;

impl StateError {
    /// Whether this error is the transient "serial preemption not allowed"
    /// reject — a settlement could not preempt a wallet queue because another
    /// serial (exclusive) task, or a committed task, holds it. This is
    /// expected under contention and is safe to retry.
    pub fn is_serial_preemption_conflict(&self) -> bool {
        matches!(self, StateError::TransitionRejected(msg) if msg.contains(ERR_CANNOT_SERIALLY_PREEMPT))
    }
}
```

> If the `storage::storage` module path is not already re-exported, add `pub(crate) use` as needed so `ERR_CANNOT_SERIALLY_PREEMPT` resolves from `error.rs`. Confirm the exact module path with `rg "mod storage" crates/state/src/storage/tx/task_queue/mod.rs`.

- [ ] **Step 5: Run the test to verify it passes**

Run: `RUSTC_BOOTSTRAP=1 cargo test -p state is_serial_preemption_conflict`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/state/src/error.rs crates/state/src/storage/tx/task_queue/storage.rs
git commit -m "state: add StateError::is_serial_preemption_conflict classifier"
```

---

### Task 2: Add the typed `PreemptionConflict` matching-engine error

**Files:**
- Modify: `crates/workers/matching-engine/matching-engine-worker/src/error.rs`

- [ ] **Step 1: Add the variant**

In `crates/workers/matching-engine/matching-engine-worker/src/error.rs`, add to the `MatchingEngineError` enum (after `State`):

```rust
    /// A settlement could not preempt a wallet's task queue because it was
    /// exclusively locked (another serial/committed task). Transient and
    /// retryable — see `is_serial_preemption_conflict`.
    #[error("settlement preempted: wallet task queue exclusively locked")]
    PreemptionConflict,
```

- [ ] **Step 2: Verify it compiles**

Run: `RUSTC_BOOTSTRAP=1 cargo check -p matching-engine-worker`
Expected: compiles (the `From<StateError>` impl is unaffected; new variant is additive).

- [ ] **Step 3: Commit**

```bash
git add crates/workers/matching-engine/matching-engine-worker/src/error.rs
git commit -m "matching-engine: add typed PreemptionConflict error"
```

---

### Task 3: Pure backoff function + retry config

**Files:**
- Modify: `crates/workers/matching-engine/matching-engine-worker/src/manager/matching/internal_engine.rs`
- Test: same file (inline `#[cfg(test)]`)

- [ ] **Step 1: Write the failing test**

Append to `internal_engine.rs`:

```rust
#[cfg(test)]
mod retry_test {
    use std::time::Duration;
    use super::{next_backoff, MAX_SETTLE_RETRIES, RETRY_BASE_DELAY, RETRY_MAX_DELAY};

    #[test]
    fn test_next_backoff_bounds_and_growth() {
        // attempt 0 is at least the base, capped by max, jitter keeps it in range
        for attempt in 0..MAX_SETTLE_RETRIES {
            let d = next_backoff(attempt);
            assert!(d >= RETRY_BASE_DELAY, "delay below base at attempt {attempt}");
            assert!(d <= RETRY_MAX_DELAY * 2, "delay exceeds cap+jitter at attempt {attempt}");
        }
        // total worst-case budget stays well under the consumer fill timeout (45s)
        let total: Duration = (0..MAX_SETTLE_RETRIES).map(next_backoff).sum();
        assert!(total < Duration::from_secs(15), "total retry budget too large: {total:?}");
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `RUSTC_BOOTSTRAP=1 cargo test -p matching-engine-worker next_backoff`
Expected: FAIL — `cannot find function next_backoff`.

- [ ] **Step 3: Implement the backoff + constants**

Add near the top of `internal_engine.rs` (module-level, below imports). Add `use rand::Rng;` and `use std::time::Duration;` to imports if not present (the `rand` crate is already a workspace dependency):

```rust
/// Max settlement attempts before giving up on a single matching run.
pub(crate) const MAX_SETTLE_RETRIES: u32 = 5;
/// Base backoff between settlement retries.
pub(crate) const RETRY_BASE_DELAY: Duration = Duration::from_millis(100);
/// Cap on the exponential backoff (a committed on-chain settlement may take
/// a few seconds to clear the queue).
pub(crate) const RETRY_MAX_DELAY: Duration = Duration::from_millis(1500);

/// Jittered exponential backoff for settlement retries. `attempt` is 0-indexed.
pub(crate) fn next_backoff(attempt: u32) -> Duration {
    let exp = RETRY_BASE_DELAY.saturating_mul(2u32.saturating_pow(attempt));
    let capped = std::cmp::min(exp, RETRY_MAX_DELAY);
    // Full jitter in [0, capped] added on top of half the capped delay.
    let half = capped / 2;
    let jitter_ms = rand::thread_rng().gen_range(0..=(capped.as_millis() as u64).max(1));
    half + Duration::from_millis(jitter_ms)
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `RUSTC_BOOTSTRAP=1 cargo test -p matching-engine-worker next_backoff`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/workers/matching-engine/matching-engine-worker/src/manager/matching/internal_engine.rs
git commit -m "matching-engine: add jittered backoff + retry config for settlement"
```

---

### Task 4: Map the reject to the typed conflict at the enqueue site

**Files:**
- Modify: `crates/workers/matching-engine/matching-engine-worker/src/manager/tasks.rs:39-55`

- [ ] **Step 1: Rewrite `enqueue_task_through_raft` to classify the reject**

Replace the body of `enqueue_task_through_raft` with:

```rust
    /// Enqueue a task through the raft task queue abstraction
    async fn enqueue_task_through_raft(
        &self,
        descriptor: TaskDescriptor,
    ) -> Result<(), MatchingEngineError> {
        // Send the proposal to the raft
        let accounts = descriptor.affected_accounts();
        let (tid, waiter) = match self
            .state
            .enqueue_preemptive_task(accounts, descriptor, true /* is_serial */)
            .await
        {
            Ok(res) => res,
            Err(e) if e.is_serial_preemption_conflict() => {
                return Err(MatchingEngineError::PreemptionConflict);
            },
            Err(e) => return Err(e.into()),
        };

        // The reject is also surfaced when the proposal is applied (via the waiter)
        if let Err(e) = waiter.await {
            if e.is_serial_preemption_conflict() {
                return Err(MatchingEngineError::PreemptionConflict);
            }
            return Err(e.into());
        }

        // Await a completion notification from the task driver
        let (job, rx) = TaskDriverJob::new_notification(tid);
        self.task_queue.send(job).map_err(MatchingEngineError::send_message)?;
        rx.await
            .map_err(MatchingEngineError::task)? // RecvError
            .map_err(MatchingEngineError::task) // TaskDriverError
    }
```

> Confirm `waiter.await` resolves to `Result<_, StateError>` (so `is_serial_preemption_conflict()` is callable). If `ProposalWaiter`'s error is a different type, add an equivalent predicate or `matches!` on its rejected variant. Check with `rg "struct ProposalWaiter|impl .*ProposalWaiter|type Output" crates/state/src`.

- [ ] **Step 2: Verify it compiles**

Run: `RUSTC_BOOTSTRAP=1 cargo check -p matching-engine-worker`
Expected: compiles. (If `is_serial_preemption_conflict` isn't in scope, add `use state::error::StateError;` — already imported via the error module.)

- [ ] **Step 3: Commit**

```bash
git add crates/workers/matching-engine/matching-engine-worker/src/manager/tasks.rs
git commit -m "matching-engine: surface serial-preemption reject as typed PreemptionConflict"
```

---

### Task 5: Retry loop + log downgrade + metric in `run_internal_matching_engine`

**Files:**
- Modify: `crates/workers/matching-engine/matching-engine-worker/src/manager/matching/internal_engine.rs:28-76`

- [ ] **Step 1: Rewrite `run_internal_matching_engine` with a bounded retry loop**

Replace the function body (lines 28-76) with the version below. It re-finds the match each attempt (so a competitor that already settled → `find` returns `None` → clean stop, no double-settle), retries only on `PreemptionConflict`, and downgrades that case to `warn`. Add `use tracing::warn;` if not present, and `use metrics::counter;`.

```rust
    #[instrument(name = "run_internal_matching_engine", skip_all)]
    pub async fn run_internal_matching_engine(
        &self,
        account_id: AccountId,
        order_id: OrderId,
    ) -> Result<(), MatchingEngineError> {
        info!("Running internal matching engine on order {order_id}");

        for attempt in 0..MAX_SETTLE_RETRIES {
            // Re-fetch + re-find each attempt so a competitor that already
            // settled this order is observed as "no match" and we stop cleanly.
            let (order, matchable_amount) =
                self.fetch_order_and_matchable_amount(&order_id).await?;
            let matching_pool = self.fetch_matching_pool(&order_id).await?;

            let pair = order.pair();
            if self.is_asset_disabled(&pair.in_token) || self.is_asset_disabled(&pair.out_token) {
                warn!("Asset disabled for matching, skipping internal matching engine for {order_id}");
                return Ok(());
            }

            let successful_match =
                match self.find_internal_match(account_id, &order, matchable_amount, matching_pool)? {
                    Some(m) => m,
                    None => {
                        info!("No internal matches found for {order_id:?}");
                        return Ok(());
                    },
                };
            let other_id = successful_match.other_order_id;

            match self.try_settle_match(order_id, successful_match).await {
                Ok(()) => return Ok(()),
                Err(MatchingEngineError::PreemptionConflict) => {
                    // Transient: a concurrent/committed settlement holds a wallet
                    // queue. Back off and re-evaluate. Expected under contention.
                    counter!("internal_match_settlement_preemption_retry").increment(1);
                    warn!(
                        "settlement for {other_id} x {order_id} preempted (attempt {}/{}); retrying",
                        attempt + 1,
                        MAX_SETTLE_RETRIES
                    );
                    if !self.order_still_valid(&order_id).await? {
                        info!("account has changed, stopping internal matching engine...");
                        return Ok(());
                    }
                    tokio::time::sleep(next_backoff(attempt)).await;
                    continue;
                },
                Err(e) => {
                    // A genuine settlement failure (not contention).
                    error!("internal match settlement failed for {other_id} x {order_id}: {e}");
                    return Ok(());
                },
            }
        }

        counter!("internal_match_settlement_preemption_exhausted").increment(1);
        warn!(
            "internal match settlement for {order_id} exhausted {MAX_SETTLE_RETRIES} preemption retries; \
             will settle on a subsequent matching run"
        );
        Ok(())
    }
```

> This removes the old `// TODO: maybe iteratively attempt to find a match...` comment (lines 56-57) — the TODO is now implemented.

- [ ] **Step 2: Verify it compiles + clippy**

Run: `RUSTC_BOOTSTRAP=1 cargo clippy -p matching-engine-worker --all-targets`
Expected: no errors. Fix any unused-import / `error!`/`warn!` import issues.

- [ ] **Step 3: Run the crate's tests**

Run: `RUSTC_BOOTSTRAP=1 cargo test -p matching-engine-worker`
Expected: PASS (the `next_backoff` test from Task 3).

- [ ] **Step 4: Commit**

```bash
git add crates/workers/matching-engine/matching-engine-worker/src/manager/matching/internal_engine.rs
git commit -m "matching-engine: retry internal settlement on preemption conflict (re-find each attempt)"
```

---

### Task 6: Workspace build + lint gate

**Files:** none (verification only)

- [ ] **Step 1: Full build**

Run: `RUSTC_BOOTSTRAP=1 cargo check --workspace`
Expected: compiles. (`CARGO_TARGET_DIR=/tmp/renegade-target` if the default target dir has stale artifacts.)

- [ ] **Step 2: Clippy on the touched crates**

Run: `RUSTC_BOOTSTRAP=1 cargo clippy -p state -p matching-engine-worker --all-targets`
Expected: clean.

- [ ] **Step 3: Targeted tests**

Run: `RUSTC_BOOTSTRAP=1 cargo test -p state -p matching-engine-worker`
Expected: PASS.

---

### Task 7: Testnet validation (manual, after deploy)

**Files:** none (operational verification)

The executor has no unit harness, so the retry loop's real behavior is validated against the synthetic `mm-resting-flow-v2` test on testnet. Deploy the relayer image to `arbitrum-sepolia-v2` + `base-sepolia-v2` (normal relayer rollout), then over a ~15-min window confirm via the `dd` skill (`pup`):

- [ ] **Step 1: serial-preemption rate drops**

`pup logs aggregate --query='service:arbitrum-sepolia-v2-relayer "serial preemption not allowed"' --from='15m' --compute=count`
Expected: sharply lower than the pre-fix baseline (~1.4/min). Most settlements now succeed on retry rather than logging the reject as an `error!`.

- [ ] **Step 2: arb mm-resting fill-timeouts drop**

`pup logs aggregate --query='service:testnet-v2-synthetic-tester @task:mm-resting-flow-v2 @chain:arbitrum-sepolia @outcome:failed' --from='15m' --compute=count`
Expected: near base-sepolia levels; `@subject:fills @outcome:ok` count rises.

- [ ] **Step 3: OTLP error-span volume drops**

`pup logs aggregate --query='service:arbitrum-sepolia-v2-relayer "batch processor"' --from='15m' --compute=count`
Expected: lower (fewer error spans from the downgraded log + fewer failed settlements feeding the exporter).

- [ ] **Step 4: no regression in internal-match or external-match**

`pup logs aggregate --query='service:testnet-v2-synthetic-tester @outcome:failed' --from='15m' --compute=count --group-by='@task'`
Expected: `internal-match-v2` / `external-match-v2` failures not increased.

---

## Self-Review

- **Spec coverage:** retry loop ✓ (Task 5), re-find each attempt ✓ (Task 5), typed `PreemptionConflict` ✓ (Tasks 2/4), classifier from storage constant ✓ (Task 1), bounded exp backoff + jitter < FILL_TIMEOUT ✓ (Task 3), log downgrade error→warn ✓ (Task 5), metric ✓ (Task 5), reject/queue semantics untouched ✓ (constraint stated; no task modifies the queue), unit tests for classifier + backoff ✓ (Tasks 1/3), testnet validation ✓ (Task 7).
- **Placeholder scan:** none — code shown for every code step; two `rg`-to-confirm notes are verification aids, not placeholders.
- **Type consistency:** `is_serial_preemption_conflict` (Task 1) used in Task 4; `MatchingEngineError::PreemptionConflict` (Task 2) matched in Tasks 4/5; `MAX_SETTLE_RETRIES` / `next_backoff` / `RETRY_BASE_DELAY` / `RETRY_MAX_DELAY` (Task 3) used in Task 5 and its test — names consistent.
- **Risk note:** the only uncertain API is `ProposalWaiter`'s await error type (Task 4 Step 1 note). If it isn't `StateError`, adjust the predicate there. Everything else is confirmed against the current code.
