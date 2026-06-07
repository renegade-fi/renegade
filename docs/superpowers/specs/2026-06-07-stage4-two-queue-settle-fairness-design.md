# Stage 4 — Two-queue settle fairness (anti-starvation)

Date: 2026-06-07
Status: design (pending approval to implement)
Crate: `state` (consensus-path; raft-replicated task-queue applicator)
Builds on: Stage 1 (`ENABLE_SETTLE_DEFER`), Stage 2 (`ENABLE_ORDER_YIELD`), Stage 3
(multi-pending FIFO). Companion analysis:
`2026-06-07-relayer-match-settlement-rethink.md`.

---

## 1. Problem

Measured (2h, both testnet chains): internal-match settlement fails **100%**
(`serial preemption deferred-queue full`), 0 fills; MM-resting-flow settles via
the **same** two-queue path (`SettleInternalMatch`, confirmed
`matching-engine-worker/.../internal_engine.rs:143-161`) so it is starved too.
External matches (single-queue) succeed at 100%. This is **starvation, not
saturation** — aggregate settle rate ~0.15/sec, ~10× under one wallet's ceiling.

### Root cause (exact)
A settle is a serial preemptive task over its affected account queues:
- `SettleExternalMatch` → **1** queue `[quoter]` (taker is off-chain).
- `SettleInternalMatch` / MM → **2** queues `[a, b]`, all-or-nothing.

In `preempt_queue_with_serial` (`storage.rs:461-539`) there is an **immediate
fast path** (`:485-497`): if no target queue is `hard_blocked` (each is
`is_serial_preemption_safe` or a within-budget yieldable head), the task
**preempts and runs now** — *without consulting the deferred FIFO*. Only the
blocked case falls through to defer (`:517-539`, append to each queue's
seq-ordered `PendingEntry` FIFO).

Consequence: when the shared quoter queue is momentarily free, an arriving
**single-queue** external settle takes the fast path and runs immediately —
**cutting ahead of a lower-seq two-queue settle already waiting in that queue's
FIFO** for its *other* queue to free. The two-queue settle only gets a chance on
a completion-hook drain (`run_unblocked_preemptions`, `task_queue.rs:428`) when
it is the lowest-seq head of **both** queues and both are safe — a window the
fast-path external settles keep stealing. The two-queue FIFO fills to
`MAX_PENDING_PER_QUEUE` (64) under the matcher's attempt flood and rejects
(`deferred-queue full`); waiters hit the quoter's 3s fill timeout. Net: 0 fills.

The FIFO already encodes fair order (global `seq`); the bug is that the
**immediate fast path bypasses it**.

---

## 2. Goal & non-goals

Goal: two-queue settles (internal + MM + real user↔quoter matches) are not
indefinitely starved by single-queue settles, **without fragmenting liquidity**
and **without weakening any settlement-correctness invariant**.

Non-goals: changing matchability (orders stay dual-book), lifting the per-wallet
~1.6/sec ceiling, fixing the single-signer scaling wall (separate, latent), or
reducing T.

---

## 3. Design

### 3.1 Core change — FIFO-order-respecting admission
Gate the immediate fast path on FIFO emptiness across the task's target queues.
In `preempt_queue_with_serial`, before the `if !hard_blocked` immediate branch,
add a precedence check:

```
let must_defer_for_fairness = settle_defer_enabled()
    && fairness_enabled()
    && queues.iter().any(|k| !self.get_pending_preempt_list(k)?.is_empty());
```

If `must_defer_for_fairness`, **skip the immediate path** and fall through to the
defer path (append to the FIFO with a fresh, higher `seq`). Rationale: `seq` is
monotonic, so any existing pending entry is strictly older; an arriving settle
that shares a queue with a waiting one must queue **behind** it. The fast path
then only fires in the **uncontended** case (no pending entries on any target
queue) — preserving today's low-latency common path.

This makes *every* settle that touches a contended queue flow through the single
seq-ordered FIFO, which `run_unblocked_preemptions` already drains in strict
seq order. A single-queue external settle deferred behind a lower-seq two-queue
settle on the quoter queue will not run until the two-queue settle runs — giving
the two-queue settle its window the moment its other queue frees.

### 3.2 Reverse-starvation bound (required)
If a two-queue settle's *other* queue stays busy a long time, naively holding all
later single-queue settles behind it would stall external throughput. Bound it
analogously to Stage-2's `MAX_CONSECUTIVE_YIELDS`:

- Track, per queue, a `head_pending_age` (drain-attempts or wall-ticks the
  current FIFO head has failed to run because a *non-shared* queue was busy).
- When the head's age exceeds `MAX_PENDING_HEAD_STALLS`, allow the next runnable
  single-queue settle behind it to bypass **once** (and reset the counter),
  so external flow makes progress while the stuck two-queue settle waits on its
  genuinely-busy counterparty.

This keeps fairness bidirectional: two-queue settles can't be starved by
single-queue ones, and a single stuck counterparty can't freeze the whole queue.
(Exact bound value TBD by test; start conservative, e.g. 3, matching Stage 2.)

### 3.3 Interaction with user-queue contention (assign-in/assign-out)
Internal matching assigns the user order into the quoter pool then back to global
(`internal_matching/matching.rs:369-393`) — two order-management tasks on the
**user** queue around the match. If one is the committed head when the settle
wants both queues, Stage-2 order-yield (`head_is_yieldable` + budget) should let
the settle preempt it. **Verify** assign/reassign descriptors are `is_yieldable()`
(`descriptors`), else the user queue blocks the two-queue settle independently of
3.1. If not yieldable, extend the yieldable set to cover order-pool assignment.
(This is a likely contributor to the current 100% failure and must be checked
during implementation.)

### 3.4 Companion (separate change, quoters crate) — matcher admission control
The matcher emits ~2507 attempts/2h for 0 fills, flooding the FIFO. Gate
`try_match_user_order` on observable quoter-queue pressure (e.g. skip if the
quoter's pending-FIFO depth is near `MAX_PENDING_PER_QUEUE`) so doomed attempts
don't saturate the FIFO. Reduces backpressure rejects; not the root fix. Tracked
separately; not part of this state-crate spec.

---

## 4. Invariants preserved

- I1 per-wallet serial settlement — unchanged (still one settle per queue head).
- I2 two-wallet atomic / all-or-nothing — unchanged (defer path is already
  all-or-nothing across target queues).
- Global `seq` total order over the FIFO — **strengthened** (now the *only* path
  for contended preemptions), keeping the multi-pending drain deadlock-free.
- No partial appends on reject (backpressure check stays before append).
- Feature-flagged: `fairness_enabled()` gate (`ENABLE_SETTLE_FAIRNESS`), default
  decided at rollout; off ⇒ exact current behavior.

## 5. Test plan

Use the matching-engine concurrency lab / `mock_state` (drive the applicator
directly; raft stalls ~16 concurrent — keep tests timeout-guarded).

1. **Regression of the bug:** committed-or-busy `b`; enqueue two-queue settle
   `[a,b]` (defers, seq=1); then single-queue settle `[a]` (seq=2). Free `b`.
   Assert the two-queue settle runs **before** the single-queue one. (Today the
   single-queue one would have run immediately on `a`.)
2. **Uncontended fast path intact:** no pending entries ⇒ single-queue settle
   still preempts immediately (no latency regression).
3. **Reverse-starvation bound:** keep the two-queue settle's other queue busy
   past `MAX_PENDING_HEAD_STALLS`; assert a later single-queue settle eventually
   bypasses once.
4. **All-or-nothing + deadlock-free:** existing
   `test_enqueue_preemptive__defer_two_queues_all_or_nothing` and the
   shared-key tests still pass.
5. **3.3:** assert a two-queue settle preempts a yieldable assign head on the
   user queue within budget.

## 6. Rollout & metrics

- Flag `ENABLE_SETTLE_FAIRNESS` (compile-time const like prior stages, or env).
- Stage on base-sepolia-v2 first (lower volume), watch:
  - `settle-internal-match` status: error→ok (target: fills > 0).
  - `deferred-queue full` rejects ↓.
  - quoter `Fill timeout` ↓, `fill detected` > 0.
  - `Settle External Match` rate/latency — must not regress materially (the
    fairness bound guards this).
- Then arb-sepolia-v2.

## 7. Open questions

Q1. Bound form for 3.2: attempt-count vs wall-clock age? (Attempt-count is
    deterministic across raft replicas — preferred; wall-clock is non-replicable.)
Q2. 3.3: are pool-assignment / reassignment descriptors already `is_yieldable()`?
    (Determines whether 3.1 alone suffices or we must extend the yieldable set.)
Q3. Default flag state for first deploy — off + targeted enable, or on?
Q4. Should single-queue external settles also be capped in *how many* can drain
    ahead per two-queue settle window, or is the head-precedence rule enough?
