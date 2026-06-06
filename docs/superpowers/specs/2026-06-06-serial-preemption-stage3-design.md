# Serial-Preemption Stage 3 — Multi-Pending FIFO + Quoter Retry

Date: 2026-06-06
Status: Design approved; implementation pending build/test verification.

## Problem

Internal matches (and MM resting matches) fail at settlement with:

```
state error: state transition rejected: serial preemption not allowed
```

This is raised by `preempt_queue_with_serial` in
`crates/state/src/storage/tx/task_queue/storage.rs`. The internal-match settle
task is a *serial preemptive* task that must preempt the task queues of the
accounts it settles against (both counterparties). Tracing the path:

1. A settle is **hard-blocked** when a target account queue's committed head
   cannot be preempted: it is not serial-preemption-safe (a committed task is
   running) **and** it is not a yieldable order task within the
   `MAX_CONSECUTIVE_YIELDS = 3` budget (Stage 2 order-yield).
2. **Stage 1 (defer-not-reject)** records *one* hard-blocked settle per queue as
   pending and re-runs it when the queue unblocks
   (`run_unblocked_preemptions`).
3. **The reject fires** at the one-pending-per-queue guard: if a settle is
   hard-blocked **and a target queue already holds a pending deferred settle**,
   the second settle is rejected (`storage.rs`, the
   `has_pending_preemption` check). The guard exists to bound buildup and to
   prevent the deadlock where two settles each wait on the other's queue.

Under real internal-match throughput (~5 settle attempts/sec), many settles
target the **same** quoter account (every WBTC match touches
`WBTC-quoter-0`'s account queue). They serialize: the first defers, every
concurrent one rejects → the quoter's 3s fill-await times out → match fails →
`internal-match-v2` at 0% pass. Stage 1/2 work as designed; they simply permit
only one in-flight deferred settle per account.

This is NOT the old match-lock or preemption-storm issue (both quiet), and it is
unmasked only after the matching pools exist (a separate fix). It is the
dominant blocker for internal/MM matches.

## Goals

- Allow more than one deferred settle per account queue so concurrent settles on
  a hot account succeed instead of rejecting.
- Preserve the two invariants the current guard protects:
  - **No deadlock** across settles that target overlapping queue sets.
  - **Bounded buildup** of pending settles.
- Preserve the apply-path invariants: **deterministic across raft nodes** and
  **panic-free** (an inconsistency must roll back the tx, never panic).
- Add a quoter-side retry so the rare residual rejection is handled gracefully.

## Non-Goals

- Changing the matching-engine match formation, proof generation, or the 3s
  fill-await timeout value.
- Reworking account-per-pair quoter topology (option C, considered and deferred).
- Touching the Stage 1 (`ENABLE_SETTLE_DEFER`) or Stage 2 (`ENABLE_ORDER_YIELD`)
  flags' semantics; Stage 3 builds on them.

## Design

### A — Multi-pending FIFO per queue (relayer state machine)

**Data model.** Replace the single per-queue pending slot
(`pending_preempt_task_key(queue) -> QueuedTask`,
`pending_preempt_keys_key(queue) -> Vec<TaskQueueKey>`) with an **ordered FIFO
list** per queue:

```
pending_preempt_list(queue) -> Vec<PendingEntry>
PendingEntry { task: QueuedTask, target_keys: Vec<TaskQueueKey>, seq: u64 }
```

Entries are ordered by `seq` ascending (FIFO). A bounded depth
`MAX_PENDING_PER_QUEUE` caps the list.

**Total ordering — the deadlock-safety core.** Each deferred settle is assigned
a monotonic `seq` from a counter persisted in the raft DB
(`pending_preempt_seq_counter`), incremented on enqueue. Because enqueues are
applied in committed-log order, `seq` is **deterministic and identical on every
node** (this is mandatory — `run_unblocked_preemptions` executes on the apply
path). A deferred settle is **eligible to run only when it is the head (lowest
`seq`) of *every* target queue's pending list AND every target queue is
serial-preemption-safe.** Because `seq` is a global total order, there is always
a unique lowest-`seq` settle that can make progress once its queues are safe →
the "two settles each waiting on the other's queue" deadlock is impossible. This
is what makes multi-pending safe where the one-slot guard was the previous
safeguard.

**Enqueue (`preempt_queue_with_serial`).** When hard-blocked and
`settle_defer_enabled()`:
- If any target queue's pending list is already at `MAX_PENDING_PER_QUEUE`,
  reject with `ERR_CANNOT_SERIALLY_PREEMPT` (backpressure — the only remaining
  reject path, now rare).
- Otherwise assign `seq` from the counter, append a `PendingEntry` to each
  target queue's list, return `PreemptOutcome::Deferred`.

The existing immediate paths (serial-preemption-safe, Stage 2 yield) are
unchanged.

**Completion hook (`run_unblocked_preemptions`).** On a queue unblock (pop path),
loop:
- Find the lowest-`seq` entry across the just-unblocked queue's list.
- If that entry is the head (lowest `seq`) of *all* its `target_keys` lists and
  all those queues are serial-preemption-safe, run the real preemption
  (`do_preempt_serial`), then remove that entry from every target queue's list.
- Repeat until no eligible entry remains. All-or-nothing preserved: if any target
  queue is not yet safe or not yet at the head, leave the entry to re-trigger on
  the next completion.

Self-heal (already present): if the settle task is already live, drop the stale
pending entry.

**Determinism & panic-freedom.** All ordering derives from committed state
(`seq` counter + list order). Any inconsistency returns a `StorageError::reject`
that rolls back the tx; no panics on the apply path.

**Touch.**
- `crates/state/src/storage/tx/task_queue/storage.rs`: data model
  (`PendingEntry`, list read/write/append/remove, seq counter), rewrite the
  enqueue tail of `preempt_queue_with_serial`, update `has_pending_preemption` /
  `get_pending_preemption` semantics (head-of-list), keep `delete_pending_preemption`
  semantics (remove a specific entry across its keys).
- `crates/state/src/applicator/task_queue.rs`: `run_unblocked_preemptions` loop.

### D — Quoter retry/backoff (quoters repo)

**Already implemented** by the existing `MatchBackoff` circuit breaker
(`quoters/src/server/quoter_context.rs`). On a settlement failure
(`serial preemption not allowed` or fill timeout) the breaker opens with
**exponential backoff + full jitter** (`record_failure`), so the contended
quoter is skipped for a backoff interval (`in_cooldown`, checked in
`select_and_lock_quoter`) and the user order re-attempts on a later cycle against
an available quoter — bounded, jittered retry without a tight loop. A success
resets it (`record_success`). With A draining the pending FIFO quickly, the first
short-backoff retry typically succeeds.

No new code is required for D: the breaker already provides exactly the
bounded-jittered-retry behavior, and adding a second retry path would duplicate
and fight the existing storm-avoidance design. (Verified by reading the code, not
just the spec.)

## Testing

A (unit tests in `crates/state/src/applicator/task_queue.rs` /
`storage/tx/task_queue`):
- N concurrent settles on one account all eventually run, in `seq` order.
- Cross-queue settles targeting overlapping sets ({A,B} and {B,C}) never
  deadlock and both eventually run.
- Depth cap: the `MAX_PENDING_PER_QUEUE + 1`-th settle on a saturated queue is
  rejected; earlier ones are not.
- Determinism: applying the same committed enqueue order on two state machines
  yields the same run order.
- `mock_state` raft concurrency harness (drive `StateApplicator` directly,
  timeout-guarded) for concurrent-proposal behavior.

D (quoter test):
- A settle that first rejects with the preemption error retries and succeeds
  after the blocking settle clears.

End-to-end (post-deploy): `internal-match-v2` and `mm-resting-flow-v2` synthetic
pass rates climb from 0%.

## Risk & verification

A modifies raft-applied state-machine logic — the highest-care area in the
codebase. The load-bearing invariants are (1) deterministic ordering across
nodes via the persisted `seq` counter and (2) panic-freedom on the apply path.
This environment cannot compile or run the relayer test suite, so before any
deploy: build the workspace, run the `task_queue` unit tests and the
`mock_state` raft harness, and review the diff. D similarly needs a quoter build.

## Rollout

1. Land + build + test A (relayer); build + test D (quoter).
2. Deploy relayer (workers via `tf apply` relayer-cluster; seed via stop-start —
   recovers from the persistent volume).
3. Deploy quoter (force-new-deployment).
4. Confirm `serial preemption not allowed` rejections drop and
   `internal-match-v2` / `mm-resting-flow-v2` pass rates rise.
