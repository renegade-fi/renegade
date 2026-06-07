# Path B — Self-heal orphaned `SerialPreemptionQueued` task queues

Date: 2026-06-07
Status: design → implement
Crate: `state` (consensus-path) + `task-driver` (NodeStartup hook)

## Problem

An account task queue can get permanently stuck in `preemption_state ==
SerialPreemptionQueued` with a committed preemptive (settle) task at
`serial_tasks[0]` that never completes. While in that state
`can_preempt_serial()` is `false`, so every new settle is rejected
`deferred-queue full` and **no settle ever runs** for that account. The state is
raft-persisted, so it survives restarts.

Observed in prod: internal-match quoter queues 100% wedged, 0 fills, 0 settle
completions, unchanged across 4 relayer restarts. External (single-queue,
different quoters) unaffected; cancel-flood already fixed.

### How a queue gets orphaned
A settle preempts the queue (`preempt_with_serial_task` → `SerialPreemptionQueued`,
head task assigned to the executing worker). The worker then **restarts and
rejoins with a NEW p2p node-id** (ephemeral worker identity — see
`raft.rs:35`). The committed head task is now assigned to a peer that is no
longer in the cluster, and nothing completes/pops it → the queue stays
`SerialPreemptionQueued` forever. `reassign_tasks` (fires on peer expiry,
`peer_index.rs:246`) reassigns the task but cannot safely *re-run* a committed
settle (re-running risks a double on-chain settle), so the queue stays wedged.

The intended recovery already exists but only for snapshot recovery:
`clear_account_task_queues` (`recovery.rs:87`) clears all queues "to prevent
accounts from being blocked on a task queue that failed." Normal restarts skip
it (intact raft log), so the wedge persists.

## Goal & non-goals

Goal: on relayer startup, automatically clear queues wedged in
`SerialPreemptionQueued` by an **orphaned** head task, so settlement recovers —
and so future relayer rolls can't permanently wedge a queue.

Non-goal: re-running orphaned committed settles (unsafe — could double-settle).
We *abort/clear* and let normal flow re-derive the match + reconcile wallet
state.

## Design

Add a startup reconciliation, run from NodeStartup's existing
`RunningStateMigrations` step (`node_startup.rs`):

`State::clear_orphaned_preempted_queues()` (new interface method):
1. Read the current raft membership peer set (voters + learners).
2. For each account id (`get_all_account_ids`):
   - If the queue's `preemption_state != SerialPreemptionQueued`, skip.
   - Get the head serial task and its assigned executor peer
     (`task_assignment` lookup).
   - **If the head's executor is still in membership, SKIP** — a live node may be
     legitimately mid-preemption; we must not disrupt it.
   - Else (executor orphaned / not in membership): `clear_task_queue(account)`
     via the existing raft **proposal**, and enqueue a `RefreshAccount` so the
     wallet's on-chain state is re-synced. Log the account + cleared task id.

### Safety argument
- **Cannot disrupt live work:** a queue is cleared only when its head task's
  executor is absent from current membership. A legitimately in-flight
  preemption has a live executor → skipped.
- **Cluster-consistent & durable:** clearing goes through `clear_task_queue`,
  which is a raft proposal (applies on every node via the log), not a local
  write — so it actually clears the replicated wedge.
- **Idempotent / safe to run on every node's startup:** clearing an
  already-clear queue is a no-op; redundant proposals from multiple nodes
  converge.
- **No double-settle:** we abort, never re-run, the orphaned committed settle.
  Wallet state is reconciled by the follow-up `RefreshAccount`; the match, if
  still valid, is re-derived by the matcher.

### Why NodeStartup
It already has a `RunningStateMigrations` startup hook and runs once per boot, so
every relayer roll reconciles wedges — closing the resilience gap that caused
this incident. It runs after the node has joined raft (membership available).

## Test plan (state crate, mock applicator)
1. **Clears orphaned wedge:** put a queue in `SerialPreemptionQueued` with a
   committed head assigned to a peer NOT in membership → reconcile → assert the
   queue is cleared (`preemption_state == NotPreempted`, empty) and a
   `RefreshAccount` was enqueued.
2. **Preserves live preemption:** same wedge but head assigned to a peer IN
   membership → reconcile → assert the queue is UNCHANGED.
3. **Ignores healthy queues:** `NotPreempted` queue with normal tasks →
   reconcile → unchanged.
4. After a clear, a fresh serial preemption succeeds (`can_preempt_serial` true).

## Rollout
- Land in the relayer image; deploy to sepolia-v2 first.
- Restart clears the existing wedge on boot; verify with
  `verify-internal-match.sh` (fills > 0, settle-internal errors → 0).
- Watch: no spurious clears of healthy accounts (log every clear with account +
  task id + orphaned-executor).

## Open question
- Membership read at startup: ensure it reflects the post-join peer set (run the
  reconcile in `RunningStateMigrations`, after `JoinRaft`/`InitializeRaft`). If
  membership is briefly empty/unstable at that point, the conservative skip
  (don't clear when executor "might" be live) means we under-clear rather than
  over-clear — acceptable; the next boot retries.
