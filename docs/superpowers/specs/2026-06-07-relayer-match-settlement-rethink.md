# Relayer match & settlement architecture — analysis and rethink

Date: 2026-06-07
Status: analysis / pre-design (decisions pending)
Scope: how the v2 relayer handles MM, internal, and external matches; how to
minimise race conditions and maximise settlements at low latency without
fragmenting liquidity.

This document is evidence-backed: every structural claim cites relayer/contract
code (file:line) or 2-hour production telemetry (arbitrum-sepolia-v2,
base-sepolia-v2, gathered 2026-06-07).

---

## 0. Assumptions challenged (what the prior session got wrong)

1. **"Split internal vs external onto disjoint quoter accounts fixes the races."**
   WRONG — it fragments liquidity. A resting order with `allow_external_matches=true`
   is deliberately placed in **both** the pool-specific book (internal matching)
   and the all-pools book (external matching) — a dual-book design
   (`matching-engine-core/src/engine.rs:258-295`, order eligibility
   `types-account/src/account/order.rs:44-45,146-148`). Concurrent discovery is
   safe; on-chain settlement is atomic and first-to-commit wins; losers reconcile
   by amount. Unified internal+external matchability is the intended, safe model.
   The flow-split would prevent an external taker from ever hitting internal
   resting size and vice versa. **Scrap it.** (The config + matcher-filter changes
   drafted earlier this session must NOT ship.)

2. **"`NonceAlreadySpent` is a cross-flow concurrency race needing isolation."**
   WRONG. Ordinary multi-fill does not consume a per-fill owner nonce — it
   decrements `openPublicIntents[hash]` amount (`DarkpoolState.sol:194-205`).
   Nonces are spent on first-fill (owner sig), per-fill executor signatures, and
   revoke/cancel (`NativeSettledPublicIntent.sol:211,245`; `StateUpdatesLib.sol:151`).
   `NonceAlreadySpent` (0xb1389610, `DarkpoolState.sol:212`) on external buys is a
   **stale executor/quote signature resubmitted after its nonce was already
   spent** — a quote-lifecycle bug, not a steady concurrency race. Telemetry: **0
   occurrences in 2h** on either chain. Low priority.

3. **"Add more quoter accounts" is a clean, sufficient fix.**
   PARTIAL. More distinct wallets genuinely multiplies settlement throughput at
   the state layer (independent per-wallet commitment chains — confirmed
   `state/src/interface/task_queue.rs:319-359`). BUT (a) all settlement txs are
   signed by **one** relayer signer that submits serially (await-receipt), a latent
   global ceiling; and (b) more accounts fragments per-book resting depth. It helps
   *now* only because we are starvation-bound, not throughput-bound (see §3).

4. **"The per-account serial queue (~1.6/sec) is THE bottleneck."**
   It is real but not the binding one today. The sharper, measured bottleneck is
   the **internal two-queue all-or-nothing preemption being starved by single-queue
   external settles on the shared quoter wallet** (see §3.3-3.4). Current aggregate
   settle rate is ~0.15/sec/chain — ~10× under a single wallet's ceiling — yet
   **100% of internal settles fail.** That is starvation, not saturation.

---

## 1. Desired outcomes (what the relayer must achieve)

D1. **Maximise successful settlements/sec** across all three flows (internal, external, MM).
D2. **Low settlement latency** (match → on-chain commit), bounded tail.
D3. **All flows viable simultaneously** — unified liquidity, no fragmentation; one
    resting order serves internal and external takers.
D4. **Inter-flow fairness** — no flow may starve another. (Today external starves internal.)
D5. **Early shedding of doomed work** — do not spawn thousands of match attempts
    that cannot settle (today: 2507 attempts → 0 fills).
D6. **Books stay stocked under churn** — order placement/rebalance must not be
    starved by settlement (today: order placement times out → no-order-in-pool).
D7. **Capital efficiency** — inventory not stranded or needlessly fragmented.
D8. **Correctness preserved** — atomic two-wallet settlement, gap-free signer
    nonce sequence, single-spend of (signer,nonce), multi-fill amount accounting.

---

## 2. Invariants that must hold

I1. **Per-wallet serial settlement.** Each darkpool wallet is a commitment/nullifier
    chain: a settlement spends the current nullifier and produces a new commitment.
    At most one settlement per wallet may be in flight. Enforced by the per-account
    task queue keyed on `account_id` (`types-tasks/src/descriptors/mod.rs:169-184`).
    Fundamental — cannot be relaxed.

I2. **Two-wallet matches are atomic across both queues.** `SettleInternalMatch` and
    `SettlePrivateMatch` mutate two darkpool wallets, so they preempt **both**
    counterparty queues all-or-nothing (`descriptors/mod.rs:211-213`;
    `state/src/applicator/task_queue.rs` all-or-nothing test 639-700). The settle
    runs only when both queues are simultaneously preemption-safe.

I3. **External matches touch one darkpool wallet.** The taker is off-chain (no
    darkpool account), so `SettleExternalMatch` preempts only `[account_id]` (the
    quoter) — single-queue (`descriptors/mod.rs` affected_accounts).

I4. **Single signer, gap-free nonce.** All darkpool txs are signed by one key per
    relayer (`darkpool-client/src/client/mod.rs:100,125-130`), submitted with
    `with_simple_nonce_management()` and `send_tx` awaits the receipt
    (`mod.rs:185-236`). Nonces must be monotonic and gap-free per signer.

I5. **Multi-fill amount accounting.** A public intent's remaining size is the
    decremented `openPublicIntents[hash]` amount, not a one-shot flag.

I6. **Single-spend of (signer,nonce); stale bundles rejected pre-submit.** Re-using a
    spent nonce reverts `NonceAlreadySpent`. Stale signed quotes must be invalidated
    before submission (quote freshness).

I7. **First-commit-wins for concurrently-discovered matches; loser reconciles.** Dual
    discovery (internal + external) is safe because settlement is on-chain atomic
    and the relayer reconciles the resting amount post-settle.

---

## 3. Natural bottlenecks (ranked, with evidence)

### 3.1 Per-wallet serial settlement — fundamental, scales with #wallets
T ≈ 0.5s/settle (code: successful internal fills <600ms, p95 565ms,
`internal_matching/matching.rs:18-26`). Ceiling ≈ 1.6 settles/sec/wallet. The
deferred-FIFO `MAX_PENDING_PER_QUEUE=64` is explicitly "only headroom; the
underlying limit is per-account serial settlement throughput (1/T)"
(`storage.rs:127-135`). Disjoint wallets settle concurrently
(`interface/task_queue.rs:319-359`), so aggregate ≈ N_wallets × 1.6/sec at this
layer.

### 3.2 Single relayer signer + await-receipt — latent GLOBAL ceiling
One signer for all settlements; `send_tx` blocks on `get_receipt()`
(`darkpool-client/src/client/mod.rs:220-224`). Upper bound ≈ 1 tx per
block-time per relayer node if submission truly serialises.
**Not binding today:** measured external settle rate 1098/2h (arb), 942/2h
(base) ≈ 0.15/sec — ~10× below one wallet's ceiling, ~100× below multi-wallet
aggregate. It is the **scaling wall** that more-wallets will eventually hit, not
the current problem. (Open question: does `simple_nonce_management` let
concurrent sends pipeline, or does it serialise/collide? — see §6 Q4.)

### 3.3 Internal two-queue all-or-nothing preemption — THE current binding failure
An internal settle must preempt BOTH the user and quoter queues at once (I2).
Under load it cannot, the deferred FIFO saturates, and the settle is **rejected**:
- settle-internal-match status, 2h: **arb 1281/1281 error, base 200/200 error** —
  **100% failure.**
- dominant error: **`serial preemption deferred-queue full`**.
- consequence: match never settles → the quoter's 3s fill-waiter times out →
  **fill-timeouts arb 2028, base 690; fills detected: 0 / 0.**

### 3.4 External settles starve internal settles on the shared quoter wallet
External settles are single-queue (I3) and all succeed (status `info`, 0 errors:
arb 1098, base 942). They keep the shared quoter queue head busy/committed, so
the two-queue internal preemption (3.3) repeatedly fails the "both queues safe"
test and defers until the FIFO rejects. **The more external/RFQ flow, the worse
internal matching gets** — a structural unfairness (violates D4).

### 3.5 Per-account queue contention starves order management
Order placement/rebalance tasks share the quoter queue with settles and time out
("task timeout"), so the quoter's counter-order isn't in the pool when the matcher
looks: **no-order-in-pool arb 469, base 441.**

### 3.6 Matcher floods doomed attempts
2507 (arb) / 1131 (base) internal-match attempts in 2h for **0** fills. Each
doomed attempt still does 2 pool-assigns on the user queue + a (rejected)
two-queue settle preemption, amplifying queue load. The per-quoter circuit
breaker (`MatchBackoff`) is not preventing the flood.

---

## 4. The three consumers — rates & order-queue cost (2h, both chains)

Synthetic-tester drivers (2h, testnet-v2): test-runner 10980, rfqt-levels 1916,
rfqt-quote 1486, internal-match-v2 1308, external-match-v2 1149,
mm-resting-flow-v2 1105, split-brain 937.

| Consumer | Queue cost per settle | Attempts /2h (arb / base) | Successful settles /2h (arb / base) | Outcome |
|---|---|---|---|---|
| **Internal match** | **TWO-queue** (user+quoter), all-or-nothing | 2507 / 1131 | **0 / 0** | 100% `deferred-queue full` → fill-timeout (2028 / 690); no-order-in-pool (469 / 441) |
| **External match** | **ONE-queue** (quoter) | taker-driven (auth: assemble 368, quote 92, rfqt 1665 arb) | **1098 / 942** | succeeds, 0 errors, 0 `NonceAlreadySpent` |
| **MM resting** | path TBD (likely external single-queue) | mm-resting-flow-v2: 1105 | not separately isolable | needs §6 Q2 |
| *Order mgmt (quoter)* | single-queue per op | place 159, cancel 134 (arb) | n/a | times out under contention → no-order-in-pool |

Order-queue cost amplification: internal matching emitted ~2507×2 ≈ **5000
user-queue assign tasks + 1281 rejected quoter-queue preemptions for ZERO
settlements** (arb, 2h).

Bottom line: **external matching is the entire working settlement throughput;
internal matching is in total collapse, starved by the two-queue lock and by
external settles on the shared quoter wallet.**

---

## 5. Solution directions (NOT yet decided — see §6)

A. **Fix inter-flow fairness so two-queue internal settles aren't starved by
   single-queue external settles.** This is the highest-leverage change because
   it targets the measured 100% failure with no liquidity fragmentation. Possible
   forms: priority for two-queue preemptions; an admission rule that yields the
   quoter queue to a pending internal settle; reserving a scheduling slot for the
   harder preemption. (Needs design in the state crate's preemption logic.)

B. **Spread quoter inventory across more wallets per token** — reduces per-quoter
   queue contention so the two-queue lock can be satisfied. Helps now (we're
   starvation-bound). Caveats: latent signer ceiling (3.2), per-book depth
   fragmentation, provisioning cost. This is a mitigation, not a root fix.

C. **Shed doomed internal attempts earlier** — gate `try_match_user_order` on
   actual quoter-queue capacity / pending-FIFO depth before assign+wait, so the
   matcher stops emitting 2507 attempts for 0 fills (D5). Cheaper than B.

D. **Protect order management from settlement starvation** (D6) — so books stay
   stocked (addresses no-order-in-pool). May already be partly covered by Stage-2
   order-yield; verify it's effective.

E. **Quote freshness for external `NonceAlreadySpent`** (I6) — low priority (0/2h).

F. **Longer term: lift the global signer ceiling** (3.2) before #wallets makes it
   bind — pipelined submission or multiple signers, preserving I4.

Recommended sequence: **A (or C as a fast partial) first** — it attacks the
measured 100% internal-settle failure directly and preserves unified liquidity.
B as a parallel mitigation. F only when aggregate approaches the signer ceiling.

---

## 6. Open questions (for the morning)

Q1. Priority: is restoring **internal-match settlement** the goal (it's at 0%), or
    is the real product goal total settled volume (today carried entirely by
    external)? This decides whether we invest in A or just lean on external.

Q2. MM resting flow: does `mm-resting-flow-v2` settle via the external
    (single-queue) or internal (two-queue) path? (Determines whether MM is healthy
    or also starved.) I can trace this next.

Q3. For direction A (fairness), acceptable to change the **state crate preemption
    policy** to favour two-queue settles? That's core consensus-path code — higher
    review bar. Or prefer the cheaper matcher-side admission control (C) first?

Q4. The single signer (3.2): do you know whether settlement submission currently
    pipelines (concurrent sends, incrementing nonces) or serialises one-at-a-time?
    It determines how soon B hits a wall. I can verify empirically.

Q5. Capital: if we pursue B, how many wallets per token and how much total
    inventory are you willing to deploy on testnet vs. mainnet?
