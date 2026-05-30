//! Deterministic correctness invariants for the lab's settlement
//! serialization, driven through the direct-applicator backend (no raft → fast
//! and reliable). These assert the *semantics*, not throughput, and hold
//! regardless of task interleaving — so they are reproducible, not flaky.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use futures::future::join_all;
use matching_engine_lab::{Backend, BackendError, DirectApplicatorBackend};
use types_core::AccountId;
use types_tasks::mocks::mock_task_descriptor;

/// INVARIANT (deterministic): a serial preemption excludes a second settlement
/// on the **same** account, but not on a **distinct** account, and the hold is
/// released on `pop`.
#[tokio::test]
async fn exclusion_is_per_account_and_releases() {
    let backend = DirectApplicatorBackend::new();
    let a = AccountId::new_v4();
    let b = AccountId::new_v4();

    let t1 = backend.enqueue_preemptive(mock_task_descriptor(a)).await.expect("admit A");
    // Same account is excluded while A is held...
    assert!(
        matches!(
            backend.enqueue_preemptive(mock_task_descriptor(a)).await,
            Err(BackendError::PreemptionConflict)
        ),
        "second preemption on a held account must be rejected"
    );
    // ...a distinct account is independent.
    let t2 = backend.enqueue_preemptive(mock_task_descriptor(b)).await.expect("admit distinct B");
    // Releasing A frees it for re-admission.
    backend.pop(t1).await;
    let t3 = backend.enqueue_preemptive(mock_task_descriptor(a)).await.expect("re-admit A after pop");

    backend.pop(t2).await;
    backend.pop(t3).await;
}

/// INVARIANT (under concurrency): the serial queue admits at most **one** holder
/// per account at any instant (mutual exclusion); every admitted settlement
/// **releases** (no leaked holds / deadlock); and **every offer resolves**
/// (settled or conflicted — conservation). Interleaving-independent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mutual_exclusion_and_no_leaks_under_concurrency() {
    const K: usize = 8; // distinct counterparty accounts
    const N: usize = 200; // concurrent offers

    let backend = Arc::new(DirectApplicatorBackend::new());
    let accounts: Vec<AccountId> = (0..K).map(|_| AccountId::new_v4()).collect();

    // Per-account concurrent-holder count; must never exceed 1.
    let holders: Arc<Mutex<HashMap<AccountId, usize>>> = Arc::new(Mutex::new(HashMap::new()));
    let violations: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    let tasks = (0..N).map(|i| {
        let backend = backend.clone();
        let holders = holders.clone();
        let violations = violations.clone();
        let acct = accounts[i % K];
        tokio::spawn(async move {
            match backend.enqueue_preemptive(mock_task_descriptor(acct)).await {
                Ok(tid) => {
                    // Admitted => exclusive holder. Mark and check.
                    {
                        let mut h = holders.lock().unwrap();
                        let c = h.entry(acct).or_insert(0);
                        *c += 1;
                        if *c > 1 {
                            violations
                                .lock()
                                .unwrap()
                                .push(format!("account {acct} had {c} concurrent holders"));
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(3)).await;
                    // Release: decrement BEFORE popping the state machine, so a
                    // concurrent enqueue still sees the account held in the SM.
                    {
                        let mut h = holders.lock().unwrap();
                        *h.get_mut(&acct).unwrap() -= 1;
                    }
                    backend.pop(tid).await;
                    true // settled
                },
                Err(BackendError::PreemptionConflict) => false, // conflicted
                Err(BackendError::Other(m)) => panic!("unexpected backend error: {m}"),
            }
        })
    });

    // Liveness: the whole run must complete (no deadlock).
    let joined = tokio::time::timeout(Duration::from_secs(20), join_all(tasks))
        .await
        .expect("invariant run should complete without deadlock");
    let outcomes: Vec<bool> = joined.into_iter().map(|r| r.unwrap()).collect();

    // Mutual exclusion held throughout.
    let v = violations.lock().unwrap();
    assert!(v.is_empty(), "mutual-exclusion violations: {v:?}");

    // Conservation: every offer resolved.
    assert_eq!(outcomes.len(), N, "every offer must resolve");

    // No leaked holds: every account is free now (a fresh enqueue succeeds).
    for acct in &accounts {
        let tid = backend
            .enqueue_preemptive(mock_task_descriptor(*acct))
            .await
            .unwrap_or_else(|e| panic!("account {acct} not free after run: {e:?}"));
        backend.pop(tid).await;
    }

    assert!(outcomes.iter().any(|s| *s), "some settlements should succeed");
}
