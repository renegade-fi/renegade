//! In-process design + load-testing lab for the matching engine's concurrency
//! handling.
//!
//! The lab drives the **real** `state` serial-preemptive task queue (so the
//! contention under study is faithful) while mocking settlement execution
//! (on-chain submit, proofs, raft commit time) as a single tunable hold. This
//! lets us reproduce the quoter/MM settlement bottleneck and A/B alternative
//! settlement strategies without a deploy.
//!
//! See `renegade-map/tickets/2026-05-30-matching-engine-concurrency-lab/`.

pub mod backend;
pub mod harness;
pub mod ledger;
pub mod strategies;
pub mod strategy;

pub use backend::{Backend, BackendError, DirectApplicatorBackend, RaftBackend};
pub use ledger::MockBalanceLedger;
pub use strategy::{SettleOutcome, SettlementStrategy};
