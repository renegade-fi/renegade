//! Metrics registered with timers on the system clock that record various
//! "snapshots" of the system on an interval.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![deny(clippy::missing_docs_in_private_items)]
#![allow(async_fn_in_trait)]

pub mod raft_metrics_sampler;
pub mod sampler;
