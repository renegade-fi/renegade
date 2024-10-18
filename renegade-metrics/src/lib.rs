//! Defines metrics to track in the relayer, along with helpers for calculating
//! and recording them

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![deny(clippy::missing_docs_in_private_items)]

pub mod gauge;
pub mod global_metrics;
pub mod helpers;
pub mod labels;

pub use helpers::*;
