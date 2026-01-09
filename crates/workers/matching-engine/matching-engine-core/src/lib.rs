//! Core matching engine logic
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![deny(unsafe_code)]

pub(crate) mod book;
pub(crate) mod engine;
pub use engine::MatchingEngine;
