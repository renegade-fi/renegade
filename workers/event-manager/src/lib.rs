//! The event manager is responsible for ingesting & exporting system events.
//!
//! These events can be generated from anywhere in the relayer, this worker
//! provides a centralized location for processing them.

#![allow(incomplete_features)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]

pub mod error;
pub mod worker;
