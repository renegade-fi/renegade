//! The handshake module handles performing MPC handshakes with peers

#![deny(unsafe_code)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![deny(missing_docs)]
#![allow(incomplete_features)]

pub mod error;
pub mod executor;
pub mod manager;
pub mod worker;
