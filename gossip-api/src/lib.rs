//! Defines API types for gossip within the p2p network

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

pub mod cluster_management;
pub mod gossip;
pub mod handshake;
pub mod heartbeat;
pub mod orderbook_management;
