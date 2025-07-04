//! The gossip module is responsible for interacting the gossip network at the
//! application layer

#![feature(let_chains)]
#![allow(incomplete_features)]

pub mod errors;
mod orderbook;
pub(crate) mod peer_discovery;
pub mod server;
pub mod worker;
