//! The gossip module is responsible for interacting the gossip network at the
//! application layer

#![feature(let_chains)]
#![feature(generic_const_exprs)]
#![allow(incomplete_features)]

pub mod errors;
mod heartbeat;
mod orderbook;
pub mod server;
pub mod worker;
