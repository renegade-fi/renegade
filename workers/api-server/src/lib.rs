//! Defines the server for the publicly facing API (both HTTP and websocket)
//! that the relayer exposes

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![allow(incomplete_features)]
#![feature(let_chains)]
#![feature(generic_const_exprs)]
#![feature(result_flattening)]

mod auth;
mod compliance;
pub mod error;
pub mod http;
mod router;
mod websocket;
pub mod worker;
