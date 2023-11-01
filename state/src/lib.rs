#![allow(incomplete_features)]
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![feature(generic_const_exprs)]
#![feature(let_chains)]

//! Groups state object definitions and handles logic for serializing access to
//! shared global state elements

#[cfg(feature = "mocks")]
pub mod mock;
mod orderbook;
pub mod peers;
mod priority;
#[allow(clippy::module_inception)]
pub mod state;
pub mod tui;
pub mod wallet;

pub use self::orderbook::NetworkOrderBook;
pub use self::state::*;
