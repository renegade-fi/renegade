#![feature(let_chains)]
#![allow(incomplete_features)]
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

//! Groups state object definitions and handles logic for serializing access to shared
//! global state elements
mod orderbook;
pub mod peers;
mod priority;
#[allow(clippy::module_inception)]
pub mod state;
pub mod tui;
pub mod wallet;

pub use self::orderbook::NetworkOrderBook;
pub use self::state::*;
