//! Price state concurrency primitive
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![allow(incomplete_features)]
#![feature(let_chains)]

mod state;
pub mod util;
pub use state::*;

use common::types::{exchange::Exchange, token::Token};

/// A type alias for a stream tuple
pub type StreamTuple = (Exchange, Token, Token);
