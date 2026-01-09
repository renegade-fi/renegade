//! Price state concurrency primitive
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![allow(incomplete_features)]

pub mod error;
mod state;
pub mod util;
pub use state::*;

use types_core::{Exchange, Token};

/// A type alias for a stream tuple
pub type StreamTuple = (Exchange, Token, Token);
