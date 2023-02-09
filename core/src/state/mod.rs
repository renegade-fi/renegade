//! Groups state object definitions and handles logic for serializing access to shared
//! global state elements
#[allow(clippy::module_inception)]
mod state;
pub mod wallet;
pub use self::state::*;
