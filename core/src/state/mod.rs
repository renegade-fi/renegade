//! Groups state object definitions and handles logic for serializing access to shared
//! global state elements
pub mod peers;
#[allow(clippy::module_inception)]
mod state;
pub mod wallet;
pub use self::state::*;
