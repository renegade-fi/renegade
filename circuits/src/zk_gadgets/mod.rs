//! Groups gadgets used in zero knowledge circuits
//!
//! Some gadgets are implemented in `mpc-jellyfish` so that they can be
//! implemented generically over provers. Gadgets in this module are built on
//! top of those low level gadgets defined in `mpc-jellyfish`.
//!
//! Some low level gadgets are defined here to provide MPC efficiency

pub mod primitives;
pub mod state_gadgets;
pub mod state_primitives;

// Re-export for convenience
pub use primitives::*;
pub use state_gadgets::*;
pub use state_primitives::*;
