//! Groups gadgets used in zero knowledge circuits
//!
//! Some gadgets are implemented in `mpc-jellyfish` so that they can be
//! implemented generically over provers. Gadgets in this module are built on
//! top of those low level gadgets defined in `mpc-jellyfish`.
//!
//! Some low level gadgets are defined here to provide MPC efficiency

// pub mod arithmetic;
pub mod bits;
// pub mod comparators;
// pub mod fixed_point;
pub mod merkle;
pub mod poseidon;
pub mod select;
pub mod wallet_operations;
