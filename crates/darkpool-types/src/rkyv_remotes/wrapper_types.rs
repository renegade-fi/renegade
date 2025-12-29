//! Wrapper types for rkyv serialization
//!
//! These wrapper types use the remote type shims via `#[rkyv(with = ...)]`
//! to satisfy the storage layer's `Value` trait requirements.

use alloy_primitives::Address;
use circuit_types::{fixed_point::FixedPoint, primitives::baby_jubjub::BabyJubJubPoint};
use rkyv::{Archive, Deserialize, Serialize};

use super::remote_types::{AddressDef, BabyJubJubPointDef, FixedPointDef};

// --- WrappedAddress --- //

/// A wrapper around `Address` that implements rkyv serialization
#[derive(Archive, Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(derive(Debug))]
pub struct WrappedAddress(#[rkyv(with = AddressDef)] pub Address);

impl WrappedAddress {
    /// Create a new WrappedAddress
    pub fn new(addr: Address) -> Self {
        Self(addr)
    }

    /// Get the underlying Address
    pub fn inner(&self) -> &Address {
        &self.0
    }
}

impl Default for WrappedAddress {
    fn default() -> Self {
        Self(Address::ZERO)
    }
}

impl std::ops::Deref for WrappedAddress {
    type Target = Address;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Address> for WrappedAddress {
    fn from(addr: Address) -> Self {
        Self(addr)
    }
}

impl From<WrappedAddress> for Address {
    fn from(wrapped: WrappedAddress) -> Self {
        wrapped.0
    }
}

// --- WrappedFixedPoint --- //

/// A wrapper around `FixedPoint` that implements rkyv serialization
#[derive(Archive, Deserialize, Serialize, Clone, Debug, PartialEq)]
#[rkyv(derive(Debug))]
pub struct WrappedFixedPoint(#[rkyv(with = FixedPointDef)] pub FixedPoint);

impl WrappedFixedPoint {
    /// Create a new WrappedFixedPoint
    pub fn new(fp: FixedPoint) -> Self {
        Self(fp)
    }

    /// Get the underlying FixedPoint
    pub fn inner(&self) -> &FixedPoint {
        &self.0
    }
}

impl Default for WrappedFixedPoint {
    fn default() -> Self {
        Self(FixedPoint::from_integer(0))
    }
}

impl std::ops::Deref for WrappedFixedPoint {
    type Target = FixedPoint;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<FixedPoint> for WrappedFixedPoint {
    fn from(fp: FixedPoint) -> Self {
        Self(fp)
    }
}

impl From<WrappedFixedPoint> for FixedPoint {
    fn from(wrapped: WrappedFixedPoint) -> Self {
        wrapped.0
    }
}

// --- WrappedBabyJubJubPoint --- //

/// A wrapper around `BabyJubJubPoint` that implements rkyv serialization
#[derive(Archive, Deserialize, Serialize, Clone, Debug, PartialEq)]
#[rkyv(derive(Debug))]
pub struct WrappedBabyJubJubPoint(#[rkyv(with = BabyJubJubPointDef)] pub BabyJubJubPoint);

impl WrappedBabyJubJubPoint {
    /// Create a new WrappedBabyJubJubPoint
    pub fn new(point: BabyJubJubPoint) -> Self {
        Self(point)
    }

    /// Get the underlying BabyJubJubPoint
    pub fn inner(&self) -> &BabyJubJubPoint {
        &self.0
    }
}

impl std::ops::Deref for WrappedBabyJubJubPoint {
    type Target = BabyJubJubPoint;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<BabyJubJubPoint> for WrappedBabyJubJubPoint {
    fn from(point: BabyJubJubPoint) -> Self {
        Self(point)
    }
}

impl From<WrappedBabyJubJubPoint> for BabyJubJubPoint {
    fn from(wrapped: WrappedBabyJubJubPoint) -> Self {
        wrapped.0
    }
}
