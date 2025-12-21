//! Remote type shims for rkyv serialization

use std::marker::PhantomData;

use alloy_primitives::Address;
use ark_bn254::FrConfig;
use ark_ff::{BigInt, Fp, MontBackend};
use circuit_types::{
    fixed_point::FixedPoint,
    primitives::{baby_jubjub::BabyJubJubPoint, schnorr::SchnorrPublicKey},
};
use constants::Scalar;
use rkyv::{Archive, Deserialize, Serialize};

/// The number of u64 limbs which arkworks uses to represent an element of the
/// BN254 scalar field
const SCALAR_LIMBS: usize = 4;

// --- Address --- //

/// Remote type shim for `alloy_primitives::Address`
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
#[rkyv(derive(Debug), compare(PartialEq))]
#[rkyv(remote = alloy_primitives::Address)]
#[rkyv(archived = ArchivedAddress)]
pub struct AddressDef(pub [u8; 20]);

impl From<AddressDef> for Address {
    fn from(value: AddressDef) -> Self {
        Address::from(value.0)
    }
}

impl PartialEq<Address> for ArchivedAddress {
    fn eq(&self, other: &Address) -> bool {
        self.0 == other.0.0
    }
}

// --- Scalar --- //

// BigIntDef matches BigInt<4> structure
#[derive(Archive, Deserialize, Serialize)]
#[rkyv(remote = BigInt<SCALAR_LIMBS>)]
struct BigIntDef(pub [u64; SCALAR_LIMBS]);

impl From<BigIntDef> for BigInt<SCALAR_LIMBS> {
    fn from(value: BigIntDef) -> Self {
        BigInt(value.0)
    }
}

// ScalarFieldDef matches ScalarField (Fp<MontBackend<FrConfig, 4>, 4>)
// structure
#[derive(Archive, Deserialize, Serialize)]
#[rkyv(remote = Fp<MontBackend<FrConfig, SCALAR_LIMBS>, SCALAR_LIMBS>)]
struct ScalarFieldDef(
    #[rkyv(with = BigIntDef)] pub BigInt<SCALAR_LIMBS>,
    pub PhantomData<MontBackend<FrConfig, SCALAR_LIMBS>>,
);

impl From<ScalarFieldDef> for Fp<MontBackend<FrConfig, SCALAR_LIMBS>, SCALAR_LIMBS> {
    fn from(value: ScalarFieldDef) -> Self {
        Fp(value.0, value.1)
    }
}

/// Remote type shim for `constants::Scalar`
#[derive(Archive, Deserialize, Serialize)]
#[rkyv(remote = constants::Scalar)]
#[rkyv(archived = ArchivedScalar)]
pub struct ScalarDef(
    #[rkyv(with = ScalarFieldDef)] pub Fp<MontBackend<FrConfig, SCALAR_LIMBS>, SCALAR_LIMBS>,
);

impl From<ScalarDef> for Scalar {
    fn from(value: ScalarDef) -> Self {
        Scalar::new(value.0)
    }
}

impl From<Scalar> for ScalarDef {
    fn from(value: Scalar) -> Self {
        ScalarDef(value.0)
    }
}

impl PartialEq<Scalar> for ArchivedScalar {
    fn eq(&self, other: &Scalar) -> bool {
        self.0.0.0 == other.0.0.0
    }
}

// --- BabyJubJubPoint --- //

/// Remote type shim for
/// `circuit_types::primitives::baby_jubjub::BabyJubJubPoint`
#[derive(Archive, Deserialize, Serialize)]
#[rkyv(remote = BabyJubJubPoint)]
#[rkyv(archived = ArchivedBabyJubJubPoint)]
pub struct BabyJubJubPointDef {
    /// The x coordinate of the point
    #[rkyv(with = ScalarDef)]
    pub x: Scalar,
    /// The y coordinate of the point
    #[rkyv(with = ScalarDef)]
    pub y: Scalar,
}

impl From<BabyJubJubPointDef> for BabyJubJubPoint {
    fn from(value: BabyJubJubPointDef) -> Self {
        BabyJubJubPoint { x: value.x, y: value.y }
    }
}

impl PartialEq<BabyJubJubPoint> for ArchivedBabyJubJubPoint {
    fn eq(&self, other: &BabyJubJubPoint) -> bool {
        self.x == other.x && self.y == other.y
    }
}

// --- SchnorrPublicKey --- //

/// Remote type shim for `circuit_types::primitives::schnorr::SchnorrPublicKey`
#[derive(Archive, Deserialize, Serialize)]
#[rkyv(remote = SchnorrPublicKey)]
#[rkyv(archived = ArchivedSchnorrPublicKey)]
pub struct SchnorrPublicKeyDef {
    /// The curve point representing the public key
    #[rkyv(with = BabyJubJubPointDef)]
    pub point: BabyJubJubPoint,
}

impl From<SchnorrPublicKeyDef> for SchnorrPublicKey {
    fn from(value: SchnorrPublicKeyDef) -> Self {
        SchnorrPublicKey { point: value.point }
    }
}

impl PartialEq<SchnorrPublicKey> for ArchivedSchnorrPublicKey {
    fn eq(&self, other: &SchnorrPublicKey) -> bool {
        self.point == other.point
    }
}

// --- FixedPoint --- //

/// Remote type shim for `circuit_types::fixed_point::FixedPoint`
#[derive(Archive, Deserialize, Serialize)]
#[rkyv(remote = FixedPoint)]
#[rkyv(archived = ArchivedFixedPoint)]
pub struct FixedPointDef {
    /// The underlying scalar representing the fixed point variable
    #[rkyv(with = ScalarDef)]
    pub repr: Scalar,
}

impl From<FixedPointDef> for FixedPoint {
    fn from(value: FixedPointDef) -> Self {
        FixedPoint::from_repr(value.repr)
    }
}

impl PartialEq<FixedPoint> for ArchivedFixedPoint {
    fn eq(&self, other: &FixedPoint) -> bool {
        self.repr == other.repr
    }
}

#[cfg(test)]
mod tests {
    #![allow(unsafe_code)]

    use super::*;
    use rand::{RngCore, thread_rng};

    /// Test wrapper for Address to test rkyv serialization
    #[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
    struct AddressWrapper(#[rkyv(with = AddressDef)] Address);

    /// Test wrapper for Scalar to test rkyv serialization
    #[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
    struct ScalarWrapper(#[rkyv(with = ScalarDef)] Scalar);

    #[test]
    fn test_address_def_round_trip() {
        let mut rng = thread_rng();
        let mut address_bytes = [0u8; 20];
        rng.fill_bytes(&mut address_bytes);
        let original = AddressWrapper(Address::from(address_bytes));

        // Serialize
        let bytes =
            rkyv::to_bytes::<rkyv::rancor::Error>(&original).expect("Failed to serialize");

        // Deserialize
        let archived = unsafe { rkyv::access_unchecked::<ArchivedAddressWrapper>(&bytes) };
        let round_trip: AddressWrapper =
            rkyv::deserialize::<_, rkyv::rancor::Error>(archived).expect("Failed to deserialize");

        assert_eq!(original, round_trip);
    }

    #[test]
    fn test_scalar_def_round_trip() {
        let mut rng = thread_rng();
        let original = ScalarWrapper(Scalar::random(&mut rng));

        // Serialize
        let bytes =
            rkyv::to_bytes::<rkyv::rancor::Error>(&original).expect("Failed to serialize");

        // Deserialize
        let archived = unsafe { rkyv::access_unchecked::<ArchivedScalarWrapper>(&bytes) };
        let round_trip: ScalarWrapper =
            rkyv::deserialize::<_, rkyv::rancor::Error>(archived).expect("Failed to deserialize");

        assert_eq!(original, round_trip);
    }
}
