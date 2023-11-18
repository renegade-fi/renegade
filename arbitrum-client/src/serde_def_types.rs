//! Types & trait implementations to enable deriving serde::{Serialize,
//! Deserialize} on the foreign Arkworks, Alloy, and other types that we compose
//! into complex structs.
//!
//! Follows the patterns laid out here:
//! https://serde.rs/remote-derive.html
//!
//! And here:
//! https://docs.rs/serde_with/3.4.0/serde_with/guide/serde_as/index.html#using-serde_as-with-serdes-remote-derives
//!
//! Mirrored from:
//! https://github.com/renegade-fi/renegade-contracts/blob/main/common/src/serde_def_types.rs

use alloy_primitives::{Address, FixedBytes, Uint};
use ark_bn254::{g1::Config as G1Config, FqConfig, FrConfig};
use ark_ec::short_weierstrass::Affine;
use ark_ff::{BigInt, Fp, FpConfig, MontBackend};
use constants::ScalarField;
use core::marker::PhantomData;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DeserializeAs, SerializeAs};

use crate::types::{G1Affine, G1BaseField};

/// Implement the `SerializeAs` and `DeserializeAs` traits for the given
/// definition type using its `Serialize` and `Deserialize` implementations so
/// that it can be de/serialized as the remote type.
macro_rules! impl_serde_as {
    ($remote_type:ty, $def_type:ty, $($generics:tt)*) => {
        impl<$($generics)*> SerializeAs<$remote_type> for $def_type {
            fn serialize_as<S>(source: &$remote_type, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                <$def_type>::serialize(source, serializer)
            }
        }

        impl<'de, $($generics)*> DeserializeAs<'de, $remote_type> for $def_type {
            fn deserialize_as<D>(deserializer: D) -> Result<$remote_type, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                <$def_type>::deserialize(deserializer)
            }
        }
    };
}

/// Serde type definition for [`BigInt`]
#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "BigInt")]
pub struct BigIntDef<const N: usize>(#[serde_as(as = "[_; N]")] pub [u64; N]);

impl_serde_as!(BigInt<N>, BigIntDef<N>, const N: usize);

/// Serde type definition for [`Fp`]
#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "Fp")]
pub struct FpDef<P: FpConfig<N>, const N: usize>(
    #[serde_as(as = "BigIntDef<N>")] pub BigInt<N>,
    pub PhantomData<P>,
);

impl_serde_as!(Fp<P, N>, FpDef<P, N>, P: FpConfig<N>, const N: usize);

/// Type alias for the serde type defition of [`ScalarField`]
pub type ScalarFieldDef = FpDef<MontBackend<FrConfig, 4>, 4>;
/// Type alias for the serde type defition of [`G1BaseField`]
pub(crate) type G1BaseFieldDef = FpDef<MontBackend<FqConfig, 4>, 4>;

/// Wrapper type for [`ScalarField`] that allows de/serializing
/// to/from [`ScalarField`] directly.
///
/// Follows the pattern laid out here:
/// https://serde.rs/remote-derive.html#invoking-the-remote-impl-directly
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct SerdeScalarField(#[serde_as(as = "ScalarFieldDef")] pub ScalarField);

/// Serde type definition for [`G1Affine`]
#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "Affine<G1Config>")]
pub(crate) struct G1AffineDef {
    #[doc(hidden)]
    #[serde_as(as = "G1BaseFieldDef")]
    x: G1BaseField,
    #[doc(hidden)]
    #[serde_as(as = "G1BaseFieldDef")]
    y: G1BaseField,
    #[doc(hidden)]
    infinity: bool,
}

impl_serde_as!(G1Affine, G1AffineDef,);

/// Serde type definition for [`FixedBytes`]
#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "FixedBytes")]
pub(crate) struct FixedBytesDef<const N: usize>(#[serde_as(as = "[_; N]")] pub [u8; N]);

impl_serde_as!(FixedBytes<N>, FixedBytesDef<N>, const N: usize);

/// Serde type definition for [`Address`]
#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "Address")]
pub(crate) struct AddressDef(#[serde_as(as = "FixedBytesDef<20>")] FixedBytes<20>);

impl_serde_as!(Address, AddressDef,);

/// Serde type definition for [`Uint`]
#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "Uint")]
pub(crate) struct UintDef<const BITS: usize, const LIMBS: usize> {
    #[doc(hidden)]
    #[serde_as(as = "[_; LIMBS]")]
    #[serde(getter = "Uint::as_limbs")]
    limbs: [u64; LIMBS],
}

impl<const BITS: usize, const LIMBS: usize> From<UintDef<BITS, LIMBS>> for Uint<BITS, LIMBS> {
    fn from(value: UintDef<BITS, LIMBS>) -> Self {
        Uint::from_limbs(value.limbs)
    }
}

impl_serde_as!(Uint<BITS, LIMBS>, UintDef<BITS, LIMBS>, const BITS: usize, const LIMBS: usize);

/// Type alias for the serde type defition of [`U256`]
pub(crate) type U256Def = UintDef<256, 4>;
