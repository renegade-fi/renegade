//! Types for Baby JubJub curve points
#![allow(missing_docs)]

use ark_ec::{
    CurveGroup,
    twisted_edwards::{Projective, TECurveConfig},
};
use constants::{EmbeddedCurveConfig, EmbeddedCurveGroupAffine, Scalar};
use serde::{Deserialize, Serialize};

use crate::traits::BaseType;
use circuit_macros::circuit_type;

#[cfg(feature = "proof-system-types")]
use {
    crate::{
        Fabric,
        traits::{
            CircuitBaseType, CircuitVarType, MpcBaseType, MpcType, MultiproverCircuitBaseType,
            SecretShareBaseType, SecretShareType, SecretShareVarType,
        },
    },
    constants::{AuthenticatedScalar, ScalarField},
    mpc_relation::{Variable, gadgets::ecc::PointVariable, traits::Circuit},
    std::ops::Add,
};

/// The affine representation of a point on the BabyJubJub curve
#[cfg_attr(
    feature = "proof-system-types",
    circuit_type(serde, singleprover_circuit, secret_share, mpc, multiprover_circuit)
)]
#[cfg_attr(not(feature = "proof-system-types"), circuit_type(serde))]
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BabyJubJubPoint {
    /// The x coordinate of the point
    pub x: Scalar,
    /// The y coordinate of the point
    pub y: Scalar,
}

impl BabyJubJubPoint {
    /// Check that the point is on the curve
    pub fn is_on_curve(&self) -> bool {
        let affine = EmbeddedCurveGroupAffine::new_unchecked(self.x.inner(), self.y.inner());
        affine.is_on_curve()
    }
}

impl Default for BabyJubJubPoint {
    fn default() -> Self {
        // The group generator
        let generator = EmbeddedCurveConfig::GENERATOR;
        let x = Scalar::new(generator.x);
        let y = Scalar::new(generator.y);

        BabyJubJubPoint { x, y }
    }
}

impl From<Projective<EmbeddedCurveConfig>> for BabyJubJubPoint {
    fn from(value: Projective<EmbeddedCurveConfig>) -> Self {
        let affine = value.into_affine();
        BabyJubJubPoint { x: Scalar::new(affine.x), y: Scalar::new(affine.y) }
    }
}

impl From<BabyJubJubPoint> for Projective<EmbeddedCurveConfig> {
    fn from(value: BabyJubJubPoint) -> Self {
        let x = value.x.inner();
        let y = value.y.inner();

        Projective::from(EmbeddedCurveGroupAffine::new(x, y))
    }
}

#[cfg(feature = "proof-system-types")]
impl From<BabyJubJubPointVar> for PointVariable {
    fn from(value: BabyJubJubPointVar) -> Self {
        PointVariable(value.x, value.y)
    }
}

#[cfg(feature = "proof-system-types")]
impl From<PointVariable> for BabyJubJubPointVar {
    fn from(value: PointVariable) -> Self {
        BabyJubJubPointVar { x: value.0, y: value.1 }
    }
}
