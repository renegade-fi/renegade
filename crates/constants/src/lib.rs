//! Defines system-wide constants for node execution

#![deny(unsafe_code)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(missing_docs)]

use std::sync::OnceLock;

use ark_ec::Group;
#[cfg(feature = "scalar")]
use ark_mpc::algebra::Scalar as GenericScalar;

#[cfg(feature = "mpc-types")]
use ark_mpc::algebra::{
    AuthenticatedScalarResult, CurvePoint as GenericCurvePoint,
    ScalarResult as GenericScalarResult, ScalarShare as GenericScalarShare,
};

// ---------------------------
// | Configuration Constants |
// ---------------------------

/// Whether or not the relayer is in bootstrap mode
pub static BOOTSTRAP_MODE: OnceLock<bool> = OnceLock::new();

/// Whether or not the relayer is in bootstrap mode
///
/// We default to false instead of erroring here to allow use of workers
/// _without_ setting this value. This is especially important outside of the
/// relayer repo
pub fn in_bootstrap_mode() -> bool {
    BOOTSTRAP_MODE.get().copied().unwrap_or(false)
}

/// Set the bootstrap mode
pub fn set_bootstrap_mode(mode: bool) {
    BOOTSTRAP_MODE
        .set(mode)
        .expect("BOOTSTRAP_MODE should not be initialized before calling set_bootstrap_mode()")
}

// -------------------------
// | System-Wide Constants |
// -------------------------

/// The maximum fee rate that may be charged by a relayer on a match
pub const MAX_RELAYER_FEE_RATE: f64 = 0.01; // 1%

/// The height of the Merkle state tree used by the contract
pub const MERKLE_HEIGHT: usize = 10;

/// The number of historical roots the contract stores as being valid
pub const MERKLE_ROOT_HISTORY_LENGTH: usize = 30;

/// The default fee take rate for the relayer in the match
pub const DEFAULT_EXTERNAL_MATCH_RELAYER_FEE: f64 = 0.0;

// ------------------------------------
// | System Specific Type Definitions |
// ------------------------------------

/// The curve that our proof system operates over
pub type SystemCurve = ark_bn254::Bn254;

/// The config of the system curve
pub type SystemCurveConfig = ark_bn254::Config;

/// The curve group that our proof system operates over
pub type SystemCurveGroup = ark_bn254::G1Projective;

/// The curve that may be embedded in the `SystemCurve`, i.e. a curve defined
/// over a base field the same size as the `SystemCurve`'s scalar field
pub type EmbeddedCurveGroup = ark_ed_on_bn254::EdwardsProjective;

/// The config of the embedded curve
pub type EmbeddedCurveConfig = ark_ed_on_bn254::EdwardsConfig;

/// The affine form of the embedded curve group
pub type EmbeddedCurveGroupAffine = ark_ed_on_bn254::EdwardsAffine;

/// The scalar field representing the curve group order
pub type ScalarField = <ark_bn254::G1Projective as Group>::ScalarField;

/// The scalar field of the embedded curve
pub type EmbeddedScalarField = ark_ed_on_bn254::Fr;

/// The scalar type that the MPC is defined over    
#[cfg(feature = "scalar")]
pub type Scalar = GenericScalar<SystemCurveGroup>;

/// The scalar share type that the MPC is defined over
#[cfg(feature = "mpc-types")]
pub type ScalarShare = GenericScalarShare<SystemCurveGroup>;

/// The scalar result type that the MPC is defined over
#[cfg(feature = "mpc-types")]
pub type ScalarResult = GenericScalarResult<SystemCurveGroup>;

/// The curve point type that the MPC is defined over
#[cfg(feature = "mpc-types")]
pub type CurvePoint = GenericCurvePoint<SystemCurveGroup>;

/// The authenticated scalar type that the MPC is defined over
#[cfg(feature = "mpc-types")]
pub type AuthenticatedScalar = AuthenticatedScalarResult<SystemCurveGroup>;

// ----------------------
// | Arbitrum Constants |
// ----------------------

/// The block number at which the darkpool was deployed on devnet
pub const DEVNET_DEPLOY_BLOCK: u64 = 0;

/// The block number at which the darkpool was deployed on Arbitrum Sepolia
pub const ARBITRUM_SEPOLIA_DEPLOY_BLOCK: u64 = 55713322;

/// The block number at which the darkpool was deployed on Arbitrum One
pub const ARBITRUM_ONE_DEPLOY_BLOCK: u64 = 249416532;

/// The block number at which the darkpool was deployed on Base Sepolia
// TODO: Fill in w/ correct value once deployed
pub const BASE_SEPOLIA_DEPLOY_BLOCK: u64 = 0; // Placeholder

/// The block number at which the darkpool was deployed on Base Mainnet
// TODO: Fill in w/ correct value once deployed
pub const BASE_MAINNET_DEPLOY_BLOCK: u64 = 0; // Placeholder
                                              //
/// The block number at which the darkpool was deployed on Ethereum Sepolia
pub const ETHEREUM_SEPOLIA_DEPLOY_BLOCK: u64 = 10144455; // Placeholder

/// The block number at which the darkpool was deployed on Ethereum Mainnet
// TODO: Fill in w/ correct value once deployed
pub const ETHEREUM_MAINNET_DEPLOY_BLOCK: u64 = 0; // Placeholder

/// The number of bytes in an Arbitrum address
pub const ADDRESS_BYTE_LENGTH: usize = 20;

/// The address used to represent the native asset (ETH) as an ERC20 address
pub const NATIVE_ASSET_ADDRESS: &str = "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE";

/// The ticker of the native asset's wrapper token
pub const NATIVE_ASSET_WRAPPER_TICKER: &str = "WETH";

/// The name of the global matching pool
pub const GLOBAL_MATCHING_POOL: &str = "global";
