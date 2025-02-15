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

/// The current relayer version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
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

/// The system-wide value of MAX_BALANCES; the number of allowable balances a
/// wallet holds
pub const MAX_BALANCES: usize = 10;

/// The system-wide value of MAX_ORDERS; the number of allowable orders a wallet
/// holds
pub const MAX_ORDERS: usize = 4;

/// The height of the Merkle state tree used by the contract
pub const MERKLE_HEIGHT: usize = 32;

/// The number of historical roots the contract stores as being valid
pub const MERKLE_ROOT_HISTORY_LENGTH: usize = 30;

/// The external match fee charged by the relayer
///
/// TODO: This is currently zero, remove this and add per-asset fees
pub const EXTERNAL_MATCH_RELAYER_FEE: f64 = 0.;

// ------------------------------------
// | System Specific Type Definitions |
// ------------------------------------

/// The curve that our proof system operates over
pub type SystemCurve = ark_bn254::Bn254;

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

/// The deployment block for the Mainnet contract
/// TODO: Update this once the contract is deployed
pub const MAINNET_CONTRACT_DEPLOYMENT_BLOCK: u64 = 0;

/// The block number at which the darkpool was deployed on devnet
pub const DEVNET_DEPLOY_BLOCK: u64 = 0;

/// The block number at which the darkpool was deployed on testnet
pub const TESTNET_DEPLOY_BLOCK: u64 = 55713322;

/// The block number at which the darkpool was deployed on mainnet
pub const MAINNET_DEPLOY_BLOCK: u64 = 249416532;

/// The number of bytes in an Arbitrum address
pub const ADDRESS_BYTE_LENGTH: usize = 20;

/// The address used to represent the native asset (ETH) on Arbitrum
pub const NATIVE_ASSET_ADDRESS: &str = "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE";

/// The ticker of the native asset's wrapper token
pub const NATIVE_ASSET_WRAPPER_TICKER: &str = "WETH";

// ----------------------
// | Pubsub Topic Names |
// ----------------------

/// The topic published to when the handshake manager begins a new
/// match computation with a peer
pub const HANDSHAKE_STATUS_TOPIC: &str = "handshakes";

/// The topic published to when a state change occurs on an order
pub const ORDER_STATE_CHANGE_TOPIC: &str = "order-state";
