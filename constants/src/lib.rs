//! Defines system-wide constants for node execution

#![deny(unsafe_code)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(missing_docs)]

use ark_ec::Group;
#[cfg(feature = "mpc-types")]
use ark_mpc::algebra::{
    AuthenticatedScalarResult, CurvePoint as GenericCurvePoint, Scalar as GenericScalar,
    ScalarResult as GenericScalarResult,
};
use jf_primitives::pcs::prelude::Commitment;
use mpc_plonk::proof_system::structs::Proof;

// -------------------------
// | System-Wide Constants |
// -------------------------

/// The system-wide value of MAX_BALANCES; the number of allowable balances a
/// wallet holds
pub const MAX_BALANCES: usize = 5;

/// The system-wide value of MAX_ORDERS; the number of allowable orders a wallet
/// holds
pub const MAX_ORDERS: usize = 5;

/// The system-wide value of MAX_FEES; the number of allowable fees a wallet
/// holds
pub const MAX_FEES: usize = 2;

/// The height of the Merkle state tree used by the contract
pub const MERKLE_HEIGHT: usize = 32;

/// The number of historical roots the contract stores as being valid
pub const MERKLE_ROOT_HISTORY_LENGTH: usize = 30;

// ------------------------------------
// | System Specific Type Definitions |
// ------------------------------------

/// The curve that our proof system operates over
pub type SystemCurve = ark_bn254::Bn254;

/// The curve group that our proof system operates over
pub type SystemCurveGroup = ark_bn254::G1Projective;

/// The scalar field the curve is defined over
pub type ScalarField = <ark_bn254::G1Projective as Group>::ScalarField;

/// The scalar type that the MPC is defined over    
#[cfg(feature = "mpc-types")]
pub type Scalar = GenericScalar<SystemCurveGroup>;

/// The scalar result type that the MPC is defined over
#[cfg(feature = "mpc-types")]
pub type ScalarResult = GenericScalarResult<SystemCurveGroup>;

/// The curve point type that the MPC is defined over
#[cfg(feature = "mpc-types")]
pub type CurvePoint = GenericCurvePoint<SystemCurveGroup>;

/// The authenticated scalar type that the MPC is defined over
#[cfg(feature = "mpc-types")]
pub type AuthenticatedScalar = AuthenticatedScalarResult<SystemCurveGroup>;

/// The (unbatched) proof type that the proof system generates
pub type SystemProof = Proof<SystemCurve>;

/// The polynomial commitment type that the proof system utilizes
pub type SystemCommitment = Commitment<SystemCurve>;

// ----------------------
// | Starknet Constants |
// ----------------------

/// The deployment block for the Mainnet contract
/// TODO: Update this once the contract is deployed
pub const MAINNET_CONTRACT_DEPLOYMENT_BLOCK: u64 = 780361;

/// The deployment block for the Goerli contract
pub const GOERLI_CONTRACT_DEPLOYMENT_BLOCK: u64 = 780361;

/// The deployment block for the devnet contract
pub const DEVNET_CONTRACT_DEPLOYMENT_BLOCK: u64 = 0;

// ----------------------
// | Pubsub Topic Names |
// ----------------------

/// The topic published to when the handshake manager begins a new
/// match computation with a peer
pub const HANDSHAKE_STATUS_TOPIC: &str = "handshakes";

/// The topic published to when a state change occurs on an order
pub const ORDER_STATE_CHANGE_TOPIC: &str = "order-state";
