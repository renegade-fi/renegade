//! Descriptors for the match settlement tasks

use std::time::Duration;

use circuit_types::r#match::{BoundedMatchResult, MatchResult};
use serde::{Deserialize, Serialize};

use crate::types::{
    handshake::HandshakeState,
    proof_bundles::{MatchBundle, OrderValidityProofBundle, OrderValidityWitnessBundle},
    wallet::{OrderIdentifier, WalletIdentifier},
    TimestampedPrice,
};

use super::TaskDescriptor;

/// The task descriptor containing only the parameterization of the
/// `SettleMatchInternal` task
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettleMatchInternalTaskDescriptor {
    /// The price at which the match was executed
    pub execution_price: TimestampedPrice,
    /// The identifier of the first order
    pub order_id1: OrderIdentifier,
    /// The identifier of the second order
    pub order_id2: OrderIdentifier,
    /// The identifier of the first order's wallet
    pub wallet_id1: WalletIdentifier,
    /// The identifier of the second order's wallet
    pub wallet_id2: WalletIdentifier,
    /// The validity proofs for the first order
    pub order1_proof: OrderValidityProofBundle,
    /// The validity proof witness for the first order
    pub order1_validity_witness: OrderValidityWitnessBundle,
    /// The validity proofs for the second order
    pub order2_proof: OrderValidityProofBundle,
    /// The validity proof witness for the second order
    pub order2_validity_witness: OrderValidityWitnessBundle,
    /// The match result
    pub match_result: MatchResult,
}

impl SettleMatchInternalTaskDescriptor {
    /// Constructor
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        execution_price: TimestampedPrice,
        order_id1: OrderIdentifier,
        order_id2: OrderIdentifier,
        wallet_id1: WalletIdentifier,
        wallet_id2: WalletIdentifier,
        order1_proof: OrderValidityProofBundle,
        order1_validity_witness: OrderValidityWitnessBundle,
        order2_proof: OrderValidityProofBundle,
        order2_validity_witness: OrderValidityWitnessBundle,
        match_result: MatchResult,
    ) -> Result<Self, String> {
        Ok(SettleMatchInternalTaskDescriptor {
            execution_price,
            order_id1,
            order_id2,
            wallet_id1,
            wallet_id2,
            order1_proof,
            order1_validity_witness,
            order2_proof,
            order2_validity_witness,
            match_result,
        })
    }
}

impl From<SettleMatchInternalTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: SettleMatchInternalTaskDescriptor) -> Self {
        TaskDescriptor::SettleMatchInternal(descriptor)
    }
}

/// The task descriptor containing only the parameterization of the
/// `SettleExternalMatch` task
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettleExternalMatchTaskDescriptor {
    /// The duration for which the external match bundle is valid
    #[serde(default)]
    pub bundle_duration: Duration,
    /// The ID of the order that the local node matched
    pub internal_order_id: OrderIdentifier,
    /// The ID of the wallet that the local node matched an order from
    pub internal_wallet_id: WalletIdentifier,
    /// The price at which the match was executed
    pub execution_price: TimestampedPrice,
    /// The match result from the external matching engine
    pub match_res: MatchResult,
    /// The system bus topic on which to send the atomic match settle bundle
    pub atomic_match_bundle_topic: String,
}

impl SettleExternalMatchTaskDescriptor {
    /// Constructor
    pub fn new(
        bundle_duration: Duration,
        internal_order_id: OrderIdentifier,
        internal_wallet_id: WalletIdentifier,
        execution_price: TimestampedPrice,
        match_res: MatchResult,
        atomic_match_bundle_topic: String,
    ) -> Self {
        SettleExternalMatchTaskDescriptor {
            bundle_duration,
            internal_order_id,
            internal_wallet_id,
            atomic_match_bundle_topic,
            execution_price,
            match_res,
        }
    }
}

impl From<SettleExternalMatchTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: SettleExternalMatchTaskDescriptor) -> Self {
        TaskDescriptor::SettleExternalMatch(descriptor)
    }
}

/// The task descriptor parameterizing the `SettleMalleableExternalMatch` task
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettleMalleableExternalMatchTaskDescriptor {
    /// The duration for which the external match bundle is valid
    #[serde(default)]
    pub bundle_duration: Duration,
    /// The ID of the order that the local node matched
    pub internal_order_id: OrderIdentifier,
    /// The ID of the wallet that the local node matched an order from
    pub internal_wallet_id: WalletIdentifier,
    /// The match result from the external matching engine
    pub match_res: BoundedMatchResult,
    /// The system bus topic on which to send the atomic match settle bundle
    pub atomic_match_bundle_topic: String,
}

impl SettleMalleableExternalMatchTaskDescriptor {
    /// Constructor
    pub fn new(
        bundle_duration: Duration,
        internal_order_id: OrderIdentifier,
        internal_wallet_id: WalletIdentifier,
        match_res: BoundedMatchResult,
        atomic_match_bundle_topic: String,
    ) -> Self {
        SettleMalleableExternalMatchTaskDescriptor {
            bundle_duration,
            internal_order_id,
            internal_wallet_id,
            atomic_match_bundle_topic,
            match_res,
        }
    }
}

impl From<SettleMalleableExternalMatchTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: SettleMalleableExternalMatchTaskDescriptor) -> Self {
        TaskDescriptor::SettleMalleableExternalMatch(descriptor)
    }
}

/// The task descriptor containing only the parameterization of the
/// `SettleMatch` task
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettleMatchTaskDescriptor {
    /// The ID of the wallet that the local node matched an order from
    pub wallet_id: WalletIdentifier,
    /// The state entry from the handshake manager that parameterizes the
    /// match process
    pub handshake_state: HandshakeState,
    /// The match result from the matching engine
    pub match_res: MatchResult,
    /// The proof that comes from the collaborative match-settle process
    pub match_bundle: MatchBundle,
    /// The validity proofs submitted by the first party
    pub party0_validity_proof: OrderValidityProofBundle,
    /// The validity proofs submitted by the second party
    pub party1_validity_proof: OrderValidityProofBundle,
}

impl SettleMatchTaskDescriptor {
    /// Constructor
    pub fn new(
        wallet_id: WalletIdentifier,
        handshake_state: HandshakeState,
        match_res: MatchResult,
        match_bundle: MatchBundle,
        party0_validity_proof: OrderValidityProofBundle,
        party1_validity_proof: OrderValidityProofBundle,
    ) -> Result<Self, String> {
        Ok(SettleMatchTaskDescriptor {
            wallet_id,
            handshake_state,
            match_res,
            match_bundle,
            party0_validity_proof,
            party1_validity_proof,
        })
    }
}

impl From<SettleMatchTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: SettleMatchTaskDescriptor) -> Self {
        TaskDescriptor::SettleMatch(descriptor)
    }
}
