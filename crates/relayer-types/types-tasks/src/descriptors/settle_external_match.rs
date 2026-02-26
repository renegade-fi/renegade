//! Descriptor for the settle external match task

use circuit_types::Amount;
use circuit_types::fixed_point::FixedPoint;
use darkpool_types::bounded_match_result::BoundedMatchResult;
#[cfg(feature = "rkyv")]
use darkpool_types::rkyv_remotes::FixedPointDef;
use types_account::OrderId;
use types_core::AccountId;

use super::TaskDescriptor;

/// The relayer fee rate fixed at external-match request time.
#[derive(Copy, Clone, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
pub struct ExternalRelayerFeeRate(
    #[cfg_attr(feature = "rkyv", rkyv(with = FixedPointDef))] FixedPoint,
);

impl ExternalRelayerFeeRate {
    /// Constructor.
    pub fn new(rate: FixedPoint) -> Self {
        Self(rate)
    }

    /// Get the wrapped fee rate value.
    pub fn rate(&self) -> FixedPoint {
        self.0
    }
}

impl From<FixedPoint> for ExternalRelayerFeeRate {
    fn from(value: FixedPoint) -> Self {
        Self::new(value)
    }
}

/// The task descriptor containing only the parameterization of the
/// `SettleExternalMatch` task
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
pub struct SettleExternalMatchTaskDescriptor {
    /// The account ID for the internal order
    pub account_id: AccountId,
    /// The ID of the internal order
    pub order_id: OrderId,
    /// The requested amount in, separate from the bounds on the match
    pub amount_in: Amount,
    /// The external-party relayer fee rate applied during matching
    pub external_relayer_fee_rate: ExternalRelayerFeeRate,
    /// The bounded match result
    pub match_result: BoundedMatchResult,
    /// The system bus topic on which to send the response
    pub response_topic: String,
    /// The number of blocks the match remains valid from the current block
    pub validity_window_blocks: u64,
}

impl From<SettleExternalMatchTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: SettleExternalMatchTaskDescriptor) -> Self {
        TaskDescriptor::SettleExternalMatch(descriptor)
    }
}
