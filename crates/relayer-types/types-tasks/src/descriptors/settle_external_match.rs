//! Descriptor for the settle external match task

use darkpool_types::bounded_match_result::BoundedMatchResult;
use types_account::OrderId;
use types_core::AccountId;

use super::TaskDescriptor;

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
    /// The bounded match result
    pub match_result: BoundedMatchResult,
    /// The system bus topic on which to send the response
    pub response_topic: String,
}

impl From<SettleExternalMatchTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: SettleExternalMatchTaskDescriptor) -> Self {
        TaskDescriptor::SettleExternalMatch(descriptor)
    }
}
