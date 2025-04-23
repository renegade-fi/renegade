//! Task state management

use std::fmt::Display;

use common::types::tasks::QueuedTaskState;
use serde::Serialize;

use crate::{
    tasks::{
        create_new_wallet::NewWalletTaskState, lookup_wallet::LookupWalletTaskState,
        node_startup::NodeStartupTaskState, pay_offline_fee::PayOfflineFeeTaskState,
        pay_relayer_fee::PayRelayerFeeTaskState, redeem_fee::RedeemFeeTaskState,
        refresh_wallet::RefreshWalletTaskState,
        settle_malleable_external_match::SettleMalleableMatchExternalTaskState,
        settle_match::SettleMatchTaskState, settle_match_external::SettleMatchExternalTaskState,
        settle_match_internal::SettleMatchInternalTaskState,
        update_merkle_proof::UpdateMerkleProofTaskState, update_wallet::UpdateWalletTaskState,
    },
    traits::TaskState,
};

// --------------------
// | State Management |
// --------------------

/// Defines a wrapper that allows state objects to be stored generically
#[derive(Clone, Debug, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(tag = "task_type", content = "state")]
pub enum StateWrapper {
    /// The state object for the lookup wallet task
    LookupWallet(LookupWalletTaskState),
    /// The state object for the refresh wallet task
    RefreshWallet(RefreshWalletTaskState),
    /// The state object for the new wallet task
    NewWallet(NewWalletTaskState),
    /// The state object for the pay protocol fee task
    PayOfflineFee(PayOfflineFeeTaskState),
    /// The state object for the pay relayer fee task
    PayRelayerFee(PayRelayerFeeTaskState),
    /// The state object for the redeem relayer fees task
    RedeemFee(RedeemFeeTaskState),
    /// The state object for the settle match task
    SettleMatch(SettleMatchTaskState),
    /// The state object for the settle match internal task
    SettleMatchInternal(SettleMatchInternalTaskState),
    /// The state object for the settle match external task
    SettleMatchExternal(SettleMatchExternalTaskState),
    /// The state object for the settle malleable match external task
    SettleMalleableMatchExternal(SettleMalleableMatchExternalTaskState),
    /// The state object for the update Merkle proof task
    UpdateMerkleProof(UpdateMerkleProofTaskState),
    /// The state object for the update wallet task
    UpdateWallet(UpdateWalletTaskState),
    /// The state object for the node startup task
    NodeStartup(NodeStartupTaskState),
}

impl StateWrapper {
    /// Whether the underlying state is committed or not
    pub fn committed(&self) -> bool {
        match self {
            StateWrapper::LookupWallet(state) => state.committed(),
            StateWrapper::RefreshWallet(state) => state.committed(),
            StateWrapper::NewWallet(state) => state.committed(),
            StateWrapper::PayOfflineFee(state) => state.committed(),
            StateWrapper::PayRelayerFee(state) => state.committed(),
            StateWrapper::RedeemFee(state) => state.committed(),
            StateWrapper::SettleMatch(state) => state.committed(),
            StateWrapper::SettleMatchInternal(state) => state.committed(),
            StateWrapper::SettleMatchExternal(state) => state.committed(),
            StateWrapper::SettleMalleableMatchExternal(state) => state.committed(),
            StateWrapper::UpdateWallet(state) => state.committed(),
            StateWrapper::UpdateMerkleProof(state) => state.committed(),
            StateWrapper::NodeStartup(state) => state.committed(),
        }
    }

    /// Whether or not this state commits the task, i.e. is the first state that
    /// for which `committed` is true
    pub fn is_committing(&self) -> bool {
        match self {
            StateWrapper::LookupWallet(state) => state == &LookupWalletTaskState::commit_point(),
            StateWrapper::RefreshWallet(state) => state == &RefreshWalletTaskState::commit_point(),
            StateWrapper::NewWallet(state) => state == &NewWalletTaskState::commit_point(),
            StateWrapper::PayOfflineFee(state) => state == &PayOfflineFeeTaskState::commit_point(),
            StateWrapper::PayRelayerFee(state) => state == &PayRelayerFeeTaskState::commit_point(),
            StateWrapper::RedeemFee(state) => state == &RedeemFeeTaskState::commit_point(),
            StateWrapper::SettleMatch(state) => state == &SettleMatchTaskState::commit_point(),
            StateWrapper::SettleMatchInternal(state) => {
                state == &SettleMatchInternalTaskState::commit_point()
            },
            StateWrapper::SettleMatchExternal(state) => {
                state == &SettleMatchExternalTaskState::commit_point()
            },
            StateWrapper::SettleMalleableMatchExternal(state) => {
                state == &SettleMalleableMatchExternalTaskState::commit_point()
            },
            StateWrapper::UpdateWallet(state) => state == &UpdateWalletTaskState::commit_point(),
            StateWrapper::UpdateMerkleProof(state) => {
                state == &UpdateMerkleProofTaskState::commit_point()
            },
            StateWrapper::NodeStartup(state) => state == &NodeStartupTaskState::commit_point(),
        }
    }

    /// Whether the underlying state is completed or not
    pub fn completed(&self) -> bool {
        match self {
            StateWrapper::LookupWallet(state) => state.completed(),
            StateWrapper::RefreshWallet(state) => state.completed(),
            StateWrapper::NewWallet(state) => state.completed(),
            StateWrapper::PayOfflineFee(state) => state.completed(),
            StateWrapper::PayRelayerFee(state) => state.completed(),
            StateWrapper::RedeemFee(state) => state.completed(),
            StateWrapper::SettleMatch(state) => state.completed(),
            StateWrapper::SettleMatchInternal(state) => state.completed(),
            StateWrapper::SettleMatchExternal(state) => state.completed(),
            StateWrapper::SettleMalleableMatchExternal(state) => state.completed(),
            StateWrapper::UpdateWallet(state) => state.completed(),
            StateWrapper::UpdateMerkleProof(state) => state.completed(),
            StateWrapper::NodeStartup(state) => state.completed(),
        }
    }
}

impl Display for StateWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let out = match self {
            StateWrapper::LookupWallet(state) => state.to_string(),
            StateWrapper::RefreshWallet(state) => state.to_string(),
            StateWrapper::NewWallet(state) => state.to_string(),
            StateWrapper::PayOfflineFee(state) => state.to_string(),
            StateWrapper::PayRelayerFee(state) => state.to_string(),
            StateWrapper::RedeemFee(state) => state.to_string(),
            StateWrapper::SettleMatch(state) => state.to_string(),
            StateWrapper::SettleMatchInternal(state) => state.to_string(),
            StateWrapper::SettleMatchExternal(state) => state.to_string(),
            StateWrapper::SettleMalleableMatchExternal(state) => state.to_string(),
            StateWrapper::UpdateWallet(state) => state.to_string(),
            StateWrapper::UpdateMerkleProof(state) => state.to_string(),
            StateWrapper::NodeStartup(state) => state.to_string(),
        };
        write!(f, "{out}")
    }
}

impl From<StateWrapper> for QueuedTaskState {
    fn from(value: StateWrapper) -> Self {
        // Serialize the state into a string
        let description = value.to_string();
        let committed = value.committed();
        QueuedTaskState::Running { state: description, committed }
    }
}
