//! The closed vocabulary of operations the on-chain event listener performs,
//! for use with [`util::log_task!`].

use util::logging::LogTask;

/// The set of operations the on-chain event listener performs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Task {
    /// Lifecycle transitions of the listener (startup, shutdown, crash, stream
    /// end).
    ListenerLifecycle,
    /// Initializing the in-memory tracked owners cache from the database.
    InitTrackedOwners,
    /// Creating ERC20 transfer log subscriptions for tracked owners.
    CreateTransferSubscriptions,
    /// Creating Permit2 approval/permit log subscriptions for tracked owners.
    CreatePermit2Subscriptions,
    /// Refreshing subscriptions after the tracked owner set changes.
    RefreshSubscriptions,
    /// Handling an owner index change notification from the system bus.
    HandleOwnerIndexChange,
    /// Handling an ERC20 Transfer event.
    HandleTransferEvent,
    /// Handling a Permit2 Approval or Permit event.
    HandlePermit2Event,
    /// Handling a darkpool contract event before dispatch.
    HandleDarkpoolEvent,
    /// Handling a PublicIntentUpdated darkpool event.
    HandlePublicIntentUpdated,
    /// Handling a PublicIntentCancelled darkpool event.
    HandlePublicIntentCancelled,
}

impl LogTask for Task {
    fn as_str(&self) -> &'static str {
        match self {
            Task::ListenerLifecycle => "listener-lifecycle",
            Task::InitTrackedOwners => "init-tracked-owners",
            Task::CreateTransferSubscriptions => "create-transfer-subscriptions",
            Task::CreatePermit2Subscriptions => "create-permit2-subscriptions",
            Task::RefreshSubscriptions => "refresh-subscriptions",
            Task::HandleOwnerIndexChange => "handle-owner-index-change",
            Task::HandleTransferEvent => "handle-transfer-event",
            Task::HandlePermit2Event => "handle-permit2-event",
            Task::HandleDarkpoolEvent => "handle-darkpool-event",
            Task::HandlePublicIntentUpdated => "handle-public-intent-updated",
            Task::HandlePublicIntentCancelled => "handle-public-intent-cancelled",
        }
    }
}
