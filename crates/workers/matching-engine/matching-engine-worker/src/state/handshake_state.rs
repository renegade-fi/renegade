//! Defines the handshake state machine

use constants::Scalar;
use crossbeam::channel::Sender;
use types_account::account::OrderId;
use types_core::TimestampedPrice;
use types_gossip::ConnectionRole;
use uuid::Uuid;

/// The state of a handshake execution
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandshakeStatus {
    /// The handshake is pending execution
    Pending,
    /// The handshake match is in progress
    InProgress,
    /// The handshake has completed successfully
    Completed,
    /// The handshake encountered an error
    Error(String),
}

/// Holds state information for a single in-flight handshake
#[derive(Clone)]
pub struct HandshakeState {
    /// The unique identifier for this handshake request
    pub request_id: Uuid,
    /// The role of this peer in the handshake (Dialer or Listener)
    pub role: ConnectionRole,
    /// The order ID of the peer's order
    pub peer_order_id: OrderId,
    /// The order ID of the local order
    pub local_order_id: OrderId,
    /// The nullifier for the peer's share
    pub peer_share_nullifier: Scalar,
    /// The nullifier for the local share
    pub local_share_nullifier: Scalar,
    /// The execution price for the match
    pub execution_price: TimestampedPrice,
    /// The current status of the handshake
    pub status: HandshakeStatus,
    /// An optional channel to cancel the handshake execution
    pub cancel_channel: Option<Sender<()>>,
}

impl HandshakeState {
    /// Creates a new handshake state in the Pending status
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id: Uuid,
        role: ConnectionRole,
        peer_order_id: OrderId,
        local_order_id: OrderId,
        peer_share_nullifier: Scalar,
        local_share_nullifier: Scalar,
        execution_price: TimestampedPrice,
    ) -> Self {
        Self {
            request_id,
            role,
            peer_order_id,
            local_order_id,
            peer_share_nullifier,
            local_share_nullifier,
            execution_price,
            status: HandshakeStatus::Pending,
            cancel_channel: None,
        }
    }

    /// Transition the handshake into the InProgress state
    pub fn in_progress(&mut self) {
        self.status = HandshakeStatus::InProgress;
    }

    /// Transition the handshake into the Completed state
    pub fn completed(&mut self) {
        self.status = HandshakeStatus::Completed;
    }

    /// Transition the handshake into the Error state
    pub fn error(&mut self, error: String) {
        self.status = HandshakeStatus::Error(error);
    }
}
