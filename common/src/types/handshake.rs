//! Groups type definitions for handshake state objects used throughout the node

use constants::Scalar;
use crossbeam::channel::Sender;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{wallet::OrderIdentifier, TimestampedPrice};

/// The role in an MPC network setup; either Dialer or Listener depending on
/// which node initiates the connection
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ConnectionRole {
    /// Dials the peer, initiating the connection
    /// The dialer also plays the role of the king in the subsequent MPC
    /// computation
    Dialer,
    /// Listens for an inbound connection from the dialer
    Listener,
}

impl ConnectionRole {
    /// Get the party_id for an MPC dialed up through this connection
    pub fn get_party_id(&self) -> u64 {
        match self {
            // Party 0 dials party 1
            ConnectionRole::Dialer => 0,
            ConnectionRole::Listener => 1,
        }
    }
}

/// The state of a given handshake execution
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandshakeState {
    /// The request identifier of the handshake, used to uniquely identify a
    /// handshake correspondence between peers
    pub request_id: Uuid,
    /// The role of the local peer in the MPC, dialer is party 0, listener is
    /// party 1
    pub role: ConnectionRole,
    /// The identifier of the order that the remote peer has proposed for match
    pub peer_order_id: OrderIdentifier,
    /// The identifier of the order that the local peer has proposed for match
    pub local_order_id: OrderIdentifier,
    /// The public secret share nullifier of remote peer's order
    pub peer_share_nullifier: Scalar,
    /// The public secret share nullifier of the local peer's order
    pub local_share_nullifier: Scalar,
    /// The agreed upon price of the asset the local party intends to match on
    pub execution_price: TimestampedPrice,
    /// The current state information of the
    pub state: State,
    /// The cancel channel that the coordinator may use to cancel MPC execution
    #[serde(skip)]
    pub cancel_channel: Option<Sender<()>>,
}

/// A state enumeration for the valid states a handshake may take
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum State {
    /// The state entered into when order pair negotiation beings, i.e. the
    /// initial state This state is exited when either:
    ///     1. A pair of orders is successfully decided on to execute matches
    ///     2. No pair of unmatched orders is found
    OrderNegotiation,
    /// This state is entered when an order pair has been successfully
    /// negotiated, and the match computation has begun. This state is
    /// either exited by a successful match or an error
    MatchInProgress,
    /// This state signals that the handshake has completed successfully one way
    /// or another; either by successful match, or because no non-cached
    /// order pairs were found
    Completed,
    /// This state is entered if an error occurs somewhere throughout the
    /// handshake execution
    Error(String),
}

impl HandshakeState {
    /// Create a new handshake in the order negotiation state
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id: Uuid,
        role: ConnectionRole,
        peer_order_id: OrderIdentifier,
        local_order_id: OrderIdentifier,
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
            state: State::OrderNegotiation,
            cancel_channel: None,
        }
    }

    /// Transition the state to MatchInProgress
    pub fn in_progress(&mut self) {
        // Assert valid transition
        assert!(
            std::matches!(self.state, State::OrderNegotiation),
            "in_progress may only be called on a handshake in the `OrderNegotiation` state"
        );
        self.state = State::MatchInProgress;
    }

    /// Transition the state to Completed
    pub fn completed(&mut self) {
        // Assert valid transition
        assert!(
            std::matches!(self.state, State::OrderNegotiation { .. })
            || std::matches!(self.state, State::MatchInProgress { .. }),
            "completed may only be called on a handshake in OrderNegotiation or MatchInProgress state"
        );

        self.state = State::Completed;
    }

    /// Transition the state to Error
    pub fn error(&mut self, err: String) {
        self.state = State::Error(err);
    }
}

/// Handshake object mocks for testing
#[cfg(feature = "mocks")]
pub mod mocks {
    use constants::Scalar;
    use rand::thread_rng;
    use uuid::Uuid;

    use crate::types::TimestampedPrice;

    use super::{ConnectionRole, HandshakeState, State};

    /// Create a mock `HandshakeState` for testing purposes
    pub fn mock_handshake_state() -> HandshakeState {
        let mut rng = thread_rng();

        HandshakeState {
            request_id: Uuid::new_v4(),
            role: ConnectionRole::Dialer,
            peer_order_id: Uuid::new_v4(),
            local_order_id: Uuid::new_v4(),
            peer_share_nullifier: Scalar::random(&mut rng),
            local_share_nullifier: Scalar::random(&mut rng),
            execution_price: TimestampedPrice::new(10.),
            state: State::Completed,
            cancel_channel: None,
        }
    }
}
