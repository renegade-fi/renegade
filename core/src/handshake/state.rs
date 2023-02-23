//! Defines a state machine and tracking mechanism for in-flight handshakes
// TODO: Remove this lint allowance
#![allow(dead_code)]

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use crate::state::{OrderIdentifier, Shared};

use super::error::HandshakeManagerError;
use uuid::Uuid;

/// Holds state information for all in-flight handshake correspondences
///
/// Abstracts mostly over the concurrent access patterns used by the thread pool
/// of handshake executors
#[derive(Clone, Debug)]
pub struct HandshakeStateIndex {
    /// The underlying map of request identifiers to state machine instances
    state_map: Shared<HashMap<Uuid, HandshakeState>>,
}

impl HandshakeStateIndex {
    /// Creates a new instance of the state index
    pub fn new() -> Self {
        Self {
            state_map: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Adds a new handshake to the state where the peer's order is already known (e.g. the peer initiated the handshake)
    #[allow(clippy::too_many_arguments)]
    pub fn new_handshake(
        &self,
        request_id: Uuid,
        peer_order_id: OrderIdentifier,
        local_order_id: OrderIdentifier,
    ) {
        let mut locked_state = self.state_map.write().expect("state_map lock poisoned");
        locked_state.insert(
            request_id,
            HandshakeState::new(request_id, peer_order_id, local_order_id),
        );
    }

    /// Removes a handshake after processing is complete; either by match completion or error
    pub fn remove_handshake(&self, request_id: &Uuid) {
        let mut locked_state = self.state_map.write().expect("state_map lock poisoned");
        locked_state.remove(request_id);
    }

    /// Gets the state of the given handshake
    pub fn get_state(&self, request_id: &Uuid) -> Option<HandshakeState> {
        let locked_state = self.state_map.read().expect("state_map lock poisoned");
        locked_state.get(request_id).cloned()
    }

    /// Transition the given handshake into the MatchInProgress state
    pub fn in_progress(&self, request_id: &Uuid) {
        let mut locked_state = self.state_map.write().expect("state_map lock poisoned");
        if let Some(entry) = locked_state.get_mut(request_id) {
            entry.in_progress()
        }
    }

    /// Transition the given handshake into the Completed state
    pub fn completed(&self, request_id: &Uuid) {
        let mut locked_state = self.state_map.write().expect("state_map lock poisoned");
        if let Some(entry) = locked_state.get_mut(request_id) {
            entry.completed()
        }
    }

    /// Transition the given handshake into the Error state
    pub fn error(&self, request_id: &Uuid, err: HandshakeManagerError) {
        let mut locked_state = self.state_map.write().expect("state_map lock poisoned");
        if let Some(entry) = locked_state.get_mut(request_id) {
            entry.error(err)
        }
    }
}

/// The state of a given handshake execution
#[derive(Clone, Debug)]
pub struct HandshakeState {
    /// The request identifier of the handshake, used to uniquely identify a handshake
    /// correspondence between peers
    pub request_id: Uuid,
    /// The identifier of the order that the remote peer has proposed for match
    pub peer_order_id: OrderIdentifier,
    /// The identifier of the order that the local peer has proposed for match
    pub local_order_id: OrderIdentifier,
    /// The current state information of the
    pub state: State,
}

/// A state enumeration for the valid states a handshake may take
#[derive(Clone, Debug)]
pub enum State {
    /// The state entered into when order pair negotiation beings, i.e. the initial state
    /// This state is exited when either:
    ///     1. A pair of orders is successfully decided on to execute matches
    ///     2. No pair of unmatched orders is found
    OrderNegotiation,
    /// This state is entered when an order pair has been successfully negotiated, and the
    /// match computation has begun. This state is either exited by a successful match or
    /// an error
    MatchInProgress,
    /// This state signals that the handshake has completed successfully one way or another;
    /// either by successful match, or because no non-cached order pairs were found
    Completed,
    /// This state is entered if an error occurs somewhere throughout the handshake execution
    Error(HandshakeManagerError),
}

impl HandshakeState {
    /// Create a new handshake in the order negotiation state
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id: Uuid,
        peer_order_id: OrderIdentifier,
        local_order_id: OrderIdentifier,
    ) -> Self {
        Self {
            request_id,
            peer_order_id,
            local_order_id,
            state: State::OrderNegotiation,
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
    pub fn error(&mut self, err: HandshakeManagerError) {
        self.state = State::Error(err);
    }
}
