//! Defines a state machine and tracking mechanism for in-flight handshakes
// TODO: Remove this lint allowance
#![allow(dead_code)]

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
};

use crate::state::{OrderIdentifier, RelayerState, Shared};

use super::error::HandshakeManagerError;
use crossbeam::channel::Sender;
use curve25519_dalek::scalar::Scalar;
use uuid::Uuid;

/// Holds state information for all in-flight handshake correspondences
///
/// Abstracts mostly over the concurrent access patterns used by the thread pool
/// of handshake executors
#[derive(Clone, Debug)]
pub struct HandshakeStateIndex {
    /// The underlying map of request identifiers to state machine instances
    state_map: Shared<HashMap<Uuid, HandshakeState>>,
    /// A mapping from nullifier to a set of request_ids on that nullifier
    nullifier_map: Shared<HashMap<Scalar, HashSet<Uuid>>>,
    /// A copy of the relayer global state
    global_state: RelayerState,
}

impl HandshakeStateIndex {
    /// Creates a new instance of the state index
    pub fn new(global_state: RelayerState) -> Self {
        Self {
            state_map: Arc::new(RwLock::new(HashMap::new())),
            nullifier_map: Arc::new(RwLock::new(HashMap::new())),
            global_state,
        }
    }

    // ----------------------------
    // | Index Management Methods |
    // ----------------------------

    /// Adds a new handshake to the state where the peer's order is already known (e.g. the peer initiated the handshake)
    #[allow(clippy::too_many_arguments)]
    pub fn new_handshake(
        &self,
        request_id: Uuid,
        peer_order_id: OrderIdentifier,
        local_order_id: OrderIdentifier,
    ) -> Result<(), HandshakeManagerError> {
        // Lookup the match nullifiers for the order
        let locked_order_book = self.global_state.read_order_book();
        let local_nullifier = locked_order_book
            .get_match_nullifier(&local_order_id)
            .ok_or_else(|| {
                HandshakeManagerError::StateNotFound(
                    "match nullifier not found for order".to_string(),
                )
            })?;
        let peer_nullifier = locked_order_book
            .get_match_nullifier(&peer_order_id)
            .ok_or_else(|| {
                HandshakeManagerError::StateNotFound(
                    "match nullifier not found for order".to_string(),
                )
            })?;

        // Index by request ID
        {
            let mut locked_state = self.state_map.write().expect("state_map lock poisoned");
            locked_state.insert(
                request_id,
                HandshakeState::new(
                    request_id,
                    peer_order_id,
                    local_order_id,
                    peer_nullifier,
                    local_nullifier,
                ),
            );
        } // locked_state released

        // Index by nullifier
        {
            let mut locked_nullifier_map = self
                .nullifier_map
                .write()
                .expect("nullifier_map lock poisoned");

            locked_nullifier_map
                .entry(local_nullifier)
                .or_default()
                .insert(request_id);
            locked_nullifier_map
                .entry(peer_nullifier)
                .or_default()
                .insert(request_id);
        } // locked_nullifier_map released

        Ok(())
    }

    /// Removes a handshake after processing is complete; either by match completion or error
    pub fn remove_handshake(&self, request_id: &Uuid) -> Option<HandshakeState> {
        // Remove from the state
        let state = {
            let mut locked_state = self.state_map.write().expect("state_map lock poisoned");
            locked_state.remove(request_id)
        }; // locked_state released

        // Remove from the nullifier index
        if let Some(state) = state.clone() {
            let mut locked_nullifier_map = self
                .nullifier_map
                .write()
                .expect("nullifier_map lock poisoned");

            if let Some(nullifier_set) = locked_nullifier_map.get_mut(&state.local_match_nullifier)
            {
                nullifier_set.remove(request_id);
            }

            if let Some(nullifier_set) = locked_nullifier_map.get_mut(&state.peer_match_nullifier) {
                nullifier_set.remove(request_id);
            }
        } // locked_nullifier_map released

        state
    }

    /// Shootdown all active handshakes on a given nullifier
    pub fn shootdown_nullifier(&self, nullifier: Scalar) -> Result<(), HandshakeManagerError> {
        let requests = {
            let mut locked_nullifier_map = self
                .nullifier_map
                .write()
                .expect("nullifier_map lock poisoned");

            locked_nullifier_map.remove(&nullifier).unwrap_or_default()
        }; // locked_nullifier_map released

        // For each request, remove the state entry for the request and send a cancel signal
        // over the request's cancel channel if one has already been allocated. The receiver
        // of this channel is the worker running in the MPC runtime
        for request in requests.iter() {
            if let Some(state) = self.remove_handshake(request)
            && let Some(channel) = state.cancel_channel
            {
                channel.send(())
                    .map_err(|err| HandshakeManagerError::SendMessage(err.to_string()))?;
            }
        }

        Ok(())
    }

    // --------------------
    // | State Transition |
    // --------------------

    /// Gets the state of the given handshake
    pub fn get_state(&self, request_id: &Uuid) -> Option<HandshakeState> {
        let locked_state = self.state_map.read().expect("state_map lock poisoned");
        locked_state.get(request_id).cloned()
    }

    /// Transition the given handshake into the MatchInProgress state
    pub fn in_progress(&self, request_id: &Uuid, cancel_channel: Sender<()>) {
        let mut locked_state = self.state_map.write().expect("state_map lock poisoned");
        if let Some(entry) = locked_state.get_mut(request_id) {
            entry.in_progress();
            entry.cancel_channel = Some(cancel_channel);
        }
    }

    /// Transition the given handshake into the Completed state
    pub fn completed(&self, request_id: &Uuid) {
        let mut locked_state = self.state_map.write().expect("state_map lock poisoned");
        if let Some(entry) = locked_state.get_mut(request_id) {
            entry.completed()
        }

        // For now, we simply remove the handshake from the state
        self.remove_handshake(request_id);
    }

    /// Transition the given handshake into the Error state
    pub fn error(&self, request_id: &Uuid, err: HandshakeManagerError) {
        let mut locked_state = self.state_map.write().expect("state_map lock poisoned");
        if let Some(entry) = locked_state.get_mut(request_id) {
            entry.error(err)
        }

        // For now we simply remove the handshake from the state
        self.remove_handshake(request_id);
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
    /// The match nullifier of remote peer's order
    pub peer_match_nullifier: Scalar,
    /// The match nullifier of the local peer's order
    pub local_match_nullifier: Scalar,
    /// The current state information of the
    pub state: State,
    /// The cancel channel that the coordinator may use to cancel MPC execution
    pub cancel_channel: Option<Sender<()>>,
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
        peer_match_nullifier: Scalar,
        local_match_nullifier: Scalar,
    ) -> Self {
        Self {
            request_id,
            peer_order_id,
            local_order_id,
            peer_match_nullifier,
            local_match_nullifier,
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
    pub fn error(&mut self, err: HandshakeManagerError) {
        self.state = State::Error(err);
    }
}
