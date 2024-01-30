//! Groups gossip error definitions

use std::fmt;

use state::error::StateError;

/// Defines an error for Gossip operation
#[derive(Clone, Debug)]
pub enum GossipError {
    /// An error resulting from a cancellation signal
    Cancelled(String),
    /// An error validating the proof link between `VALID COMMITMENTS` and
    /// `VALID REBLIND`
    CommitmentsReblindLinkVerification(String),
    /// An error occurred looking up a critical state element
    MissingState(String),
    /// A nullifier has already been used in the contract
    NullifierUsed(String),
    /// An error parsing a gossip message
    Parse(String),
    /// An error setting up the gossip server
    ServerSetup(String),
    /// An error forwarding a message to the network manager
    SendMessage(String),
    /// An error interacting with the global state
    State(String),
    /// An error occurred executing an Arbitrum RPC
    Arbitrum(String),
    /// Timer failed to send a heartbeat
    TimerFailed(String),
    /// An unhandled request type was received
    UnhandledRequest(String),
    /// An error verifying a peer's proof of `VALID COMMITMENTS`
    ValidCommitmentVerification(String),
    /// An error verifying a peer's proof of `VALID REBLIND`
    ValidReblindVerification(String),
}

impl fmt::Display for GossipError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<StateError> for GossipError {
    fn from(e: StateError) -> Self {
        Self::State(e.to_string())
    }
}
