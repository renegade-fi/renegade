//! Defines a state machine and tracking mechanism for in-flight handshakes

pub mod handshake_state;
pub mod index;

pub use handshake_state::{HandshakeState, HandshakeStatus};
pub use index::HandshakeStateIndex;
