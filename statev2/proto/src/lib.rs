#[deny(missing_docs)]
#[deny(clippy::missing_docs_in_private_items)]
#[deny(unsafe_code)]

/// Protobuf definitions for state transitions
mod protos {
    include!(concat!(env!("OUT_DIR"), "/state_transitions.rs"));
}

pub use protos::*;

#[cfg(test)]
mod tests {
    use super::NewPeer;
    use prost::Message;

    /// Tests the add new peer message
    #[test]
    fn test_new_peer_serialization() {
        let msg = NewPeer {
            peer_id: "test".to_string(),
        };

        let bytes = msg.encode_to_vec();
        let recovered: NewPeer = NewPeer::decode(bytes.as_slice()).unwrap();

        assert_eq!(msg, recovered);
    }
}
