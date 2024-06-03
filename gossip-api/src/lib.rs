//! Defines API types for gossip within the p2p network

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use common::types::gossip::ClusterSymmetricKey;
use hmac::Mac;
use serde::Serialize;
use sha2::Sha256;
use tracing::instrument;
use util::telemetry::helpers::backfill_trace_field;

pub mod pubsub;
pub mod request_response;

/// Type alias for the hmac core implementation
pub type HmacSha256 = hmac::Hmac<Sha256>;

// -----------
// | Helpers |
// -----------

/// Sign a request body with the given key
#[instrument(name = "sign_message", skip_all, fields(req_size))]
pub fn create_hmac<M: Serialize>(req: &M, key: &ClusterSymmetricKey) -> Vec<u8> {
    let buf = bincode::serialize(req).unwrap();
    backfill_trace_field("req_size", buf.len());

    let mut hmac = HmacSha256::new_from_slice(key).expect("hmac can handle all slice lengths");
    hmac.update(&buf);
    let mac = hmac.finalize();

    mac.into_bytes().to_vec()
}

/// Check a signature on a request body with the given key
#[instrument(name = "check_signature", skip_all)]
pub fn check_hmac<M: Serialize>(req: &M, mac: &[u8], key: &ClusterSymmetricKey) -> bool {
    let expected = create_hmac(req, key);
    expected == mac
}

/// The destination to which a request should be sent
pub enum GossipDestination {
    /// To the gossip server
    GossipServer,
    /// To the handshake manager
    HandshakeManager,
    /// Directly handled in the network layer
    NetworkManager,
}

#[cfg(test)]
mod tests {
    use crate::request_response::{GossipRequest, GossipRequestType};

    use super::*;

    #[test]
    fn test_hmac() {
        const SIZE: usize = 10_000;
        let key = [20u8; 32];

        let body = vec![0u8; SIZE];
        let message = GossipRequest::new(GossipRequestType::Raft(body));
        let hmac = create_hmac(&message, &key);

        assert!(check_hmac(&message, &hmac, &key));
    }
}
