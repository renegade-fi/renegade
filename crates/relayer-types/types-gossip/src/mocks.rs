//! Mocks for peer info types

use std::{
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
};

use libp2p::Multiaddr;

use crate::{ClusterId, PeerInfo, WrappedPeerId};

/// Build a mock peer ID
pub fn mock_peer_id() -> WrappedPeerId {
    WrappedPeerId::random()
}

/// Build a mock peer's info
pub fn mock_peer() -> PeerInfo {
    // Build an RPC message to add a peer
    let cluster_id = ClusterId::from_str("1234").unwrap();
    let peer_id = mock_peer_id();
    let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let addr = Multiaddr::from(addr);

    PeerInfo::new(peer_id, cluster_id, addr.clone(), vec![] /* signature */)
}
