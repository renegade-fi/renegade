//! Defines networking utilities

use std::net::SocketAddr;

use libp2p::{multiaddr::Protocol, Multiaddr};

/// Convert a libp2p multiaddr into a standard library socketaddr representation
pub fn multiaddr_to_socketaddr(addr: &Multiaddr, port: u16) -> Option<SocketAddr> {
    for protoc in addr.iter() {
        match protoc {
            Protocol::Ip4(ip4_addr) => return Some(SocketAddr::new(ip4_addr.into(), port)),
            Protocol::Ip6(ip6_addr) => return Some(SocketAddr::new(ip6_addr.into(), port)),
            _ => {},
        }
    }

    None
}

/// A wrapper around `is_dialable_addr` that first converts a `Multiaddr` into
/// a `SocketAddr`
pub fn is_dialable_multiaddr(addr: &Multiaddr, allow_local: bool) -> bool {
    match multiaddr_to_socketaddr(addr, 0 /* port */) {
        None => false,
        Some(socketaddr) => is_dialable_addr(&socketaddr, allow_local),
    }
}

/// Returns true if the given address is a dialable remote address
///
/// The `allow_local` flag allows the local node to dial peers on a local
/// network interface. This should be set to true if it is expected that more
/// than one node is running on a given interface.
pub fn is_dialable_addr(addr: &SocketAddr, allow_local: bool) -> bool {
    !addr.ip().is_unspecified() && // 0.0.0.0
    !addr.ip().is_benchmarking() &&
    (allow_local || !is_local_addr(addr)) // only allow local if configured
}

/// Returns true if the given address refers to a local address
pub fn is_local_addr(addr: &SocketAddr) -> bool {
    !addr.ip().is_global()
}

#[cfg(test)]
mod test {
    use libp2p::Multiaddr;

    use crate::networking::{is_local_addr, multiaddr_to_socketaddr};

    /// Tests the helper that determines whether a multiaddr is a local addr
    #[test]
    fn test_local_addr() {
        let addr_str =
            "/ip4/35.183.229.42/tcp/8000/p2p/12D3KooWS9m8drb9NFtZB6t3S8hnUeikyG96DupQ6EvMJ6c1ARWn";
        let addr_parsed: Multiaddr = addr_str.parse().unwrap();

        assert!(!is_local_addr(
            &multiaddr_to_socketaddr(&addr_parsed, 0 /* port */).unwrap()
        ))
    }
}
