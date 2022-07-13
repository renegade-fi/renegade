use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use libp2p::{Multiaddr, PeerId};

// Contains information about connected peers
#[derive(Debug)]
pub struct PeerInfo {
    // The identifier used by libp2p for a peer
    peer_id: PeerId,

    // The multiaddr of the peer
    addr: Multiaddr,

    // Last time a successful hearbeat was received from this peer
    last_heartbeat: AtomicU64
}

impl PeerInfo {
    pub fn new(
        peer_id: PeerId,
        addr: Multiaddr,
    ) -> Self {
        Self { 
            addr,
            peer_id,
            last_heartbeat: AtomicU64::new(current_time_seconds()), 
        }
    }

    // Getters and Setters
    pub fn get_peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn get_addr(&self) -> Multiaddr {
        self.addr.clone()
    }

    // Records a successful heartbeat
    pub fn successful_heartbeat(&mut self) {
        self.last_heartbeat.store(current_time_seconds(), Ordering::Relaxed);
    }

    pub fn get_last_heartbeat(&self) -> u64 {
        self.last_heartbeat.load(Ordering::Relaxed)
    }
}

// Clones PeerInfo to reference the curren time for the last heartbeat
impl Clone for PeerInfo {
    fn clone(&self) -> Self {
        Self { 
            peer_id: self.peer_id,
            addr: self.addr.clone(),
            last_heartbeat: AtomicU64::new(self.last_heartbeat.load(Ordering::Relaxed))
        } 
    }
}


/**
 * Helpers
 */

// Returns a u64 representing the current unix timestamp in seconds
fn current_time_seconds() -> u64 {
    SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("negative timestamp")
                .as_secs()
}
