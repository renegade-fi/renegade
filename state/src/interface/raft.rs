//! State interface methods for modifying the raft config state

use common::types::gossip::WrappedPeerId;

use crate::{
    error::StateError, notifications::ProposalWaiter,
    replication::network::address_translation::PeerIdTranslationMap, State, StateTransition,
};

impl State {
    // -----------
    // | Setters |
    // -----------

    /// Add a raft peer as a learner to the local cluster
    pub fn add_raft_learner(&self, peer_id: WrappedPeerId) -> Result<ProposalWaiter, StateError> {
        // Add the peer ID to the translation map
        let mut locked_map = self.translation_map.write().expect("translation map poisoned");
        locked_map.insert(peer_id);
        let raft_id = PeerIdTranslationMap::get_raft_id(&peer_id);
        drop(locked_map); // Unlock the map

        let transition = StateTransition::AddRaftLearner { peer_id: raft_id };
        self.send_proposal(transition)
    }
}
