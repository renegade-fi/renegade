//! Mocks of various types used throughout the implementation of the MPC Network

use async_trait::async_trait;
use mpc_stark::{
    algebra::scalar::Scalar,
    beaver::SharedValueSource,
    error::MpcNetworkError,
    network::{MpcNetwork, NetworkOutbound, NetworkPayload, PartyId},
    PARTY0,
};

/// An implementation of a beaver value source that returns
/// beaver triples (0, 0, 0) for party 0 and (1, 1, 1) for party 1
#[derive(Clone, Debug)]
pub struct PartyIDBeaverSource {
    /// The ID of the local party
    party_id: u64,
}

impl PartyIDBeaverSource {
    /// Create a new beaver source given the local party_id
    pub fn new(party_id: u64) -> Self {
        Self { party_id }
    }
}

/// The PartyIDBeaverSource returns beaver triplets split statically between the
/// parties. We assume a = 2, b = 3 ==> c = 6. [a] = (1, 1); [b] = (3, 0) [c] = (2, 4)
impl SharedValueSource for PartyIDBeaverSource {
    fn next_shared_bit(&mut self) -> Scalar {
        // Simply output partyID, assume partyID \in {0, 1}
        assert!(self.party_id == 0 || self.party_id == 1);
        Scalar::from(self.party_id)
    }

    fn next_triplet(&mut self) -> (Scalar, Scalar, Scalar) {
        if self.party_id == 0 {
            (Scalar::from(1u64), Scalar::from(3u64), Scalar::from(2u64))
        } else {
            (Scalar::from(1u64), Scalar::from(0u64), Scalar::from(4u64))
        }
    }

    fn next_shared_inverse_pair(&mut self) -> (Scalar, Scalar) {
        (Scalar::from(self.party_id), Scalar::from(self.party_id))
    }

    fn next_shared_value(&mut self) -> Scalar {
        Scalar::from(self.party_id)
    }
}

/// A dummy network implementation used for unit testing
#[derive(Default)]
pub struct MockNetwork;

#[async_trait]
impl MpcNetwork for MockNetwork {
    fn party_id(&self) -> PartyId {
        PARTY0
    }

    async fn send_message(&mut self, _message: NetworkOutbound) -> Result<(), MpcNetworkError> {
        Ok(())
    }

    async fn receive_message(&mut self) -> Result<NetworkOutbound, MpcNetworkError> {
        Ok(NetworkOutbound {
            op_id: 0,
            payload: NetworkPayload::Scalar(Scalar::one()),
        })
    }

    async fn exchange_messages(
        &mut self,
        _message: NetworkOutbound,
    ) -> Result<NetworkOutbound, MpcNetworkError> {
        Ok(NetworkOutbound {
            op_id: 0,
            payload: NetworkPayload::Scalar(Scalar::one()),
        })
    }

    async fn close(&mut self) -> Result<(), MpcNetworkError> {
        Ok(())
    }
}
