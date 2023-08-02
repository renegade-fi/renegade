//! Mocks of various types used throughout the implementation of the MPC Network

use async_trait::async_trait;

use mpc_stark::{
    algebra::scalar::Scalar,
    beaver::SharedValueSource,
    error::MpcNetworkError,
    network::{MpcNetwork, NetworkOutbound, PartyId},
    PARTY0,
};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

/// The maximum message length in the mock network, used for debugging
pub const MAX_MESSAGE_LEN: u64 = 1_000_000;

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

/// An unbounded duplex channel used to mock a network connection
pub struct UnboundedDuplexStream {
    /// The send side of the stream
    send: UnboundedSender<NetworkOutbound>,
    /// The receive side of the stream
    recv: UnboundedReceiver<NetworkOutbound>,
}

impl UnboundedDuplexStream {
    /// Create a new pair of duplex streams
    pub fn new_duplex_pair() -> (Self, Self) {
        let (send1, recv1) = unbounded_channel();
        let (send2, recv2) = unbounded_channel();

        (
            Self {
                send: send1,
                recv: recv2,
            },
            Self {
                send: send2,
                recv: recv1,
            },
        )
    }

    /// Send a message on the stream
    pub fn send(&mut self, msg: NetworkOutbound) {
        self.send.send(msg).unwrap();
    }

    /// Recv a message from the stream
    pub async fn recv(&mut self) -> NetworkOutbound {
        self.recv.recv().await.unwrap()
    }
}

/// A dummy network implementation used for unit testing
pub struct MockNetwork {
    /// The ID of the local party
    party_id: PartyId,
    /// The underlying mock network connection
    mock_conn: UnboundedDuplexStream,
}

impl MockNetwork {
    /// Create a new mock network from one half of a duplex stream
    pub fn new(party_id: PartyId, stream: UnboundedDuplexStream) -> Self {
        Self {
            party_id,
            mock_conn: stream,
        }
    }
}

#[async_trait]
impl MpcNetwork for MockNetwork {
    fn party_id(&self) -> PartyId {
        self.party_id
    }

    async fn send_message(&mut self, message: NetworkOutbound) -> Result<(), MpcNetworkError> {
        self.mock_conn.send(message);
        Ok(())
    }

    async fn receive_message(&mut self) -> Result<NetworkOutbound, MpcNetworkError> {
        let msg = self.mock_conn.recv().await;
        Ok(msg)
    }

    async fn exchange_messages(
        &mut self,
        message: NetworkOutbound,
    ) -> Result<NetworkOutbound, MpcNetworkError> {
        if self.party_id() == PARTY0 {
            self.send_message(message).await?;
            self.receive_message().await
        } else {
            let res = self.receive_message().await?;
            self.send_message(message).await?;
            Ok(res)
        }
    }

    async fn close(&mut self) -> Result<(), MpcNetworkError> {
        Ok(())
    }
}
