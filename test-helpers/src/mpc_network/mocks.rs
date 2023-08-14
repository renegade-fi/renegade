//! Mocks of various types used throughout the implementation of the MPC Network

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use async_trait::async_trait;

use futures::{Future, Sink, Stream};
use mpc_stark::{
    algebra::scalar::Scalar,
    beaver::SharedValueSource,
    error::MpcNetworkError,
    network::{MpcNetwork, NetworkOutbound, PartyId},
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
pub struct UnboundedDuplexStream<T> {
    /// The send side of the stream
    send: UnboundedSender<T>,
    /// The receive side of the stream
    recv: UnboundedReceiver<T>,
}

impl<T> UnboundedDuplexStream<T> {
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
    pub fn send(&mut self, msg: T) {
        self.send.send(msg).unwrap();
    }

    /// Recv a message from the stream
    pub async fn recv(&mut self) -> T {
        self.recv.recv().await.unwrap()
    }
}

/// A dummy network implementation used for unit testing
pub struct MockNetwork {
    /// The ID of the local party
    party_id: PartyId,
    /// The underlying mock network connection
    mock_conn: UnboundedDuplexStream<NetworkOutbound>,
}

impl MockNetwork {
    /// Create a new mock network from one half of a duplex stream
    pub fn new(party_id: PartyId, stream: UnboundedDuplexStream<NetworkOutbound>) -> Self {
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

    async fn close(&mut self) -> Result<(), MpcNetworkError> {
        Ok(())
    }
}

impl Stream for MockNetwork {
    type Item = Result<NetworkOutbound, MpcNetworkError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Box::pin(self.mock_conn.recv())
            .as_mut()
            .poll(cx)
            .map(|value| Some(Ok(value)))
    }
}

impl Sink<NetworkOutbound> for MockNetwork {
    type Error = MpcNetworkError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, item: NetworkOutbound) -> Result<(), Self::Error> {
        self.mock_conn.send(item);
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}
