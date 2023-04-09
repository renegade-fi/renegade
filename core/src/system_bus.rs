//! The system bus defines an embedded pubsub architecture in which
//! consumers may subscribe to a topic and producers may publish to the topics
//! with broadcast semantics
//!
//! The implementation of the bus is such that if there are no subscribers to
//! a given topic; a publish action is a no-op. Consequently, a new subscriber
//! will not see historical messages

// TODO: Remove this lint allowance
#![allow(dead_code)]

use bus::{Bus, BusReader};
use futures::Stream;
use std::{
    cell::RefCell,
    collections::HashMap,
    pin::Pin,
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc, RwLock, RwLockReadGuard, RwLockWriteGuard,
    },
    task::{Context, Poll, Waker},
};
use tokio::macros::support::poll_fn;

use crate::state::Shared;

/// The number of messages to buffer inside a single topic's bus
const BUS_BUFFER_SIZE: usize = 10;

/// A wrapper around `BusReader` that allows us to store topic-relevant information,
/// add reference counts, and build pollable methods around reading
///
/// The trait bounds on the message (Clone + Sync) are required by the Bus implementation
#[derive(Debug)]
pub struct TopicReader<M> {
    /// The name of the topic that this reader listens to
    topic_name: String,
    /// The underlying bus reader for the topic's bus
    reader: BusReader<M>,
    /// A buffered message; used when a call to has_next returns a value
    buffered_message: RefCell<Option<M>>,
    /// When the reader is dropped we decrement this value in the parent struct so that
    /// the topic may be deallocated if we are the last reader
    num_readers: Arc<AtomicU16>,
    /// The list of wakers on the given topic; the reader should add itself to the waker
    /// queue when it is polled and returns pending
    topic_wakers: Shared<Vec<Waker>>,
    /// A reference to the system bus's topic mesh; readers hold this reference so that they
    /// may deallocate the topic when dropped if they are the last reader on the topic
    topic_mesh: Shared<HashMap<String, Shared<TopicFabric<M>>>>,
}

impl<M> Unpin for TopicReader<M> {}

impl<M: Clone + Sync> TopicReader<M> {
    /// Construct a new reader for a topic
    pub fn new(
        topic_name: String,
        bus_reader: BusReader<M>,
        num_readers: Arc<AtomicU16>,
        topic_wakers: Shared<Vec<Waker>>,
        topic_mesh: Shared<HashMap<String, Shared<TopicFabric<M>>>>,
    ) -> Self {
        // Increment num_readers in the topic mesh now that the local thread is reading
        num_readers.fetch_add(1 /* val */, Ordering::Relaxed);
        Self {
            topic_name,
            reader: bus_reader,
            buffered_message: RefCell::new(None),
            num_readers,
            topic_wakers,
            topic_mesh,
        }
    }

    /// Check whether there is a message on the bus, does not block
    ///
    /// The bus primitive we use here does not support a `has_next` method;
    /// instead we can do a non-blocking attempted recv. If this returns a value
    /// we buffer it so that it can be consumed by the next call to `next_message`
    pub fn has_next(&mut self) -> bool {
        // If we've previously buffered a message
        if self.buffered_message.borrow().is_some() {
            return true;
        }

        // If we call `try_recv` and it returns a message; we must buffer that
        // message for the next call to `next_message`
        if let Ok(message) = self.reader.try_recv() {
            self.buffered_message.replace(Some(message));
            true
        } else {
            false
        }
    }

    /// Awaits the next message published onto the bus
    pub async fn next_message(&mut self) -> M {
        poll_fn(|ctx| self.poll_bus(ctx)).await
    }

    /// Poll the underlying bus, wrapped in `PollFn` to give an async interface
    /// to the reader
    fn poll_bus(&mut self, cx: &mut Context<'_>) -> Poll<M> {
        // If we have previously buffered a message for delivery; take ownership of
        // the message and leave `None` in its place
        if self.buffered_message.borrow().is_some() {
            return Poll::Ready(self.buffered_message.take().unwrap());
        }

        // Otherwise, poll the bus
        if let Ok(message) = self.reader.try_recv() {
            Poll::Ready(message)
        } else {
            // Add the local task waker to the list of waiting wakers for the topic
            let mut locked_topic_wakers = self
                .topic_wakers
                .write()
                .expect("topic_wakers lock poisoned");
            locked_topic_wakers.push(cx.waker().clone());

            Poll::Pending
        }
    }
}

impl<M: Clone + Sync> Stream for TopicReader<M> {
    type Item = M;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.poll_bus(cx).map(|message| Some(message))
    }
}

/// A reference counting `Drop` implementation for the reader; if the reader is the last
/// reader on a given topic, it should clean up the topic from the system bus's mesh
impl<M> Drop for TopicReader<M> {
    fn drop(&mut self) {
        // If there was only one reader (local thread) before this reader was dropped, deallocate the
        // topic in the pubsub mesh
        let prev_num_readers = self.num_readers.fetch_sub(1 /* val */, Ordering::Relaxed);
        if prev_num_readers == 1 {
            let mut locked_mesh = self.topic_mesh.write().expect("topic_mesh lock poisoned");

            // Ensure that no new subscriptions have come in since we acquired the lock
            // If so, abort the deallocation of the topic, otherwise zombie readers will
            // exist for the deallocated topic
            let new_num_readers = self.num_readers.load(Ordering::Relaxed);
            if new_num_readers > 0 {
                return;
            }

            locked_mesh.remove(&self.topic_name);
        } // locked_mesh released here
    }
}

/// An implementation of a single-producer, multi-consumer topic specific bus
#[derive(Debug)]
pub struct TopicFabric<M> {
    /// The name of the topic that this fabric is allocated for
    topic_name: String,
    /// The broadcast primitive underlying a shared bus
    bus: Bus<M>,
    /// The number of readers on the given topic
    num_readers: Arc<AtomicU16>,
    /// The wakers for the tasks that are actively waiting on the topic
    wakers: Shared<Vec<Waker>>,
    /// A reference to the parent mesh that this topic is stored in
    ///
    /// Topics store these references so that they may deallocate themselves
    /// when the last listener is dropped
    topic_mesh: Shared<HashMap<String, Shared<TopicFabric<M>>>>,
}

impl<M: Clone + Sync> TopicFabric<M> {
    /// Construct a new fabric for a registered topic
    pub fn new(
        topic_name: String,
        topic_mesh: Shared<HashMap<String, Shared<TopicFabric<M>>>>,
    ) -> Self {
        Self {
            topic_name,
            bus: Bus::new(BUS_BUFFER_SIZE),
            num_readers: Arc::new(AtomicU16::new(0 /* val */)),
            wakers: Arc::new(RwLock::new(Vec::new())),
            topic_mesh,
        }
    }

    /// Add a new reader to the fabric
    pub fn new_reader(&mut self) -> TopicReader<M> {
        TopicReader::new(
            self.topic_name.clone(),
            self.bus.add_rx(),
            self.num_readers.clone(),
            self.wakers.clone(),
            self.topic_mesh.clone(),
        )
    }

    /// Write a message onto the topic bus
    pub fn write_message(&mut self, message: M) {
        // Push the message onto the bus
        self.bus.broadcast(message);

        // Wake all the readers waiting on a message
        let mut locked_wakers = self.wakers.write().expect("wakers lock poisoned");
        for waker in locked_wakers.drain(0..) {
            waker.wake()
        }
    }

    /// Get the number of readers of the topic
    pub fn num_readers(&self) -> u16 {
        self.num_readers.load(Ordering::Relaxed)
    }
}

/// The system bus abstracts over an embedded pubsub functionality
///
/// Note that publishing to a topic with no subscribers is a no-op
#[derive(Clone, Debug)]
pub struct SystemBus<M> {
    /// The topic mesh connects publishers to subscribers, it is concretely implemented
    /// as a mapping from topic name (String) to a bus (single-producer, multi-consumer)
    topic_mesh: Shared<HashMap<String, Shared<TopicFabric<M>>>>,
}

impl<M: Clone + Sync> SystemBus<M> {
    /// Construct a new system bus
    pub fn new() -> Self {
        Self {
            topic_mesh: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Acquire a read lock on the topic mesh
    fn read_topic_mesh(&self) -> RwLockReadGuard<HashMap<String, Shared<TopicFabric<M>>>> {
        self.topic_mesh.read().expect("topic_mesh lock poisoned")
    }

    /// Acquire a write lock on the topic mesh
    fn write_topic_mesh(&self) -> RwLockWriteGuard<HashMap<String, Shared<TopicFabric<M>>>> {
        self.topic_mesh.write().expect("topic_mesh lock poisoned")
    }

    /// Publish a message onto a topic; blocks if the buffer is full
    pub fn publish(&self, topic: String, message: M) {
        let locked_mesh = self.read_topic_mesh();
        let topic_entry = locked_mesh.get(&topic);

        // If the topic is not registered, there are no listeners, short circuit
        if topic_entry.is_none() {
            return;
        }

        // Otherwise, lock the topic and push a message onto it
        let mut locked_topic = topic_entry
            .unwrap()
            .write()
            .expect("topic_entry lock poisoned");
        locked_topic.write_message(message);
    }

    /// Subscribe to a topic, returns a pollable future
    pub fn subscribe(&self, topic: String) -> TopicReader<M> {
        // If the topic is not yet registered, create one
        let contains_topic = { self.read_topic_mesh().contains_key(&topic) };
        if !contains_topic {
            let mut locked_mesh = self.write_topic_mesh();
            locked_mesh.insert(
                topic.clone(),
                Arc::new(RwLock::new(TopicFabric::new(
                    topic.clone(),
                    self.topic_mesh.clone(),
                ))),
            );
        } // locked_mesh released

        // Build a reader on the topic of interest and return it as a pollable to the subscriber
        let locked_mesh = self.read_topic_mesh();
        let mut locked_topic = locked_mesh
            .get(&topic)
            .unwrap()
            .write()
            .expect("topic_entry lock poisoned");

        locked_topic.new_reader()
    }

    /// Returns the number of listeners on a topic
    pub fn num_listeners(&self, topic: &String) -> u16 {
        if let Some(topic_entry) = self.read_topic_mesh().get(topic) {
            let locked_topic = topic_entry.write().expect("topic_entry lock poisoned");
            locked_topic.num_readers()
        } else {
            0
        }
    }

    /// Returns whether or not the given topic has been subscribed to by any readers
    ///
    /// This method is implemented mostly for testing purposes, i.e. to give us an idea of
    /// whether the topic is allocated in the underlying mesh
    pub fn has_listeners(&self, topic: &String) -> bool {
        self.read_topic_mesh().contains_key(topic)
    }
}

#[cfg(test)]
mod system_bus_tests {
    use rand::{thread_rng, RngCore};

    use super::SystemBus;

    const TEST_TOPIC: &str = "test topic";

    /// Tests a simple send and receive
    #[tokio::test]
    async fn test_send_recv() {
        let mut rng = thread_rng();
        let message = rng.next_u64();

        // Setup the pubsub mesh
        let pubsub = SystemBus::<u64>::new();
        let mut reader = pubsub.subscribe(TEST_TOPIC.to_string());

        // Publish a message
        pubsub.publish(TEST_TOPIC.to_string(), message);

        // Ensure that the message is consumed
        let res = reader.next_message().await;
        assert_eq!(res, message);
    }

    /// Tests the `has_next` method on the bus receiver
    #[tokio::test]
    async fn test_has_next() {
        let mut rng = thread_rng();
        let message1 = rng.next_u64();
        let message2 = rng.next_u64();

        // Setup pubsub mesh
        let pubsub = SystemBus::<u64>::new();
        let mut reader = pubsub.subscribe(TEST_TOPIC.to_string());

        // Publish a message
        pubsub.publish(TEST_TOPIC.to_string(), message1);
        pubsub.publish(TEST_TOPIC.to_string(), message2);

        // Ensure that has_next returns true and that the messages are appropriately delivered
        assert!(reader.has_next());
        assert_eq!(message1, reader.next_message().await);
        assert_eq!(message2, reader.next_message().await);
    }

    /// Tests that a reader joining after messages are sent *does not* receive old messages
    #[tokio::test]
    async fn test_subscribe_after_send() {
        let mut rng = thread_rng();
        let message1 = rng.next_u64();
        let message2 = rng.next_u64();

        // Setup pubsub mesh and send the first message before a reader is subscribed
        // we expect this to be a no-op
        let pubsub = SystemBus::<u64>::new();
        pubsub.publish(TEST_TOPIC.to_string(), message1);

        // Now subscribe a reader, send a second message and read from the bus
        // We expect *only* message2 to be delivered
        let mut reader = pubsub.subscribe(TEST_TOPIC.to_string());
        pubsub.publish(TEST_TOPIC.to_string(), message2);

        assert!(reader.has_next());
        assert_eq!(message2, reader.next_message().await);
        assert!(!reader.has_next());
    }

    /// Tests that multiple readers joining in between messages receive only the messages
    /// they were active for
    #[tokio::test]
    async fn test_readers_staggered_join() {
        let mut rng = thread_rng();
        let message1 = rng.next_u64();
        let message2 = rng.next_u64();

        // Setup the pubsub mesh and register the first reader before the first message
        // is sent. This reader should receive both message1 and message2
        let pubsub = SystemBus::<u64>::new();
        let mut reader1 = pubsub.subscribe(TEST_TOPIC.to_string());
        pubsub.publish(TEST_TOPIC.to_string(), message1);

        // Register a second reader after the message is published, then publish the
        // second message. We expect the second reader to receive *only* message2
        let mut reader2 = pubsub.subscribe(TEST_TOPIC.to_string());
        assert!(reader1.has_next());
        assert!(!reader2.has_next());

        pubsub.publish(TEST_TOPIC.to_string(), message2);

        assert_eq!(message1, reader1.next_message().await);
        assert_eq!(message2, reader1.next_message().await);
        assert_eq!(message2, reader2.next_message().await);
    }

    /// Tests the num_listeners method
    #[tokio::test]
    async fn test_num_listeners() {
        // Start out with no listeners
        let pubsub = SystemBus::<()>::new();
        assert_eq!(0, pubsub.num_listeners(&TEST_TOPIC.to_string()));

        let _reader1 = pubsub.subscribe(TEST_TOPIC.to_string());
        assert_eq!(1, pubsub.num_listeners(&TEST_TOPIC.to_string()));

        let _reader2 = pubsub.subscribe(TEST_TOPIC.to_string());
        assert_eq!(2, pubsub.num_listeners(&TEST_TOPIC.to_string()));
    }

    /// Tests that topics are deallocated from the pubsub mesh when the last reader is dropped
    #[tokio::test]
    async fn test_dealloc_topic() {
        // Setup the pubsub mesh; there are no listeners to any topic to begin, so `has_listeners`
        // should return false
        let pubsub = SystemBus::<u64>::new();
        assert!(!pubsub.has_listeners(&TEST_TOPIC.to_string()));

        // Add one reader, `has_listeners` should now be true
        let reader1 = pubsub.subscribe(TEST_TOPIC.to_string());
        assert!(pubsub.has_listeners(&TEST_TOPIC.to_string()));

        // Drop the reader, `has_listeners` should be false
        drop(reader1);
        assert!(!pubsub.has_listeners(&TEST_TOPIC.to_string()));

        // Add two readers, drop them one by one
        let reader2 = pubsub.subscribe(TEST_TOPIC.to_string());
        let reader3 = pubsub.subscribe(TEST_TOPIC.to_string());
        assert!(pubsub.has_listeners(&TEST_TOPIC.to_string()));

        drop(reader3);
        assert!(pubsub.has_listeners(&TEST_TOPIC.to_string()));

        // Drop the last reader, `has_listeners` should now be returning false
        drop(reader2);
        assert!(!pubsub.has_listeners(&TEST_TOPIC.to_string()));
    }
}
