//! The system bus defines an embedded pubsub architecture in which
//! consumers may subscribe to a topic and producers may publish to the topics
//! with broadcast semantics
//!
//! The implementation of the bus is such that if there are no subscribers to
//! a given topic; a publish action is a no-op. Consequently, a new subscriber
//! will not see historical messages

use bus::{Bus, BusReader};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
};
use tokio::macros::support::poll_fn;

use crate::state::Shared;

/// The number of messages to buffer inside a single topic's bus
const BUS_BUFFER_SIZE: usize = 10;

/// A wrapper around `BusReader` that allows us to store topic-relevant information,
/// add reference counts, and build pollable methods around reading
#[derive(Debug)]
pub struct TopicReader<M> {
    /// The underlying bus reader for the topic's bus
    reader: BusReader<M>,
}

impl<M> TopicReader<M> {
    /// Construct a new reader for a topic
    pub fn new(bus_reader: BusReader<M>) -> Self {
        Self { reader: bus_reader }
    }
}

/// An implementation of a single-producer, multi-consumer topic specific bus
#[derive(Debug)]
pub struct TopicFabric<M> {
    /// The broadcast primitive underlying a shared bus
    bus: Bus<M>,
}

impl<M> TopicFabric<M> {
    /// Construct a new fabric for a registered topic
    pub fn new() -> Self {
        Self {
            bus: Bus::new(BUS_BUFFER_SIZE),
        }
    }

    /// Add a new reader to the fabric
    pub fn new_reader(&mut self) -> TopicReader<M> {
        TopicReader::new(self.bus.add_rx())
    }

    /// Write a message onto the topic bus
    pub fn write_message(&mut self, message: M) {
        self.bus.broadcast(message)
    }
}

/// The system bus abstracts over an embedded pubsub functionality
///
/// Note that publishing to a topic with no subscribers is a no-op
#[derive(Debug)]
pub struct SystemBus<M> {
    /// The topic mesh connects publishers to subscribers, it is concretely implemented
    /// as a mapping from topic name (String) to a bus (single-producer, multi-consumer)
    topic_mesh: Shared<HashMap<String, Shared<TopicFabric<M>>>>,
}

impl<M> SystemBus<M> {
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
        locked_topic.write_message(message)
    }

    /// Subscribe to a topic, returns a pollable future
    pub fn subscribe(&self, topic: String) {
        // If the topic is not yet registered, create one
        let contains_topic = { self.read_topic_mesh().contains_key(&topic) };
        if !contains_topic {
            let mut locked_mesh = self.write_topic_mesh();
            locked_mesh.insert(topic.clone(), Arc::new(RwLock::new(TopicFabric::new())));
        } // locked_mesh released

        // Build a reader on the topic of interest and return it as a pollable to the subscriber
        let locked_mesh = self.read_topic_mesh();
        let mut locked_topic = locked_mesh
            .get(&topic)
            .unwrap()
            .write()
            .expect("topic_entry lock poisoned");
        let reader = locked_topic.new_reader();
    }

    /// Returns whether or not the given topic has been subscribed to by any readers
    pub fn has_listeners(&self, topic: &String) -> bool {
        self.read_topic_mesh().contains_key(topic)
    }
}
