//! This crate defines the relayer's state machine and durable, consistent storage primitives
//!
//! We store our relayer state in an embedded database using `libmdbx` as the underlying storage
//! engine. The database is then replicated by a raft instance at higher layers in the application

pub mod storage;
