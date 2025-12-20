//! Defines types for concurrency primitives

use std::sync::{Arc, LazyLock, RwLock};
use tokio::sync::RwLock as TokioRwLock;

/// A type alias for a shared, concurrency safe, mutable pointer
pub type Shared<T> = Arc<RwLock<T>>;
/// A type alias for a shared, concurrency safe, mutable pointer in an
/// async context
pub type AsyncShared<T> = Arc<TokioRwLock<T>>;
/// A type alias representing an `RwLock` wrapped in a `LazyLock`,
/// allowing for it to be used as a primitive for mutable static variables
pub type RwStatic<T> = LazyLock<RwLock<T>>;

/// Wrap an abstract value in a shared lock
pub fn new_shared<T>(wrapped: T) -> Shared<T> {
    Arc::new(RwLock::new(wrapped))
}

/// Wrap an abstract value in an async shared lock
pub fn new_async_shared<T>(wrapped: T) -> AsyncShared<T> {
    Arc::new(TokioRwLock::new(wrapped))
}
