//! Helpers for async execution

use std::future::Future;

use futures::future::join_all;
use tokio::runtime::Handle;

/// Block the Tokio runtime on a future, returning the result
pub fn block_current<T, F: Future<Output = T>>(res: F) -> T {
    Handle::current().block_on(res)
}

/// Block the Tokio runtime on a collection of futures, returning the results
pub fn block_current_multi<T, F: Future<Output = T>>(res: Vec<F>) -> Vec<T> {
    Handle::current().block_on(join_all(res))
}
