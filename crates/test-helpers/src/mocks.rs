//! Utilities for mocking relayer functionality

use std::mem;

use common::types::{CancelChannel, new_cancel_channel};

/// Create a cancel channel and forget the sender to avoid drops
pub fn mock_cancel() -> CancelChannel {
    let (send, recv) = new_cancel_channel();
    mem::forget(send);

    recv
}
