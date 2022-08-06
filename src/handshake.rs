use std::sync::Arc;

use rayon::{ThreadPool, ThreadPoolBuilder};

/**
 * Groups logic for handshakes executed through a threadpool at period intervals
 */

const NUM_HANDSHAKE_THREADS: u32 = 8;

pub struct HandshakeManager {

}

impl HandshakeManager {
    pub fn new() -> Self {
        // Build a thread pool to handle handshake operations
        let thread_pool = Arc::new(
            ThreadPoolBuilder::new()
                .num_threads(32)
                .build()
                .unwrap()
        );
        
        for i in 0..20 {
            let pool_copy = thread_pool.clone();
            thread_pool.install(move || {
                let thread_id = pool_copy.current_thread_index().unwrap();
                println!("Thread {} running task {}", thread_id, i);
            })
        }

        HandshakeManager {  } 
    }
}