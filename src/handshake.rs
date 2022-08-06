use rayon::{ThreadPool, ThreadPoolBuilder};
use std::{
    sync::Arc,
    thread::{self, JoinHandle}, time::Duration
};

/**
 * Groups logic for handshakes executed through a threadpool at period intervals
 */

// The number of threads executing handshakes
const NUM_HANDSHAKE_THREADS: usize = 8;

// The interval at which to initiate handshakes
const HANDSHAKE_INTERVAL_MS: u64 = 5000;

const NANOS_PER_MILLI: u64 = 1_000_000;

pub struct HandshakeManager {
    timer: HandshakeTimer
}

impl HandshakeManager {
    pub fn new() -> Self {
        // Build a thread pool to handle handshake operations
        let thread_pool = Arc::new(
            ThreadPoolBuilder::new()
                .num_threads(NUM_HANDSHAKE_THREADS)
                .build()
                .unwrap()
        );

        // Start a timer thread
        let timer = HandshakeTimer::new(thread_pool);

        HandshakeManager { timer } 
    }

    // Joins execution of the calling thread to the HandshakeManager's execution
    pub fn join(self) -> thread::Result<()> {
        self.timer.join()
    }

    // Perform a handshake, dummy job for now
    pub fn perform_handshake(job_id: u32, thread_pool: Arc<ThreadPool>) {
        println!(
            "Thread {} running task {}", 
            thread_pool.current_thread_index().unwrap(), 
            job_id
        );
    }

}

/**
 * Implements a timer that periodically enqueues jobs to the threadpool
 */
pub struct HandshakeTimer {
    thread_handle: thread::JoinHandle<()>
}

impl HandshakeTimer {
    pub fn new(
        thread_pool: Arc<ThreadPool>
    ) -> Self {
        let interval_seconds = HANDSHAKE_INTERVAL_MS / 1000;
        let interval_nanos = (HANDSHAKE_INTERVAL_MS % 1000 * NANOS_PER_MILLI) as u32;

        let refresh_interval = Duration::new(interval_seconds, interval_nanos);

        // Spawn the execution loop
        let thread_handle = thread::Builder::new()
            .name("handshake-manager-timer".to_string())
            .spawn(move || {
                Self::execution_loop(refresh_interval, thread_pool)
            })
            .unwrap();

        HandshakeTimer { thread_handle }
    }

    pub fn join(self) -> thread::Result<()> {
        self.thread_handle.join()
    }

    // The execution loop of the timer, periodically enqueues handshake jobs
    fn execution_loop(
        refresh_interval: Duration,
        thread_pool: Arc<ThreadPool>,
    ) {
        // Enqueue refreshes periodically
        loop {
            for i in 1..10 {
                let pool_copy = thread_pool.clone();
                thread_pool.install(move || { 
                    HandshakeManager::perform_handshake(i, pool_copy) 
                })
            }

            thread::sleep(refresh_interval);
        }
    }
}

