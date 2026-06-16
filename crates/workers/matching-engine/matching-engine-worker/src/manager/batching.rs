//! The Hybrid Batch Processor pools matched trades and dynamically scales the
//! batch size based on available CPU load before triggering the heavy recursive PlonK prover.

use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::time::{sleep, Duration};
use types_tasks::TaskDescriptor;

/// The maximum number of trades to batch into a single recursive SNARK
const MAX_BATCH_SIZE: usize = 50;
/// The maximum time to wait before forcing a batch to prove, regardless of size
const BATCH_TIMEOUT_MS: u64 = 5000;

/// The HybridBatchProcessor manages the dynamic pooling of private matches.
pub struct HybridBatchProcessor {
    /// The queue of incoming match tasks from the MPC matching engine
    incoming_queue: UnboundedReceiver<TaskDescriptor>,
    /// The sender used by the matching engine to push tasks to the pool
    queue_sender: UnboundedSender<TaskDescriptor>,
    /// The current size of the batch
    current_batch_size: AtomicUsize,
    // TODO: Add reference to TaskDriver job queue to forward the batched task
}

impl HybridBatchProcessor {
    /// Create a new HybridBatchProcessor
    pub fn new() -> Self {
        let (tx, rx) = unbounded_channel();
        Self {
            incoming_queue: rx,
            queue_sender: tx,
            current_batch_size: AtomicUsize::new(0),
        }
    }

    /// Get the sender for pushing tasks into the batch processor
    pub fn get_sender(&self) -> UnboundedSender<TaskDescriptor> {
        self.queue_sender.clone()
    }

    /// The main execution loop of the batch processor
    pub async fn start(mut self) {
        let mut current_batch = Vec::new();

        loop {
            tokio::select! {
                // Receive new matched trades from the MPC engine
                Some(task) = self.incoming_queue.recv() => {
                    current_batch.push(task);
                    self.current_batch_size.fetch_add(1, Ordering::SeqCst);

                    // Dynamic scaling: If we hit MAX_BATCH_SIZE, trigger the prover immediately
                    if current_batch.len() >= MAX_BATCH_SIZE {
                        self.trigger_batched_proof(&mut current_batch).await;
                    }
                }
                // Timeout: If the market is slow, don't let traders wait forever. Prove whatever we have.
                _ = sleep(Duration::from_millis(BATCH_TIMEOUT_MS)) => {
                    if !current_batch.is_empty() {
                        self.trigger_batched_proof(&mut current_batch).await;
                    }
                }
            }
        }
    }

    /// Trigger the recursive PlonK prover on the batched constraints
    async fn trigger_batched_proof(&self, batch: &mut Vec<TaskDescriptor>) {
        let size = batch.len();
        tracing::info!("Triggering Recursive Batched Proof for {} trades", size);
        
        // TODO: Map individual TaskDescriptors to their circuit witnesses
        // TODO: Pass the batch to the `batched_settlement.rs` recursive circuit
        // TODO: Forward the single master proof to the TaskDriver for on-chain submission
        
        // Reset the batch
        batch.clear();
        self.current_batch_size.store(0, Ordering::SeqCst);
    }
}
