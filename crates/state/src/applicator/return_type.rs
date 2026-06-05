//! Return types from applicator methods
//!
//! We provide "function call" like semantics over the consensus engine by
//! allowing the applicator to return a value from the engine to its callers.
//! In this case the callers are locations awaiting a proposal's application
//!
//! Each of such waiters will be given a copy of the return value

/// The return type from the Applicator
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ApplicatorReturnType {
    /// No return value
    None,
    /// A serial preemptive task was blocked by a committed queue head and has
    /// been recorded as pending (Stage 1 defer-not-reject); it will run
    /// automatically when the blocking task(s) complete.
    ///
    /// Surfaced to the proposing caller so it can await the deferred task's
    /// completion with a bounded timeout rather than treating the enqueue as an
    /// immediate success.
    Deferred,
}
