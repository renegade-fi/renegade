//! Return types from applicator methods
//!
//! We provide "function call" like semantics over the consensus engine by
//! allowing the applicator to return a value from the engine to its callers.
//! In this case the callers are locations awaiting a proposal's application
//!
//! Each of such waiters will be given a copy of the return value

/// The return type from the Applicator
///
/// TODO: This is currently empty, deprecate if unnecessary
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ApplicatorReturnType {
    /// No return value
    None,
}
