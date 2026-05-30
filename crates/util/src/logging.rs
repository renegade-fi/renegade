//! Structured log envelope shared across the relayer workspace.
//!
//! Every relayer log line that names an operation should go through
//! [`log_task!`] so it follows the same `[<task>] [<outcome>] <description>`
//! shape used by gardener (`gardener/src/utils/logger.ts`) and funds-manager
//! (`relayer-extensions/funds-manager/funds-manager-server/src/logger.rs`).
//! This makes relayer activity easy to read in raw log output and aggregable
//! in Datadog via the `@task` / `@outcome` JSON fields the macro attaches.
//!
//! Pattern:
//!
//! ```text
//! [<task>] [<outcome>] <description>     (+ task, outcome, and any extra fields)
//! ```
//!
//! - **Task** is a closed vocabulary of operations a crate performs. Unlike
//!   funds-manager (a single crate with one global enum), the relayer is a
//!   multi-crate workspace, so each crate defines its OWN closed `Task` enum
//!   implementing [`LogTask`]. The closed vocabulary is what makes `@task:X`
//!   aggregations and `[task]`-prefixed greps reliable.
//! - **Outcome** is closed and global: see [`Outcome`]. The outcome picks the
//!   underlying tracing level (info/warn/error) so callers do not choose it.
//! - **Description** is the human-readable detail. Any number of structured
//!   fields can be passed before the description as `key = value`. Reserve the
//!   field name `subject` for naming WHICH thing the log line is about (order
//!   id, peer, ticker, route) so dashboards aggregate across call sites that
//!   share a task.
//!
//! Usage:
//!
//! ```ignore
//! use util::logging::Outcome;
//! use util::log_task;
//!
//! // `Task` here is the calling crate's own enum implementing `LogTask`.
//! log_task!(Task::HandleOrder, Outcome::Started, "received new order");
//!
//! log_task!(
//!     Task::SettleMatch,
//!     Outcome::Failed,
//!     subject = %order_id,
//!     error = %e,
//!     "settlement tx submission failed"
//! );
//! ```

use tracing::Level;

/// A closed vocabulary of operations a crate performs.
///
/// Each crate defines its own enum implementing this trait. Add a variant
/// before introducing a new task at a call site; the closed vocabulary is
/// what makes `@task:X` Datadog aggregations and `[task]`-prefixed greps
/// reliable.
pub trait LogTask {
    /// Stable, kebab-cased string form of this task. Used both in the
    /// `[task]` text envelope and in the `task` structured field.
    fn as_str(&self) -> &'static str;
}

/// Closed vocabulary of operation outcomes. Mirrors gardener's and
/// funds-manager's set.
///
/// Semantics:
/// - `Started`: work has begun. Pair with a later `Ok`/`Failed`/`Skipped`.
/// - `Ok`: completed successfully.
/// - `Skipped`: nothing to do this cycle; not a failure.
/// - `Partial`: completed with a known degradation (cache fallback, some legs
///   failed but the operation continued).
/// - `Retrying`: intra-call retry attempt. A failure that propagates back to
///   the caller for a later retry is `Failed`, not `Retrying`.
/// - `Failed`: errored out; the operation did not complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Work has begun.
    Started,
    /// Completed successfully.
    Ok,
    /// Nothing to do; not a failure.
    Skipped,
    /// Completed with known degradation.
    Partial,
    /// Intra-call retry attempt.
    Retrying,
    /// Errored out; did not complete.
    Failed,
}

impl Outcome {
    /// Stable kebab-cased string form for the `[outcome]` envelope and the
    /// structured `outcome` field.
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Started => "started",
            Outcome::Ok => "ok",
            Outcome::Skipped => "skipped",
            Outcome::Partial => "partial",
            Outcome::Retrying => "retrying",
            Outcome::Failed => "failed",
        }
    }

    /// Map this outcome to a tracing [`Level`]. Successes / skips at INFO,
    /// partial / retrying at WARN, failed at ERROR. Call sites do not pick the
    /// level themselves — picking the right `Outcome` is enough.
    pub fn level(self) -> Level {
        match self {
            Outcome::Started | Outcome::Ok | Outcome::Skipped => Level::INFO,
            Outcome::Partial | Outcome::Retrying => Level::WARN,
            Outcome::Failed => Level::ERROR,
        }
    }
}

/// Process-level tasks owned by `util` itself.
///
/// Most tasks belong to a specific crate's `Task` enum, but the panic hook in
/// [`install_panic_hook`] runs in generic `util` code and needs a task value
/// that is not tied to any one worker crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessTask {
    /// An untagged failure that escaped to the process-level panic hook.
    UncaughtPanic,
}

impl LogTask for ProcessTask {
    fn as_str(&self) -> &'static str {
        match self {
            ProcessTask::UncaughtPanic => "uncaught-panic",
        }
    }
}

/// Emit a structured log line in the relayer taxonomy:
///
/// ```text
/// [<task>] [<outcome>] <description>     (+ task, outcome, and any extra fields)
/// ```
///
/// Signature:
///
/// ```ignore
/// log_task!(<task>, <outcome>, [field = value, ...] <fmt literal> [, args...]);
/// ```
///
/// `<task>` is any value whose type implements [`LogTask`] (typically the
/// calling crate's own `Task` enum). `<outcome>` is an [`Outcome`]. The format
/// literal follows `tracing::info!` / `println!` conventions. Any number of
/// `key = value` pairs can be passed before the literal as structured fields
/// (`?expr` for Debug, `%expr` for Display, as in `tracing`). Use the field
/// name `subject` to name WHICH thing the line is about so dashboards can
/// aggregate across tasks.
///
/// The macro picks the underlying tracing level from [`Outcome::level`], so
/// call sites never choose between `info!` / `warn!` / `error!` manually.
#[macro_export]
macro_rules! log_task {
    ($task:expr, $outcome:expr, $($rest:tt)+) => {
        $crate::__log_task_inner!(@munch [] $task, $outcome, $($rest)+)
    };
}

/// Implementation detail of [`log_task!`]. The tt-muncher peels off
/// `ident = expr,` field pairs one at a time before falling through to the
/// format-args terminal arm. The `=` after the identifier disambiguates
/// "field" from "first token of format args" — without it, `macro_rules`
/// cannot tell the two cases apart and rejects the call with `local
/// ambiguity`.
#[doc(hidden)]
#[macro_export]
macro_rules! __log_task_inner {
    // Munch one field — Debug-formatted value (tracing's `?expr` shorthand)
    (@munch [$($fields:tt)*] $task:expr, $outcome:expr, $field:ident = ?$val:expr, $($rest:tt)+) => {
        $crate::__log_task_inner!(@munch [$($fields)* $field = ?$val,] $task, $outcome, $($rest)+)
    };
    // Munch one field — Display-formatted value (tracing's `%expr` shorthand)
    (@munch [$($fields:tt)*] $task:expr, $outcome:expr, $field:ident = %$val:expr, $($rest:tt)+) => {
        $crate::__log_task_inner!(@munch [$($fields)* $field = %$val,] $task, $outcome, $($rest)+)
    };
    // Munch one field — plain value
    (@munch [$($fields:tt)*] $task:expr, $outcome:expr, $field:ident = $val:expr, $($rest:tt)+) => {
        $crate::__log_task_inner!(@munch [$($fields)* $field = $val,] $task, $outcome, $($rest)+)
    };
    // Out of fields; emit the event at the level chosen by Outcome::level()
    (@munch [$($fields:tt)*] $task:expr, $outcome:expr, $($arg:tt)+) => {{
        let __task = $task;
        let __outcome = $outcome;
        let __task_str = $crate::logging::LogTask::as_str(&__task);
        let __outcome_str = $crate::logging::Outcome::as_str(__outcome);
        match $crate::logging::Outcome::level(__outcome) {
            ::tracing::Level::ERROR => ::tracing::error!(
                task = __task_str,
                outcome = __outcome_str,
                $($fields)*
                "[{}] [{}] {}",
                __task_str,
                __outcome_str,
                ::std::format_args!($($arg)+)
            ),
            ::tracing::Level::WARN => ::tracing::warn!(
                task = __task_str,
                outcome = __outcome_str,
                $($fields)*
                "[{}] [{}] {}",
                __task_str,
                __outcome_str,
                ::std::format_args!($($arg)+)
            ),
            _ => ::tracing::info!(
                task = __task_str,
                outcome = __outcome_str,
                $($fields)*
                "[{}] [{}] {}",
                __task_str,
                __outcome_str,
                ::std::format_args!($($arg)+)
            ),
        }
    }};
}

/// Install a panic hook that routes panics through [`log_task!`]. Without
/// this, a panic emits an unstructured backtrace that cannot be filtered
/// alongside other `failed` outcomes. Call once from a binary's `main` before
/// any worker spawns; the previous hook still runs afterwards.
pub fn install_panic_hook() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let payload = info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(String::as_str))
            .unwrap_or("<non-string panic payload>");
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "<unknown>".to_string());
        crate::log_task!(
            ProcessTask::UncaughtPanic,
            Outcome::Failed,
            location = %location,
            payload = %payload,
            "panic at {}: {}",
            location,
            payload
        );
        default(info);
    }));
}
