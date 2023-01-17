//! Groups the global static data structures used for tracing circuit execution
//!
//! The types used here are copied over from the circuit-macros crate. Due to the restriction
//! on procedural macros to own their crate, these two crates cannot share these types.
#![cfg(feature = "bench")]

use lazy_static::lazy_static;
use std::{
    collections::{hash_map::Entry, HashMap},
    sync::Mutex,
};

/// A type used for scoping trace metrics
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Scope {
    pub path: Vec<String>,
}

impl Scope {
    /// Build a new scope
    pub fn new() -> Self {
        Self { path: vec![] }
    }

    pub fn from_path(path: Vec<String>) -> Self {
        Self { path }
    }

    /// Append a value to the scope
    pub fn scope_in(&mut self, scope: String) {
        self.path.push(scope)
    }

    /// Pop the latest scope from the path
    pub fn scope_out(&mut self) -> String {
        self.path.pop().unwrap()
    }
}

/// Represents a list of metrics collected via a trace
#[derive(Clone, Debug)]
pub struct ScopedMetrics {
    /// A list of metrics, represented as named tuples
    pub(crate) data: HashMap<String, u64>,
}

impl ScopedMetrics {
    /// Create a new, empty list of metrics
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }

    /// Add a metric to the list, aggregating if the metric already exists
    ///
    /// Returns the value if a previous value existed
    pub fn add_metric(&mut self, name: String, value: u64) -> Option<u64> {
        if let Some(curr_val) = self.data.get(&name) {
            self.data.insert(name, curr_val + value)
        } else {
            self.data.insert(name, value);
            None
        }
    }
}

/// A set of metrics captured by the execution of the tracer on a circuit
#[derive(Clone, Debug)]
pub struct MetricsCapture {
    /// A mapping from scope to the metrics captured at that scope
    pub(crate) metrics: HashMap<Scope, ScopedMetrics>,
}

impl MetricsCapture {
    /// Create a new MetricsCapture instance
    pub fn new() -> Self {
        Self {
            metrics: HashMap::new(),
        }
    }

    /// Record a scoped metric, if the metric already exists for the scope, aggregate it
    pub fn record_metric(&mut self, scope: Scope, metric_name: String, value: u64) {
        if let Entry::Vacant(e) = self.metrics.entry(scope.clone()) {
            e.insert(ScopedMetrics::new());
        }

        self.metrics
            .get_mut(&scope)
            .unwrap()
            .add_metric(metric_name, value);
    }

    /// Get the metric for the given scope and metric name
    pub fn get_metric(&mut self, scope: Scope, metric_name: String) -> Option<u64> {
        self.metrics.get(&scope)?.data.get(&metric_name).cloned()
    }
}

lazy_static! {
    pub(crate) static ref SCOPED_METRICS: Mutex<MetricsCapture> = Mutex::new(MetricsCapture::new());
    pub(crate) static ref CURR_SCOPE: Mutex<Scope> = Mutex::new(Scope::new());
}
