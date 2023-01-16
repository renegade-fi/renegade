use circuit_macros::circuit_trace;
use lazy_static::lazy_static;
use merlin::Transcript;
use mpc_bulletproof::{r1cs::Prover, PedersenGens};
use std::{
    collections::{hash_map::Entry, HashMap},
    sync::Mutex,
};

/// A type used for scop
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Scope {
    pub path: Vec<String>,
}

impl Scope {
    /// Build a new scope
    pub fn new() -> Self {
        Self { path: vec![] }
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
}

lazy_static! {
    static ref SCOPED_METRICS: Mutex<MetricsCapture> = Mutex::new(MetricsCapture::new());
    static ref CURR_SCOPE: Mutex<Scope> = Mutex::new(Scope::new());
}

fn helper(x: u64) -> u64 {
    x + 1
}

/// A dummy target for the macro
#[circuit_trace(n_constraints, n_multipliers, latency)]
#[allow(unused)]
fn dummy(x: u64, cs: &mut Prover) -> u64 {
    let new_x = helper(x);
    new_x
}

#[test]
fn test_macro() {
    let mut prover_transcript = Transcript::new("test".as_bytes());
    let pc_gens = PedersenGens::default();
    let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

    dummy(1, &mut prover);
    println!("SCOPED METRICS: {:?}", SCOPED_METRICS.lock().unwrap());
}
