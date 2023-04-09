use circuit_macros::circuit_trace;
use curve25519_dalek::scalar::Scalar;
use lazy_static::lazy_static;
use merlin::Transcript;
use mpc_bulletproof::{
    r1cs::{ConstraintSystem, Prover, Variable},
    PedersenGens,
};
use rand_core::OsRng;
use std::{
    collections::{hash_map::Entry, HashMap},
    sync::Mutex,
    thread,
    time::Duration,
};

/// A type used for scoping trace metrics
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Scope {
    pub path: Vec<String>,
}

impl Scope {
    pub fn from_path(path: Vec<String>) -> Self {
        Self { path }
    }

    /// Append a value to the scope
    pub fn scope_in(&mut self, scope: String) {
        self.path.push(scope);
    }

    /// Pop the latest scope from the path
    pub fn scope_out(&mut self) -> String {
        self.path.pop().unwrap()
    }
}

/// Represents a list of metrics collected via a trace
#[derive(Clone, Debug, Default)]
pub struct ScopedMetrics {
    /// A list of metrics, represented as named tuples
    pub(crate) data: HashMap<String, u64>,
}

impl ScopedMetrics {
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
#[derive(Clone, Debug, Default)]
pub struct MetricsCapture {
    /// A mapping from scope to the metrics captured at that scope
    pub(crate) metrics: HashMap<Scope, ScopedMetrics>,
}

impl MetricsCapture {
    /// Record a scoped metric, if the metric already exists for the scope, aggregate it
    pub fn record_metric(&mut self, scope: Scope, metric_name: String, value: u64) {
        if let Entry::Vacant(e) = self.metrics.entry(scope.clone()) {
            e.insert(ScopedMetrics::default());
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
    static ref SCOPED_METRICS: Mutex<MetricsCapture> = Mutex::new(MetricsCapture::default());
    static ref CURR_SCOPE: Mutex<Scope> = Mutex::new(Scope::default());
    /// Used to synchronize the tests in this module in specific, because the tracer does not
    /// allow concurrent access to these global state elements
    static ref TEST_LOCK: Mutex<()> = Mutex::new(());
}

/// A dummy gadget whose constraint generation is done through an associated function, used to
/// test the trace macro on an associated function
pub struct Gadget {}
impl Gadget {
    #[circuit_trace(n_constraints, n_multipliers, latency)]
    pub fn apply_constraints(cs: &mut Prover) {
        // Apply dummy constraints
        let mut rng = OsRng {};
        let (_, var) = cs.commit(Scalar::one(), Scalar::random(&mut rng));
        let (_, _, mul_out) = cs.multiply(var.into(), Variable::Zero().into());
        cs.constrain(mul_out.into());

        // Add some latency to test the latency metric
        thread::sleep(Duration::from_millis(100));
    }
}

/// A dummy macro target that is not an associated function of any abstract gadget, used to
/// test the non-associated macro arg
#[circuit_trace(non_associated, n_constraints, n_multipliers, latency)]
fn non_associated_gadget(cs: &mut Prover) {
    // Apply dummy constraints
    let mut rng = OsRng {};
    let (_, var) = cs.commit(Scalar::one(), Scalar::random(&mut rng));
    let (_, _, mul_out) = cs.multiply(var.into(), Variable::Zero().into());
    cs.constrain(mul_out.into());

    // Add some latency to test the latency metric
    thread::sleep(Duration::from_millis(100));
}

/// Tests the tracer macro on an associated function when the tracer is enabled
#[cfg(feature = "bench")]
#[test]
fn test_macro_associated() {
    // Lock the test harness
    let _lock = TEST_LOCK.lock().unwrap();

    // Build a dummy constraint system and apply a few constraints
    let mut prover_transcript = Transcript::new("test".as_bytes());
    let pc_gens = PedersenGens::default();
    let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

    Gadget::apply_constraints(&mut prover);

    // Read the values from the tracer, this test is gated behind the same feature flag
    // as the tracer, so metrics should have been recorded
    let gadget_scope = Scope::from_path(vec!["apply_constraints".to_string()]);
    let mut locked_metrics = SCOPED_METRICS.lock().unwrap();

    let latency_metric = locked_metrics
        .get_metric(gadget_scope.clone(), "latency".to_string())
        .unwrap();
    assert!(latency_metric >= 100);

    let n_constraints_metric = locked_metrics
        .get_metric(gadget_scope.clone(), "n_constraints".to_string())
        .unwrap();
    assert_eq!(3, n_constraints_metric);

    let n_multipliers_metric = locked_metrics
        .get_metric(gadget_scope, "n_multipliers".to_string())
        .unwrap();
    assert_eq!(1, n_multipliers_metric);
}

/// Tests the tracer macro on a non-associated function when the tracer is enabled
#[cfg(feature = "bench")]
#[test]
fn test_macro_non_associated() {
    // Lock the test harness
    let _lock = TEST_LOCK.lock().unwrap();

    // Build a dummy constraint system and apply a few constraints
    let mut prover_transcript = Transcript::new("test".as_bytes());
    let pc_gens = PedersenGens::default();
    let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

    non_associated_gadget(&mut prover);

    // Read the values from the tracer, this test is gated behind the same feature flag
    // as the tracer, so metrics should have been recorded
    let gadget_scope = Scope::from_path(vec!["non_associated_gadget".to_string()]);
    let mut locked_metrics = SCOPED_METRICS.lock().unwrap();

    let latency_metric = locked_metrics
        .get_metric(gadget_scope.clone(), "latency".to_string())
        .unwrap();
    assert!(latency_metric >= 100);

    let n_constraints_metric = locked_metrics
        .get_metric(gadget_scope.clone(), "n_constraints".to_string())
        .unwrap();
    assert_eq!(3, n_constraints_metric);

    let n_multipliers_metric = locked_metrics
        .get_metric(gadget_scope, "n_multipliers".to_string())
        .unwrap();
    assert_eq!(1, n_multipliers_metric);
}

/// Tests the tracer macro on an associated function when the tracer is disabled
#[cfg(not(feature = "bench"))]
#[test]
fn test_macro_associated() {
    // Build a dummy constraint system and apply a few constraints
    let mut prover_transcript = Transcript::new("test".as_bytes());
    let pc_gens = PedersenGens::default();
    let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

    Gadget::apply_constraints(&mut prover);

    // Read the values from the tracer, this test is gated behind the same feature flag
    // as the tracer, so metrics should have been recorded
    let gadget_scope = Scope::from_path(vec!["apply_constraints".to_string()]);
    let mut locked_metrics = SCOPED_METRICS.lock().unwrap();

    assert!(locked_metrics
        .get_metric(gadget_scope.clone(), "latency".to_string())
        .is_none());

    assert!(locked_metrics
        .get_metric(gadget_scope.clone(), "n_constraints".to_string())
        .is_none());

    assert!(locked_metrics
        .get_metric(gadget_scope, "n_multipliers".to_string())
        .is_none());
}

/// Tests the tracer macro on a non-associated function when the tracer is disabled
#[cfg(not(feature = "bench"))]
#[test]
fn test_macro_non_associated() {
    // Build a dummy constraint system and apply a few constraints
    let mut prover_transcript = Transcript::new("test".as_bytes());
    let pc_gens = PedersenGens::default();
    let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

    non_associated_gadget(&mut prover);

    // Read the values from the tracer, this test is gated behind the same feature flag
    // as the tracer, so metrics should have been recorded
    let gadget_scope = Scope::from_path(vec!["non_associated_gadget".to_string()]);
    let mut locked_metrics = SCOPED_METRICS.lock().unwrap();

    assert!(locked_metrics
        .get_metric(gadget_scope.clone(), "latency".to_string())
        .is_none());

    assert!(locked_metrics
        .get_metric(gadget_scope.clone(), "n_constraints".to_string())
        .is_none());

    assert!(locked_metrics
        .get_metric(gadget_scope, "n_multipliers".to_string())
        .is_none());
}
