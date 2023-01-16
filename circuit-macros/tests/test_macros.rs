use circuit_macros::circuit_trace;
use lazy_static::lazy_static;
use merlin::Transcript;
use mpc_bulletproof::{
    r1cs::{Prover, RandomizableConstraintSystem},
    PedersenGens,
};
use std::collections::HashMap;

/// A type used for scop
#[derive(Clone, Debug)]
pub struct Scope {
    pub path: Vec<String>,
}

/// Represents a list of metrics collected via a trace
#[derive(Clone, Debug)]
pub struct Metrics {
    /// A list of metrics, represented as named tuples
    metrics_list: Vec<(String, u64)>,
}

lazy_static! {
    static ref SCOPED_METRICS: HashMap<Scope, Metrics> = HashMap::new();
}

struct Temp {
    x: u64,
}

impl Temp {
    pub fn new(x: u64) -> Self {
        Temp { x }
    }

    fn test2(&self) {
        println!("testing")
    }

    // #[circuit_trace]
    pub fn test(&self, y: u64) -> u64 {
        Self::test2(&self);
        self.x + y
    }
}

fn helper(x: u64) -> u64 {
    x + 1
}

/// A dummy target for the macro
#[circuit_trace]
fn dummy(x: u64) -> u64 {
    // let temp = Temp::new(1);
    // let y = 5;
    // temp.test(y);
    let new_x = helper(x);
    println!("Tests abc: {:?}", new_x);
    new_x
}

#[test]
fn test_macro() {
    let mut transcript = Transcript::new("test".as_bytes());
    let pc_gens = PedersenGens::default();
    let prover = Prover::new(&pc_gens, &mut transcript);

    let res = dummy(1);
    assert_eq!(res, 2);
    assert_eq!(1, 2);
}
