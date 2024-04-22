//! Types for the offline phase of an MPC, used for storage and online phase use

use ark_mpc::offline_prep::PreprocessingPhase;
use constants::{Scalar, ScalarShare, SystemCurveGroup};
use renegade_dealer_api::DealerResponse;
use serde::{Deserialize, Serialize};

/// The result of an offline phase
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CorrelatedRandomness {
    /// The random bits, shares of values in {0, 1}
    pub random_bits: Vec<ScalarShare>,
    /// The random values, shared of uniform random values over the scalar field
    pub random_values: Vec<ScalarShare>,
    /// The input masks
    ///
    /// Holds the plaintext values of the input masks, the shares of these
    /// cleartext values, and the shares of the counterparty's input masks in
    /// order
    pub my_input_masks: (Vec<Scalar>, Vec<ScalarShare>),
    /// The counterparty's input masks
    pub counterparty_input_masks: Vec<ScalarShare>,
    /// The inverse pairs
    ///
    /// Random values r, r^-1 in the scalar field
    pub inverse_pairs: (Vec<ScalarShare>, Vec<ScalarShare>),
    /// The triples, shares of values (a, b, c) such that a * b = c
    pub beaver_triples: (Vec<ScalarShare>, Vec<ScalarShare>, Vec<ScalarShare>),
}

impl CorrelatedRandomness {
    /// Append one correlated randomness instance to another
    pub fn append(&mut self, other: &CorrelatedRandomness) {
        self.random_bits.extend(other.random_bits.iter().cloned());
        self.random_values.extend(other.random_values.iter().cloned());
        self.my_input_masks.0.extend(other.my_input_masks.0.iter().cloned());
        self.my_input_masks.1.extend(other.my_input_masks.1.iter().cloned());
        self.counterparty_input_masks.extend(other.counterparty_input_masks.iter().cloned());
        self.inverse_pairs.0.extend(other.inverse_pairs.0.iter().cloned());
        self.inverse_pairs.1.extend(other.inverse_pairs.1.iter().cloned());
        self.beaver_triples.0.extend(other.beaver_triples.0.iter().cloned());
        self.beaver_triples.1.extend(other.beaver_triples.1.iter().cloned());
        self.beaver_triples.2.extend(other.beaver_triples.2.iter().cloned());
    }

    /// Pop the given number of each randomness value from the
    /// `CorrelatedRandomness`
    ///
    /// Returns an instance of `CorrelatedRandomness` with the given number of
    /// randomness values popped from each of the randomness vectors
    pub fn pop(
        &mut self,
        num_bits: usize,
        num_values: usize,
        num_input_masks: usize,
        num_inverse_pairs: usize,
        num_triples: usize,
    ) -> CorrelatedRandomness {
        let bits = self.random_bits.split_off(self.random_bits.len() - num_bits);
        let values = self.random_values.split_off(self.random_values.len() - num_values);
        let masks = self.my_input_masks.0.split_off(self.my_input_masks.0.len() - num_input_masks);
        let masks1 = self.my_input_masks.1.split_off(self.my_input_masks.1.len() - num_input_masks);
        let masks2 = self
            .counterparty_input_masks
            .split_off(self.counterparty_input_masks.len() - num_input_masks);
        let inverse0 =
            self.inverse_pairs.0.split_off(self.inverse_pairs.0.len() - num_inverse_pairs);
        let inverse1 =
            self.inverse_pairs.1.split_off(self.inverse_pairs.1.len() - num_inverse_pairs);
        let triples0 = self.beaver_triples.0.split_off(self.beaver_triples.0.len() - num_triples);
        let triples1 = self.beaver_triples.1.split_off(self.beaver_triples.1.len() - num_triples);
        let triples2 = self.beaver_triples.2.split_off(self.beaver_triples.2.len() - num_triples);

        CorrelatedRandomness {
            random_bits: bits,
            random_values: values,
            my_input_masks: (masks, masks1),
            counterparty_input_masks: masks2,
            inverse_pairs: (inverse0, inverse1),
            beaver_triples: (triples0, triples1, triples2),
        }
    }
}

impl From<DealerResponse> for CorrelatedRandomness {
    fn from(response: DealerResponse) -> Self {
        CorrelatedRandomness {
            random_bits: response.random_bits,
            random_values: response.random_values,
            my_input_masks: (response.input_masks.0, response.input_masks.1),
            counterparty_input_masks: response.input_masks.2,
            inverse_pairs: (response.inverse_pairs.0, response.inverse_pairs.1),
            beaver_triples: (
                response.beaver_triples.0,
                response.beaver_triples.1,
                response.beaver_triples.2,
            ),
        }
    }
}

/// The result of an offline phase with the counterparty
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairwiseOfflineSetup {
    /// The local share of the MAC key
    pub mac_key: Scalar,
    /// The correlated randomness created for the pair
    pub values: CorrelatedRandomness,
}

impl PairwiseOfflineSetup {
    /// Create a new empty setup
    pub fn new(mac_key: Scalar) -> Self {
        PairwiseOfflineSetup { mac_key, values: CorrelatedRandomness::default() }
    }

    /// Append new correlated randomness to the setup
    pub fn append(&mut self, other: &CorrelatedRandomness) {
        self.values.append(other);
    }

    /// Append a response from the dealer
    pub fn append_dealer_response(&mut self, response: DealerResponse) {
        self.values.append(&response.into());
    }

    /// Pop the given number of correlated randomness values from the setup
    pub fn pop(
        &mut self,
        num_bits: usize,
        num_values: usize,
        num_input_masks: usize,
        num_inverse_pairs: usize,
        num_triples: usize,
    ) -> Self {
        let values =
            self.values.pop(num_bits, num_values, num_input_masks, num_inverse_pairs, num_triples);
        PairwiseOfflineSetup { mac_key: self.mac_key, values }
    }
}

impl PreprocessingPhase<SystemCurveGroup> for PairwiseOfflineSetup {
    fn get_mac_key_share(&self) -> Scalar {
        self.mac_key
    }

    fn next_local_input_mask(&mut self) -> (Scalar, ScalarShare) {
        let mask = self.values.my_input_masks.0.pop().unwrap();
        (mask, self.values.my_input_masks.1.pop().unwrap())
    }

    fn next_local_input_mask_batch(&mut self, n: usize) -> (Vec<Scalar>, Vec<ScalarShare>) {
        assert_eq!(self.values.my_input_masks.0.len(), self.values.my_input_masks.1.len());
        let split_idx = self.values.my_input_masks.0.len() - n;

        let masks = self.values.my_input_masks.0.split_off(split_idx);
        let masks1 = self.values.my_input_masks.1.split_off(split_idx);

        (masks, masks1)
    }

    fn next_counterparty_input_mask(&mut self) -> ScalarShare {
        self.values.counterparty_input_masks.pop().unwrap()
    }

    fn next_counterparty_input_mask_batch(&mut self, n: usize) -> Vec<ScalarShare> {
        let split_idx = self.values.counterparty_input_masks.len() - n;
        self.values.counterparty_input_masks.split_off(split_idx)
    }

    fn next_shared_bit(&mut self) -> ScalarShare {
        self.values.random_bits.pop().unwrap()
    }

    fn next_shared_bit_batch(&mut self, n: usize) -> Vec<ScalarShare> {
        let split_idx = self.values.random_bits.len() - n;
        self.values.random_bits.split_off(split_idx)
    }

    fn next_shared_value(&mut self) -> ScalarShare {
        self.values.random_values.pop().unwrap()
    }

    fn next_shared_value_batch(&mut self, n: usize) -> Vec<ScalarShare> {
        let split_idx = self.values.random_values.len() - n;
        self.values.random_values.split_off(split_idx)
    }

    fn next_shared_inverse_pair(&mut self) -> (ScalarShare, ScalarShare) {
        (self.values.inverse_pairs.0.pop().unwrap(), self.values.inverse_pairs.1.pop().unwrap())
    }

    fn next_shared_inverse_pair_batch(&mut self, n: usize) -> (Vec<ScalarShare>, Vec<ScalarShare>) {
        assert_eq!(self.values.inverse_pairs.0.len(), self.values.inverse_pairs.1.len());
        let split_idx = self.values.inverse_pairs.0.len() - n;

        (
            self.values.inverse_pairs.0.split_off(split_idx),
            self.values.inverse_pairs.1.split_off(split_idx),
        )
    }

    fn next_triplet(&mut self) -> (ScalarShare, ScalarShare, ScalarShare) {
        (
            self.values.beaver_triples.0.pop().unwrap(),
            self.values.beaver_triples.1.pop().unwrap(),
            self.values.beaver_triples.2.pop().unwrap(),
        )
    }

    fn next_triplet_batch(
        &mut self,
        n: usize,
    ) -> (Vec<ScalarShare>, Vec<ScalarShare>, Vec<ScalarShare>) {
        let len = self.values.beaver_triples.0.len();
        assert_eq!(len, self.values.beaver_triples.1.len());
        assert_eq!(len, self.values.beaver_triples.2.len());

        let split_idx = len - n;

        (
            self.values.beaver_triples.0.split_off(split_idx),
            self.values.beaver_triples.1.split_off(split_idx),
            self.values.beaver_triples.2.split_off(split_idx),
        )
    }
}
