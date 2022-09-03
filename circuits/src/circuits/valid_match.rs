use std::{cell::RefCell, marker::PhantomData, rc::Rc};

use ark_ec::{PairingEngine};
use ark_ff::{PrimeField, Zero};
use ark_groth16::{Proof, create_random_proof, ProvingKey, generate_random_parameters};
use ark_r1cs_std::{prelude::{AllocVar, EqGadget}, R1CSVar, ToBitsGadget, uint64::UInt64, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError, ConstraintSynthesizer};
use num_bigint::{BigUint, ToBigUint};
use rand::rngs::OsRng;

use crate::{
    types::{SystemField, SystemPairingEngine, Wallet, MatchResult, WalletVar}, 
    gadgets::{wallet_match::MatchGadget, poseidon::{PoseidonSpongeWrapperVar, MatchHashInput, PoseidonVectorHashGadget, WalletHashInput}}
};


/**
 * Constants
 */

/**
 * A helper trait common across all circuits we use to abstract the inner workings
 * of proof generation. I.e. proving/verifying key setup, etc.
 */
pub trait RelayerProof {
    // TODO
}

/**
 * ValidMatch has the following function
 *      1. Compute matches between two order books
 *      2. Check input consistency with the wallet committments computed in ValidRelayer
 *      3. Compute a match consistency output
 * 
 * We wrap the valid match implementation in a parent struct for two reasons:
 *      1. To hide the interior mutability pattern used to extract circuit intermediates 
 *         (i.e. matches and match hashes)
 *      2. To hide the details of field selection from the consumers of this module
 */

#[derive(Clone, Debug)]
pub struct ValidMatchCircuit<> {
    match_cell: Rc<RefCell<Option<MatchResult>>>,
    match_hash_cell: Rc<RefCell<Option<u64>>>,
    match_result: Option<MatchResult>,
    match_hash: Option<u64>,
    wrapped_type: RefCell<ValidMatchCircuitImpl<SystemField>>,
}

impl ValidMatchCircuit {
    pub fn new(
        wallet1: Wallet, 
        wallet2: Wallet,
        wallet1_hash: BigUint,
        wallet2_hash: BigUint,
    ) -> Self {
        let match_cell = Rc::new(RefCell::new(None));
        let match_hash_cell = Rc::new(RefCell::new(None));
        let wrapped_type = RefCell::new(
            ValidMatchCircuitImpl::<SystemField>::new(
                wallet1, 
                wallet2, 
                wallet1_hash, 
                wallet2_hash, 
                match_cell.clone(),
                match_hash_cell.clone()
            )
        );

        Self { match_cell, match_hash_cell, match_result: None, match_hash: None, wrapped_type }
    }

    // Creates a proving key for the proof system given a circuit size
    pub fn create_proving_key(max_balances: usize, max_orders: usize) -> Result<ProvingKey<SystemPairingEngine>, SynthesisError> {
        let mut rng = OsRng{};
            // Dummy wallet, circuit sizes are filled in by max_orders and max_balances
        let dummy_wallet = Wallet::new_with_bounds(vec![], vec![], max_balances, max_orders);
        generate_random_parameters::<SystemPairingEngine, _, _>(
            ValidMatchCircuitImpl::new(
                dummy_wallet.clone(),
                dummy_wallet,
                BigUint::zero(),  // Value does not matter here, only width of values
                BigUint::zero(),
                Rc::new(RefCell::new(None)),
                Rc::new(RefCell::new(None)),
            ), &mut rng
        ) 
    }

    // Generates the circuit constraints using the witness supplied in the constructor
    pub fn generate_constraints(&self, cs: ConstraintSystemRef<SystemField>) -> Result<(), SynthesisError> {
        self.wrapped_type
            .take()
            .generate_constraints(cs)
    }

    // Creates a groth16 proof of the ValidMatch circuit
    pub fn create_proof<E: PairingEngine<Fr = SystemField>>(&self, proving_key: &ProvingKey<E>) -> Result<Proof<E>, SynthesisError> {
        let circuit = self.wrapped_type.take();
        let mut rng = OsRng{};

        create_random_proof(circuit, proving_key, &mut rng)
    }

    // Returns the matches produced by circuit evaluation and caches the result
    pub fn get_matches(&mut self) -> Option<MatchResult> {
        // Lift the value to the wrapper struct; allow it to be consumed multiple times
        if self.match_result.is_none() {
            self.match_result = self.match_cell.take()
        }

        self.match_result.clone()
    }

    // Returns the hash of the matches produced by circuit evaluation and caches the result
    pub fn get_match_hash(&mut self) -> Option<u64> {
        // Lift the value to the wrapper struct; allow it to be consumed multiple times
        if self.match_hash.is_none() {
            self.match_hash = self.match_hash_cell.take();
        }

        self.match_hash
    }
}


#[derive(Clone, Debug)]
struct ValidMatchCircuitImpl<F: PrimeField> {
    // Input variables
    wallet1: Wallet,
    wallet2: Wallet,
    wallet1_hash: BigUint,
    wallet2_hash: BigUint,

    // Extracted variables
    pub match_cell: Rc<RefCell<Option<MatchResult>>>,
    pub match_hash_cell: Rc<RefCell<Option<u64>>>,

    // Phantom
    _phantom: PhantomData<F>
}

impl<F: PrimeField> Default for ValidMatchCircuitImpl<F> {
    fn default() -> Self {
        Self {
            wallet1: Wallet::default(),
            wallet2: Wallet::default(),
            wallet1_hash: 0.to_biguint().unwrap(),
            wallet2_hash: 0.to_biguint().unwrap(),
            match_cell: Rc::new(RefCell::new(None)),
            match_hash_cell: Rc::new(RefCell::new(None)),
            _phantom: PhantomData
        }
    }
}

impl<F: PrimeField> ValidMatchCircuitImpl<F> {
    fn new(
        wallet1: Wallet,
        wallet2: Wallet,
        wallet1_hash: BigUint,
        wallet2_hash: BigUint,
        match_cell: Rc<RefCell<Option<MatchResult>>>,
        match_hash_cell: Rc<RefCell<Option<u64>>>
    ) -> Self {
        Self { 
            wallet1, 
            wallet2, 
            wallet1_hash, 
            wallet2_hash, 
            match_cell,
            match_hash_cell, 
            _phantom: PhantomData
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for ValidMatchCircuitImpl<F> {
    fn generate_constraints(
        self, 
        cs: ConstraintSystemRef<F>
    ) -> Result<(), SynthesisError> {
        // Allocate the public inputs
        let expected_hash_1 = FpVar::new_input(
            cs.clone(), 
            || Ok(F::from(self.wallet1_hash.clone()))
        )?;

        let expected_hash_2 = FpVar::new_input(
            cs.clone(), 
            || Ok(F::from(self.wallet2_hash.clone()))
        )?;

        // Allocate the private inputs
        let wallet1_var = WalletVar::new_witness(
            cs.clone(),
            || Ok(&self.wallet1)
        )?;

        let wallet2_var = WalletVar::new_witness(
            cs.clone(), 
            || Ok(&self.wallet2)
        )?;

        // Evaluate the matches
        let matches_result = MatchGadget::compute_matches(&wallet1_var, &wallet2_var)?;

        // Hash the matches
        let mut hasher = PoseidonSpongeWrapperVar::new(cs.clone());
        let hash_input = Result::<MatchHashInput<F>, SynthesisError>::from(&matches_result)?;

        let match_hash = PoseidonVectorHashGadget::evaluate(&hash_input, &mut hasher)?;

        // Evaluate the wallet committments
        let mut wallet1_hasher = PoseidonSpongeWrapperVar::new(cs.clone());
        let wallet1_hash_input = Result::<WalletHashInput<F>, SynthesisError>::from(&wallet1_var)?;

        let wallet1_hash = PoseidonVectorHashGadget::evaluate(&wallet1_hash_input, &mut wallet1_hasher)?;

        let mut wallet2_hasher = PoseidonSpongeWrapperVar::new(cs);
        let wallet2_hash_input = Result::<WalletHashInput<F>, SynthesisError>::from(&wallet2_var)?;

        let wallet2_hash = PoseidonVectorHashGadget::evaluate(&wallet2_hash_input, &mut wallet2_hasher)?;

        // Compare hashes
        wallet1_hash.enforce_equal(&expected_hash_1)?;
        wallet2_hash.enforce_equal(&expected_hash_2)?;

        // Extract the match hash and the matches result
        self.match_cell.replace(matches_result.value().ok());
        self.match_hash_cell.replace(
            UInt64::from_bits_le(&match_hash.to_bits_le()?[0..64])
                .value()
                .ok()
        );
        
        Ok(())
    }
}

/**
 * Tests
 */
#[cfg(test)]
mod valid_match_test {
    use ark_groth16::{prepare_verifying_key, verify_proof};
    use ark_relations::r1cs::ConstraintSystem;

    use crate::{types::{SystemField, Wallet, Order, OrderSide, Balance}, circuits::valid_match::ValidMatchCircuit, constants::MAX_ORDERS};


    #[test]
    fn test_extract_matches() {
        // Build the wallets
        let wallet1 = Wallet::new_with_bounds(
            vec![] /* balances */,
            vec![
                Order { 
                    quote_mint: 1, base_mint: 2, side: OrderSide::Buy, amount: 5, price: 10,
                }
            ] /* orders */,
            2, /* max_balances */
            2 /* max_orders */
        );

        let wallet2 = Wallet::new_with_bounds(
            vec![], /* balances */
            vec![
                Order {
                    quote_mint: 1, base_mint: 2, side: OrderSide::Sell, amount: 3, price: 8,
                }
            ], /* orders */
            2, /* max_balances */
            2 /* max_orderss */
        );

        // Compute the hashes of the wallets for input
        let wallet1_hash = wallet1.hash();
        let wallet2_hash = wallet2.hash();

        // Create a constraint system
        let cs = ConstraintSystem::new_ref();

        // Run the circuit and generate its constraints
        let mut circuit = ValidMatchCircuit::new(wallet1, wallet2, wallet1_hash, wallet2_hash);
        circuit.generate_constraints(cs).unwrap();

        let matches = circuit.get_matches().unwrap();
        assert!(matches.matches1.len() == 2 * MAX_ORDERS * MAX_ORDERS);
    }

    #[test]
    fn test_prove() {
        // Build the wallets
        let max_balances = 1;
        let max_orders = 1;
        let wallet1 = Wallet::new_with_bounds(
            vec![ Balance { mint: 1, amount: 70 } ], /* balances */
            vec![
                Order { 
                    quote_mint: 1, base_mint: 2, side: OrderSide::Buy, amount: 5, price: 10,
                }
            ], /* orders */
            max_balances,
            max_orders
        );

        let wallet2 = Wallet::new_with_bounds(
            vec![ Balance { mint: 2, amount: 3 }], /* balances */
            vec![
                Order {
                    quote_mint: 1, base_mint: 2, side: OrderSide::Sell, amount: 3, price: 8,
                }
            ], /* orders */
            max_balances,
            max_orders
        );

        let wallet1_hash = wallet1.hash();
        let wallet2_hash = wallet2.hash();
    
        // Build and setup the constraint system and proof system keys
        let circuit = ValidMatchCircuit::new(wallet1, wallet2, wallet1_hash.clone(), wallet2_hash.clone());

        let proving_key = ValidMatchCircuit::create_proving_key(max_balances, max_orders).unwrap();
        let proof = circuit.create_proof(&proving_key).unwrap();

        // Verify the proof and assert validity
        let verifying_key = prepare_verifying_key(&proving_key.vk);
        let verification_result = verify_proof(&verifying_key, &proof, &[
            SystemField::from(wallet1_hash),
            SystemField::from(wallet2_hash)
        ]).unwrap();

        assert!(verification_result)
    }
}