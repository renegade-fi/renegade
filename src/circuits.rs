use std::{cell::{RefCell, Ref}, marker::PhantomData, alloc::System, rc::Rc};

use ark_ff::PrimeField;
use ark_r1cs_std::{prelude::{AllocVar, Boolean, EqGadget}, uint128::UInt128, R1CSVar, ToBitsGadget, uint64::UInt64};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError, ConstraintSynthesizer};

use self::{types::{WalletVar, Wallet}, wallet_match::{MatchGadget, MatchResult}, poseidon::{MatchHashInput, PoseidonSpongeWrapperVar, PoseidonVectorHashGadget, WalletHashInput}};

pub mod constants;
pub mod gadgets;
pub mod poseidon;
pub mod types;
pub mod wallet_match;

/**
 * Constants
 */
pub const MAX_ORDERS: usize = 20;
pub const MAX_BALANCES: usize = 20;
pub const MAX_MATCHES: usize = MAX_ORDERS * MAX_ORDERS;
pub type SystemField = ark_ed_on_bn254::Fr;

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
        wallet1_hash: u64,
        wallet2_hash: u64,
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

    // Generates the circuit constraints using the witness supplied in the constructor
    pub fn generate_constraints(&self, cs: ConstraintSystemRef<SystemField>) -> Result<(), SynthesisError> {
        self.wrapped_type
            .take()
            .generate_constraints(cs)
    }

    // Returns the matches produced by circuit evaluation and caches the result
    pub fn get_matches(&mut self) -> &Option<MatchResult> {
        // Lift the value to the wrapper struct; allow it to be consumed multiple times
        if self.match_result.is_none() {
            self.match_result = self.match_cell.take()
        }

        &self.match_result
    }

    // Returns the hash of the matches produced by circuit evaluation and caches the result
    pub fn get_match_hash(&mut self) -> &Option<u64> {
        // Lift the value to the wrapper struct; allow it to be consumed multiple times
        if self.match_hash.is_none() {
            self.match_hash = self.match_hash_cell.take();
        }

        &self.match_hash
    }
}


#[derive(Debug)]
struct ValidMatchCircuitImpl<F: PrimeField> {
    // Input variables
    wallet1: Wallet,
    wallet2: Wallet,
    wallet1_hash: u64,
    wallet2_hash: u64,

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
            wallet1_hash: 0,
            wallet2_hash: 0,
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
        wallet1_hash: u64,
        wallet2_hash: u64,
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
        let uint_hash1 = UInt64::new_input(
            cs.clone(), 
            || Ok(&self.wallet1_hash)
        )?;
        let expected_hash_1 = Boolean::le_bits_to_fp_var(&uint_hash1.to_bits_le())?;

        let uint_hash2 = UInt64::new_input(
            cs.clone(), 
            || Ok(&self.wallet2_hash)
        )?;
        let expected_hash_2 = Boolean::le_bits_to_fp_var(&uint_hash2.to_bits_le())?;

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

        let mut wallet2_hasher = PoseidonSpongeWrapperVar::new(cs.clone());
        let wallet2_hash_input = Result::<WalletHashInput<F>, SynthesisError>::from(&wallet2_var)?;

        let wallet2_hash = PoseidonVectorHashGadget::evaluate(&wallet2_hash_input, &mut wallet2_hasher)?;

        // Compare hashes
        wallet1_hash.enforce_equal(&expected_hash_1)?;
        wallet2_hash.enforce_equal(&expected_hash_2)?;

        // Extract the match hash and the matches result
        self.match_cell.replace(Some(matches_result.value()?));
        self.match_hash_cell.replace(
            Some(
                UInt64::from_bits_le(&match_hash.to_bits_le()?[0..64]).value()?
            )
        );
        
        Ok(())
    }
}

/**
 * Tests
 */
#[cfg(test)]
mod test {
    use ark_relations::r1cs::ConstraintSystem;
    use ark_sponge::{poseidon::PoseidonSponge, CryptographicSponge};

    use super::{types::{Wallet, Order, OrderSide}, poseidon::PoseidonSpongeWrapperVar, SystemField, ValidMatchCircuit};

    // Helper to hash a wallet
    fn compute_wallet_hash(wallet: &Wallet) -> u64 {
        // Convert wallet to u64
        let mut hash_input = Vec::<u64>::new();
        for order in &wallet.orders {
            hash_input.append(&mut vec![order.base_mint, order.quote_mint, order.side.clone() as u64, order.price, order.amount]);
        }

        let mut sponge = PoseidonSponge::<SystemField>::new(&PoseidonSpongeWrapperVar::default_params());
        for input in hash_input.iter() {
            sponge.absorb(input)
        }

        let sponge_out = sponge.squeeze_field_elements::<SystemField>(1);

        // Convert to u64
        sponge_out[0].0.0[0]
    }

    #[test]
    fn test_extract_matches() {
        // Build the wallets
        let wallet1 = Wallet {
            balances: vec![],
            orders: vec![
                Order { 
                    quote_mint: 1, base_mint: 2, side: OrderSide::Buy, amount: 5, price: 10,
                }
            ]
        };

        let wallet2 = Wallet {
            balances: vec![],
            orders: vec![
                Order {
                    quote_mint: 1, base_mint: 2, side: OrderSide::Sell, amount: 3, price: 8,
                }
            ]
        };

        // Compute the hashes of the wallets for input
        let wallet1_hash = compute_wallet_hash(&wallet1);
        let wallet2_hash = compute_wallet_hash(&wallet2);

        // Create a constraint system
        let cs = ConstraintSystem::new_ref();

        // Run the circuit and generate its constraints
        let circuit = ValidMatchCircuit::new(wallet1, wallet2, wallet1_hash, wallet2_hash);
        circuit.generate_constraints(cs).unwrap();

        let matches = circuit.get_matches().unwrap();
        assert!(matches.matches1.len() == 2);
    }
}