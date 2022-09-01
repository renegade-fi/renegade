use std::{marker::PhantomData, cell::RefCell};

use ark_ec::PairingEngine;
use ark_ff::PrimeField;
use ark_groth16::{ProvingKey, Proof, create_random_proof, generate_random_parameters};
use ark_r1cs_std::{prelude::{AllocVar, Boolean, EqGadget}, uint64::UInt64};
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError, ConstraintSystemRef};
use rand::rngs::OsRng;

use crate::{types::{MatchResult, Balance, Order, MatchResultVariable, BalanceVar, OrderVar, SystemField, SystemPairingEngine, OrderSide, Match, SingleMatchResult, SingleMatchResultVar}, gadgets::{util::GreaterThanEqGadget, covered_match::ValidMatchGadget}};


/**
 * Defines a smaller version of the ValidMatch circuit
 * that involves 4 low-depth Merkle proofs, and range checks
 */

pub struct SmallValidMatchCircuit {
    // Inputs
    matches: SingleMatchResult,
    balance1: Balance,
    balance2: Balance,
    order1: Order,
    order2: Order,

    // Circuit implementation
    circuit: RefCell<SmallValidMatchCircuitImpl<SystemField>>
}

impl SmallValidMatchCircuit {
    pub fn new(
        matches: SingleMatchResult,
        balance1: Balance,
        balance2: Balance,
        order1: Order,
        order2: Order,
    ) -> Self {
        let circuit = RefCell::new(
            SmallValidMatchCircuitImpl::new(
                matches.clone(), balance1.clone(), balance2.clone(), order1.clone(), order2.clone()
            )
        );

        Self { matches, balance1, balance2, order1, order2, circuit }
    }

    // Creates a proving key for the proof system given a circuit size
    pub fn create_proving_key() -> Result<ProvingKey<SystemPairingEngine>, SynthesisError> {
        let mut rng = OsRng{};

        // Create dummy variables, proving key is not witness specific
        let dummy_match = Match { mint: 0, amount: 0, side: OrderSide::Buy };
        let dummy_single_match = SingleMatchResult {
            buy_side1: dummy_match.clone(),
            sell_side1: dummy_match.clone(),
            buy_side2: dummy_match.clone(),
            sell_side2: dummy_match
        };
        let dummy_balance = Balance { mint: 0, amount: 0 };
        let dummy_order = Order { quote_mint: 0, base_mint: 0, side: OrderSide::Buy, amount: 0, price: 0 };

        let dummy_circuit = SmallValidMatchCircuitImpl::new(
            dummy_single_match, 
            dummy_balance.clone(), 
            dummy_balance, 
            dummy_order.clone(), 
            dummy_order
        );

        generate_random_parameters(dummy_circuit, &mut rng)
    }

    // Generates the circuit constraints using the witness supplied in the constructor
    pub fn generate_constraints(&self, cs: ConstraintSystemRef<SystemField>) -> Result<(), SynthesisError> {
        self.circuit
            .take()
            .generate_constraints(cs)
    }

    pub fn create_proof<E: PairingEngine<Fr = SystemField>>(
        &mut self, proving_key: &ProvingKey<E>
    ) -> Result<Proof<E>, SynthesisError> {
        // let circuit = self.wrapped_type.take();
        let mut rng = OsRng{};

        create_random_proof(self.circuit.take(), proving_key, &mut rng)
    }
}

#[derive(Clone, Debug, Default)]
struct SmallValidMatchCircuitImpl<F: PrimeField> {
    // Inputs
    matches: SingleMatchResult,
    balance1: Balance,
    balance2: Balance,
    order1: Order,
    order2: Order,

    // Phantom
    _phantom: PhantomData<F>
}

impl<F: PrimeField> SmallValidMatchCircuitImpl<F> {
   fn new(
        matches: SingleMatchResult,
        balance1: Balance,
        balance2: Balance,
        order1: Order,
        order2: Order,
    ) -> Self {
        Self { matches, balance1, balance2, order1, order2, _phantom: PhantomData }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for SmallValidMatchCircuitImpl<F> {
    fn generate_constraints(
        self, 
        cs: ark_relations::r1cs::ConstraintSystemRef<F>
    ) -> Result<(), SynthesisError> {
        // The witness variables
        let single_match_var = SingleMatchResultVar::new_witness(cs.clone(), || { Ok(self.matches) })?;

        let balance1_var = BalanceVar::new_witness(cs.clone(), || { Ok(self.balance1) })?;
        let balance2_var = BalanceVar::new_witness(cs.clone(), || { Ok(self.balance2 )})?;

        let order1_var = OrderVar::new_witness(cs.clone(), || { Ok(self.order1) })?;
        let order2_var = OrderVar::new_witness(cs.clone(), || { Ok(self.order2) })?;

        // Check that
        // 1. The match is internally valid (sells match buys)
        // 2. The match is backed by two valid balances
        // 3. The match is a result of two valid orders
        ValidMatchGadget::enforce_valid(&single_match_var)?;
        ValidMatchGadget::enforce_valid_balances(&single_match_var, &balance1_var, &balance2_var)?;
        ValidMatchGadget::enforce_valid_orders(&single_match_var, &order1_var, &order2_var)?;
        
        // Validate the orders and balances in the state tree
        
        Ok(())
    }
}


#[cfg(test)]
mod small_valid_match_test {
    use ark_groth16::{prepare_verifying_key, verify_proof};

    use crate::types::{Order, OrderSide, Balance, Match, SingleMatchResult};

    use super::SmallValidMatchCircuit;

    #[test]
    fn test_match() {
        // Create fake overlapping orders with a midpoint price of 10 quote/base and 4 base tokens transferred
        let QUOTE_MINT = 1;
        let BASE_MINT = 2;

        let order1 = Order { quote_mint: QUOTE_MINT, base_mint: BASE_MINT, side: OrderSide::Buy, amount: 5, price: 11 };
        let order2 = Order { quote_mint: QUOTE_MINT, base_mint: BASE_MINT, side: OrderSide::Sell, amount: 3, price: 9 };

        let balance1 = Balance { mint: QUOTE_MINT, amount: 50 };
        let balance2 = Balance { mint: BASE_MINT, amount: 3 };

        let match_result = SingleMatchResult {
            buy_side1: Match { mint: BASE_MINT, amount: 3, side: OrderSide::Buy },
            sell_side1: Match { mint: QUOTE_MINT, amount: 30, side: OrderSide::Sell },
            buy_side2: Match { mint: QUOTE_MINT, amount: 30, side: OrderSide::Buy },
            sell_side2: Match { mint: BASE_MINT, amount: 3, side: OrderSide::Sell },
        };

        // Create a circuit and verify that it is satisfied
        let mut circuit = SmallValidMatchCircuit::new(match_result, balance1, balance2, order1, order2);
        let proving_key = SmallValidMatchCircuit::create_proving_key().unwrap();

        let proof = circuit.create_proof(&proving_key).unwrap();

        let verifying_key = prepare_verifying_key(&proving_key.vk);
        let verification_result = verify_proof(&verifying_key, &proof, &vec![]).unwrap();

        assert!(verification_result)
    }
}

