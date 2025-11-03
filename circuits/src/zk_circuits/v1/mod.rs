//! Zero-knowledge circuit definitions for the Renegade v1 protocol

#![allow(missing_docs, clippy::missing_docs_in_private_items)]

pub mod proof_linking;
pub mod valid_commitments;
pub mod valid_fee_redemption;
pub mod valid_malleable_match_settle_atomic;
pub mod valid_match_settle;
pub mod valid_match_settle_atomic;
pub mod valid_offline_fee_settlement;
pub mod valid_reblind;
pub mod valid_relayer_fee_settlement;
pub mod valid_wallet_create;
pub mod valid_wallet_update;

use circuit_types::{
    Fabric, MpcPlonkCircuit, PlonkCircuit,
    traits::{
        BaseType, CircuitBaseType, MpcType, MultiProverCircuit, MultiproverCircuitBaseType,
        SingleProverCircuit,
    },
};
use constants::Scalar;
use itertools::Itertools;
use mpc_relation::{proof_linking::LinkableCircuit, traits::Circuit};

/// The group name for the VALID REBLIND <-> VALID COMMITMENTS link
pub const VALID_REBLIND_COMMITMENTS_LINK: &str = "valid_reblind_commitments";
/// The group for the VALID COMMITMENTS <-> VALID MATCH SETTLE (party 0) link
pub const VALID_COMMITMENTS_MATCH_SETTLE_LINK0: &str = "valid_commitments_match_settle0";
/// The group for the VALID COMMITMENTS <-> VALID MATCH SETTLE (party 1) link
pub const VALID_COMMITMENTS_MATCH_SETTLE_LINK1: &str = "valid_commitments_match_settle1";

// -----------
// | Helpers |
// -----------

/// Check whether a witness and statement satisfy wire assignments for a
/// circuit
pub fn check_constraint_satisfaction<C: SingleProverCircuit>(
    witness: &C::Witness,
    statement: &C::Statement,
) -> bool {
    // Apply the constraints
    let mut cs = PlonkCircuit::new_turbo_plonk();
    let circuit_layout = C::get_circuit_layout().unwrap();
    for (id, layout) in circuit_layout.group_layouts.into_iter() {
        cs.create_link_group(id, Some(layout));
    }

    let witness_var = witness.create_witness(&mut cs);
    let statement_var = statement.create_public_var(&mut cs);

    C::apply_constraints(witness_var, statement_var, &mut cs).unwrap();

    // Check for satisfaction
    let statement_scalars = statement.to_scalars().iter().map(Scalar::inner).collect_vec();
    cs.check_circuit_satisfiability(&statement_scalars).is_ok()
}

/// Check whether a witness and statement satisfy wire assignments for a
/// multiprover circuit
pub fn check_constraint_satisfaction_multiprover<C: MultiProverCircuit>(
    witness: &C::Witness,
    statement: &C::Statement,
    fabric: &Fabric,
) -> bool {
    let mut cs = MpcPlonkCircuit::new(fabric.clone());
    let circuit_layout = C::get_circuit_layout().unwrap();
    for (id, layout) in circuit_layout.group_layouts.into_iter() {
        cs.create_link_group(id, Some(layout));
    }

    let witness_var = witness.create_shared_witness(&mut cs);
    let statement_var = statement.create_shared_public_var(&mut cs);

    C::apply_constraints_multiprover(witness_var, statement_var, fabric, &mut cs).unwrap();

    // Check for satisfaction
    let statement_scalars = statement.to_authenticated_scalars();
    cs.check_circuit_satisfiability(&statement_scalars).is_ok()
}

#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    use std::iter::{self, from_fn};

    use circuit_types::csprng_state::PoseidonCSPRNG;
    use circuit_types::{
        Address, Amount,
        balance::Balance,
        elgamal::{DecryptionKey, EncryptionKey},
        fixed_point::FixedPoint,
        keychain::{NUM_KEYS, NonNativeScalar, PublicKeyChain, PublicSigningKey},
        r#match::{MatchResult, OrderSettlementIndices},
        merkle::MerkleOpening,
        native_helpers::create_wallet_shares_with_randomness,
        order::{Order, OrderSide},
        wallet::{Wallet, WalletShare},
    };
    use constants::Scalar;
    use itertools::Itertools;
    use lazy_static::lazy_static;
    use num_bigint::BigUint;
    use rand::thread_rng;
    use renegade_crypto::{fields::scalar_to_biguint, hash::compute_poseidon_hash};
    use util::matching_engine::match_orders_with_max_min_amounts;

    // --------------
    // | Dummy Data |
    // --------------

    lazy_static! {
        // The key data for the wallet, note that only the identification keys are currently
        // computed correctly
        pub static ref PRIVATE_KEYS: Vec<Scalar> = vec![Scalar::one(); NUM_KEYS];
        pub static ref PUBLIC_KEYS: PublicKeyChain = PublicKeyChain {
            pk_root: PublicSigningKey {
                x: NonNativeScalar::from(&BigUint::from(2u8).pow(256)),
                y: NonNativeScalar::from(&BigUint::from(2u8).pow(256)),
            },
            pk_match: compute_poseidon_hash(&[PRIVATE_KEYS[1]]).into(),
            nonce: 0u8.into(),
        };
        pub static ref INITIAL_BALANCES: [Balance; MAX_BALANCES] = [
            Balance { mint: 1u8.into(), amount: 5, relayer_fee_balance: 0, protocol_fee_balance: 0 },
            Balance {
                mint: 2u8.into(),
                amount: 10,
                relayer_fee_balance: 0,
                protocol_fee_balance: 0
            }
        ];
        pub static ref INITIAL_ORDERS: [Order; MAX_ORDERS] = [
            Order {
                quote_mint: 1u8.into(),
                base_mint: 2u8.into(),
                side: OrderSide::Buy,
                amount: 1,
                // No price limit by default
                worst_case_price: FixedPoint::from_integer(100000),
            },
            Order {
                quote_mint: 1u8.into(),
                base_mint: 3u8.into(),
                side: OrderSide::Sell,
                amount: 10,
                // No price limit by default
                worst_case_price: FixedPoint::from_integer(0),
            }
        ];
        pub static ref INITIAL_WALLET: SizedWallet = Wallet {
            balances: INITIAL_BALANCES.clone(),
            orders: INITIAL_ORDERS.clone(),
            keys: PUBLIC_KEYS.clone(),
            max_match_fee: FixedPoint::from_f64_round_down(0.002), // 20 bps
            managing_cluster: DecryptionKey::random_pair(&mut thread_rng()).1,
            blinder: Scalar::from(42u64)
        };

        /// The protocol encryption key used for testing
        pub static ref PROTOCOL_KEY: EncryptionKey = {
            let mut rng = thread_rng();
            let (_, enc) = DecryptionKey::random_pair(&mut rng);
            enc
        };

    }

    // -------------
    // | Constants |
    // -------------

    /// The maximum number of balances allowed in a wallet for tests
    pub const MAX_BALANCES: usize = 2;
    /// The maximum number of orders allowed in a wallet for tests
    pub const MAX_ORDERS: usize = 2;

    pub type SizedWallet = Wallet<MAX_BALANCES, MAX_ORDERS>;
    pub type SizedWalletShare = WalletShare<MAX_BALANCES, MAX_ORDERS>;

    // -----------
    // | Helpers |
    // -----------

    /// Get a random address
    pub(crate) fn random_address() -> Address {
        let random_u128 = rand::random::<u128>();
        Address::from_bytes_be(random_u128.to_be_bytes().as_slice())
    }

    /// Construct secret shares of a wallet for testing
    pub fn create_wallet_shares<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
        wallet: &Wallet<MAX_BALANCES, MAX_ORDERS>,
    ) -> (WalletShare<MAX_BALANCES, MAX_ORDERS>, WalletShare<MAX_BALANCES, MAX_ORDERS>) {
        // Sample a random secret share for the blinder
        let mut rng = thread_rng();
        let blinder_share = Scalar::random(&mut rng);

        let blinder = wallet.blinder;
        create_wallet_shares_with_randomness(
            wallet,
            blinder,
            blinder_share,
            from_fn(|| Some(Scalar::random(&mut rng))),
        )
    }

    /// Construct secret shares of a wallet with a given blinder seed
    pub fn create_wallet_shares_with_blinder_seed<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
    >(
        wallet: &mut Wallet<MAX_BALANCES, MAX_ORDERS>,
        blinder_seed: Scalar,
    ) -> (WalletShare<MAX_BALANCES, MAX_ORDERS>, WalletShare<MAX_BALANCES, MAX_ORDERS>) {
        let mut rng = thread_rng();
        let mut csprng = PoseidonCSPRNG::new(blinder_seed);
        let (blinder, private_share) = csprng.next_tuple().unwrap();

        wallet.blinder = blinder;
        let shares = from_fn(|| Some(Scalar::random(&mut rng)));
        create_wallet_shares_with_randomness(wallet, blinder, private_share, shares)
    }

    // ---------------------
    // | Helper Validation |
    // ---------------------

    /// Test the Merkle tree root
    #[test]
    fn test_multi_opening_root() {
        const HEIGHT: usize = 2; // capacity 4 merkle tree
        let leaves = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        let (root, _) = create_multi_opening::<HEIGHT>(&leaves);

        // Compute the expected root
        let expected_root = compute_poseidon_hash(&[
            compute_poseidon_hash(&[Scalar::from(1u64), Scalar::from(2u64)]),
            compute_poseidon_hash(&[Scalar::from(3u64), Scalar::zero()]),
        ]);

        assert_eq!(root, expected_root);
    }

    /// Test the Merkle tree opening
    #[test]
    fn test_multi_opening_path() {
        const HEIGHT: usize = 3; // capacity 8 merkle tree
        let leaves = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        let (_, openings) = create_multi_opening::<HEIGHT>(&leaves);

        // Compute the expected opening for the first element
        let hash_3_and_0 = compute_poseidon_hash(&[Scalar::from(3u64), Scalar::zero()]);
        let hash_0_and_0 = compute_poseidon_hash(&[Scalar::zero(), Scalar::zero()]);
        let hash_0_four_times = compute_poseidon_hash(&[hash_0_and_0, hash_0_and_0]);

        // The expected opening for the first element
        let expected_first_opening = vec![Scalar::from(2u64), hash_3_and_0, hash_0_four_times];
        assert_eq!(openings[0].elems.to_vec(), expected_first_opening);

        let expected_second_opening = vec![Scalar::from(1u64), hash_3_and_0, hash_0_four_times];
        assert_eq!(openings[1].elems.to_vec(), expected_second_opening);
    }

    /// Test the path indices of the Merkle opening
    #[test]
    fn test_multi_opening_indices() {
        const HEIGHT: usize = 3; // capacity 8 merkle tree
        let leaves = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        let (_, openings) = create_multi_opening::<HEIGHT>(&leaves);

        // Check the indices
        let expected_first_indices = vec![false, false, false];
        assert_eq!(openings[0].indices.to_vec(), expected_first_indices);

        let expected_second_indices = vec![true, false, false];
        assert_eq!(openings[1].indices.to_vec(), expected_second_indices);

        let expected_third_indices = vec![false, true, false];
        assert_eq!(openings[2].indices.to_vec(), expected_third_indices);
    }

    /// Verify that the wallet shares helper correctly splits and recombines
    #[test]
    fn test_split_wallet_into_shares() {
        // Split into secret shares
        let wallet = INITIAL_WALLET.clone();
        let wallet_blinder = wallet.blinder;
        let (private_share, public_share) = create_wallet_shares(&wallet);

        // Unblind the public shares, recover from shares
        let unblinded_public_shares = public_share.unblind_shares(wallet_blinder);
        let recovered_wallet = private_share + unblinded_public_shares;

        assert_eq!(wallet, recovered_wallet);
    }

    /// Verify that reblinding a wallet creates valid secret shares of the
    /// underlying wallet
    #[test]
    fn test_reblind_wallet() {
        use circuit_types::native_helpers::reblind_wallet;

        let mut wallet = INITIAL_WALLET.clone();
        let (private_share, _) = create_wallet_shares(&wallet);

        // Reblind the shares
        let (reblinded_private_shares, reblinded_public_shares) =
            reblind_wallet(&private_share, &wallet);

        // Unblind the public shares, recover from shares
        let recovered_blinder = reblinded_public_shares.blinder + reblinded_private_shares.blinder;
        let unblinded_public_shares = reblinded_public_shares.unblind_shares(recovered_blinder);
        let recovered_wallet = reblinded_private_shares + unblinded_public_shares;

        wallet.blinder = recovered_blinder;
        assert_eq!(wallet, recovered_wallet);
    }

    // -----------
    // | Additional Helpers from lib.rs |
    // -----------

    /// Generate a random set of settlement indices
    pub fn random_indices() -> OrderSettlementIndices {
        let balance_send = random_index(MAX_BALANCES);
        let mut balance_receive = random_index(MAX_BALANCES);

        while balance_send == balance_receive {
            balance_receive = random_index(MAX_BALANCES);
        }

        OrderSettlementIndices { order: random_index(MAX_ORDERS), balance_send, balance_receive }
    }

    /// Generate a random index bounded by a max
    fn random_index(max: usize) -> usize {
        let mut rng = thread_rng();
        rng.gen_range(0..max)
    }

    /// Get a dummy set of wallet shares
    pub fn dummy_wallet_share<const MAX_BALANCES: usize, const MAX_ORDERS: usize>()
    -> WalletShare<MAX_BALANCES, MAX_ORDERS> {
        let mut iter = iter::from_fn(|| Some(Scalar::zero()));
        WalletShare::from_scalars(&mut iter)
    }

    /// Create a wallet with random zero'd balances
    pub fn wallet_with_random_balances<const MAX_BALANCES: usize, const MAX_FEES: usize>()
    -> Wallet<MAX_BALANCES, MAX_FEES> {
        let mut rng = thread_rng();
        let mut wallet = Wallet::<MAX_BALANCES, MAX_FEES>::default();

        for bal in wallet.balances.iter_mut() {
            let mint = scalar_to_biguint(&Scalar::random(&mut rng));
            *bal = Balance::new_from_mint(mint);
        }

        wallet
    }

    /// Get two random orders that cross along with their match result
    pub fn random_orders_and_match() -> (Order, Order, FixedPoint, MatchResult) {
        let mut rng = thread_rng();
        let quote_mint = scalar_to_biguint(&Scalar::random(&mut rng));
        let base_mint = scalar_to_biguint(&Scalar::random(&mut rng));

        let price = FixedPoint::from_f64_round_down(rng.gen_range(0.0..100.0));
        let base_amount = rng.next_u32() as u128;

        // Buy side
        let o1 = Order {
            quote_mint: quote_mint.clone(),
            base_mint: base_mint.clone(),
            side: OrderSide::Buy,
            amount: rng.gen_range(1..base_amount),
            worst_case_price: price + Scalar::from(2u8),
        };

        // Sell side
        let o2 = Order {
            quote_mint: quote_mint.clone(),
            base_mint: base_mint.clone(),
            side: OrderSide::Sell,
            amount: rng.gen_range(1..base_amount),
            worst_case_price: price - Scalar::from(2u8),
        };

        // Randomly permute the orders
        let (o1, o2) = if rng.gen_bool(0.5) { (o1, o2) } else { (o2, o1) };

        // Match orders assuming they are fully capitalized
        let match_res = match_orders_with_max_min_amounts(
            &o1,
            &o2,
            o1.amount,
            o2.amount,
            Amount::MIN, // min_quote_amount
            Amount::MIN, // min_base_amount
            price,
        )
        .unwrap();

        (o1, o2, price, match_res)
    }
}
