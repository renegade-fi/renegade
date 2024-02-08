//! Defines wallet types useful throughout the workspace

use std::{
    collections::HashSet,
    iter,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use circuit_types::{
    balance::Balance,
    fee::Fee,
    keychain::{PublicKeyChain, SecretIdentificationKey, SecretSigningKey},
    native_helpers::{
        compute_wallet_private_share_commitment, compute_wallet_share_commitment,
        compute_wallet_share_nullifier, create_wallet_shares_from_private,
        wallet_from_blinded_shares,
    },
    order::{Order, OrderSide},
    r#match::MatchResult,
    traits::BaseType,
    wallet::{Nullifier, SizedWallet, WalletShare, WalletShareStateCommitment},
    SizedWallet as SizedCircuitWallet, SizedWalletShare,
};
use constants::{Scalar, MAX_BALANCES, MAX_FEES, MAX_ORDERS};
use derivative::Derivative;
use itertools::Itertools;
use num_bigint::BigUint;
use renegade_crypto::hash::evaluate_hash_chain;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::keyed_list::KeyedList;

use super::{gossip::WrappedPeerId, merkle::MerkleAuthenticationPath};

/// A type alias for the wallet identifier type, currently a UUID
pub type WalletIdentifier = Uuid;
/// An identifier of an order used for caching
pub type OrderIdentifier = Uuid;

/// Error message emitted when the balances of a wallet are full
const ERR_BALANCES_FULL: &str = "balances full";
/// Error message emitted when a balance overflows
const ERR_BALANCE_OVERFLOW: &str = "balance overflowed";
/// Error message emitted when the orders of a wallet are full
const ERR_ORDERS_FULL: &str = "orders full";

/// Represents the private keys a relayer has access to for a given wallet
#[derive(Clone, Debug, Derivative, Serialize, Deserialize)]
#[derivative(PartialEq, Eq)]
pub struct PrivateKeyChain {
    /// Optionally the relayer holds sk_root, in which case the relayer has
    /// heightened permissions than the standard case
    ///
    /// We call such a relayer a "super relayer"
    pub sk_root: Option<SecretSigningKey>,
    /// The match private key, authorizes the relayer to match orders for the
    /// wallet
    pub sk_match: SecretIdentificationKey,
}

/// Represents the public and private keys given to the relayer managing a
/// wallet
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyChain {
    /// The public keys in the wallet
    pub public_keys: PublicKeyChain,
    /// The secret keys in the wallet
    pub secret_keys: PrivateKeyChain,
}

/// The Merkle opening from the wallet shares' commitment to the global root
pub type WalletAuthenticationPath = MerkleAuthenticationPath;

/// Represents a wallet managed by the local relayer
#[derive(Clone, Debug, Serialize, Derivative, Deserialize)]
#[derivative(PartialEq)]
pub struct Wallet {
    /// The identifier used to index the wallet
    pub wallet_id: WalletIdentifier,
    /// A list of orders in this wallet
    ///
    /// We use an `IndexMap` here to preserve the order of insertion
    /// on the orders. This is necessary because we must have
    /// order parity with the secret shared wallet stored on-chain
    pub orders: KeyedList<OrderIdentifier, Order>,
    /// A mapping of mint to Balance information
    pub balances: KeyedList<BigUint, Balance>,
    /// A list of the fees in this wallet
    pub fees: Vec<Fee>,
    /// The keys that the relayer has access to for this wallet
    pub key_chain: KeyChain,
    /// The wallet blinder, used to blind secret shares the wallet holds
    pub blinder: Scalar,
    /// Wallet metadata; replicas, trusted peers, etc
    pub metadata: WalletMetadata,
    /// The private secret shares of the wallet
    pub private_shares: SizedWalletShare,
    /// The public secret shares of the wallet
    pub blinded_public_shares: SizedWalletShare,
    /// The authentication paths for the public and private shares of the wallet
    #[serde(default)]
    pub merkle_proof: Option<WalletAuthenticationPath>,
    /// The staleness of the Merkle proof, i.e. the number of Merkle root
    /// updates that have occurred since the wallet's Merkle proof was last
    /// updated
    #[serde(skip_serializing, skip_deserializing, default)]
    #[derivative(PartialEq = "ignore")]
    pub merkle_staleness: Arc<AtomicUsize>,
}

impl From<Wallet> for SizedCircuitWallet {
    fn from(wallet: Wallet) -> Self {
        SizedCircuitWallet {
            balances: wallet
                .balances
                .into_values()
                .chain(iter::repeat(Balance::default()))
                .take(MAX_BALANCES)
                .collect_vec()
                .try_into()
                .unwrap(),
            orders: wallet
                .orders
                .into_values()
                .chain(iter::repeat(Order::default()))
                .take(MAX_ORDERS)
                .collect_vec()
                .try_into()
                .unwrap(),
            fees: wallet
                .fees
                .into_iter()
                .chain(iter::repeat(Fee::default()))
                .take(MAX_FEES)
                .collect_vec()
                .try_into()
                .unwrap(),
            keys: wallet.key_chain.public_keys,
            blinder: wallet.blinder,
        }
    }
}

impl Wallet {
    // -----------
    // | Getters |
    // -----------

    /// Check that the wallet's shares correctly add to its contents
    pub fn check_wallet_shares(&self) -> bool {
        let circuit_wallet: SizedWallet = self.clone().into();
        let recovered_wallet =
            wallet_from_blinded_shares(&self.private_shares, &self.blinded_public_shares);

        circuit_wallet == recovered_wallet
    }

    /// Computes the commitment to the private shares of the wallet
    pub fn get_private_share_commitment(&self) -> WalletShareStateCommitment {
        compute_wallet_private_share_commitment(&self.private_shares)
    }

    /// Compute the commitment to the full wallet shares
    pub fn get_wallet_share_commitment(&self) -> WalletShareStateCommitment {
        compute_wallet_share_commitment(&self.blinded_public_shares, &self.private_shares)
    }

    /// Compute the wallet nullifier
    pub fn get_wallet_nullifier(&self) -> Nullifier {
        compute_wallet_share_nullifier(self.get_wallet_share_commitment(), self.blinder)
    }

    /// Invalidate the Merkle opening of a wallet after an update
    fn invalidate_merkle_opening(&mut self) {
        self.merkle_proof = None;
        self.merkle_staleness.store(0, Ordering::Relaxed);
    }

    /// Returns whether any of the orders in the wallet are eligible for
    /// matching
    ///
    /// This amounts to non-default orders with non-zero balances to cover them
    pub fn has_orders_to_match(&self) -> bool {
        for order in self.orders.values() {
            let send_mint = order.send_mint();
            let has_balance = match self.balances.get(send_mint) {
                Some(balance) => balance.amount > 0,
                None => false,
            };

            // If a single non-default order has a non-zero balance, we can match on it
            if !order.is_default() && has_balance {
                return true;
            }
        }

        false
    }

    // -----------
    // | Setters |
    // -----------

    /// Reblind the wallet, consuming the next set of blinders and secret shares
    pub fn reblind_wallet(&mut self) {
        let private_shares_serialized: Vec<Scalar> = self.private_shares.to_scalars();

        // Sample a new blinder and private secret share
        let n_shares = private_shares_serialized.len();
        let blinder_and_private_share =
            evaluate_hash_chain(private_shares_serialized[n_shares - 1], 2 /* length */);
        let new_blinder = blinder_and_private_share[0];
        let new_blinder_private_share = blinder_and_private_share[1];

        // Sample new secret shares for the wallet
        let mut new_private_shares =
            evaluate_hash_chain(private_shares_serialized[n_shares - 2], n_shares - 1);
        new_private_shares.push(new_blinder_private_share);

        let (new_private_share, new_public_share) = create_wallet_shares_from_private(
            &self.clone().into(),
            &WalletShare::from_scalars(&mut new_private_shares.into_iter()),
            new_blinder,
        );

        self.private_shares = new_private_share;
        self.blinded_public_shares = new_public_share;
        self.blinder = new_blinder;
        self.invalidate_merkle_opening();
    }

    /// Remove default balances, orders, fees
    pub fn remove_default_elements(&mut self) {
        self.balances.retain(|_mint, balance| !balance.is_default());
        self.orders.retain(|_id, order| !order.is_default());
        self.fees.retain(|fee| !fee.is_default());
    }

    // --- Balances --- //

    /// Add a balance to the wallet, replacing the first default balance
    pub fn add_balance(&mut self, balance: Balance) -> Result<(), String> {
        // If the balance exists, increment it
        if let Some(balance) = self.balances.get_mut(&balance.mint) {
            balance.amount = balance
                .amount
                .checked_add(balance.amount)
                .ok_or(ERR_BALANCE_OVERFLOW.to_string())?;
            return Ok(());
        }

        // Otherwise, add the balance
        if self.balances.len() < MAX_BALANCES {
            self.balances.insert(balance.mint.clone(), balance);
            return Ok(());
        }

        // If the balances are full, try to find a balance to overwrite
        let idx = self
            .balances
            .iter()
            .enumerate()
            .find_map(|(i, (_, balance))| balance.is_zero().then_some(i))
            .ok_or_else(|| ERR_BALANCES_FULL.to_string())?;
        self.balances.replace_at_index(idx, balance.mint.clone(), balance);

        Ok(())
    }

    // --- Orders --- //

    /// Add an order to the wallet, replacing the first default order if the
    /// wallet is full
    pub fn add_order(&mut self, id: Uuid, order: Order) -> Result<(), String> {
        // Append if the orders are not full
        if self.orders.len() < MAX_ORDERS {
            self.orders.insert(id, order);
            return Ok(());
        }

        // Otherwise try to find an order to overwrite
        let idx = self
            .orders
            .iter()
            .enumerate()
            .find_map(|(i, (_, order))| order.is_zero().then_some(i))
            .ok_or_else(|| ERR_ORDERS_FULL.to_string())?;
        self.orders.replace_at_index(idx, id, order);

        Ok(())
    }

    // --- Matches --- //

    /// Get the balance, fee, and fee_balance for an order by specifying the
    /// order directly
    ///
    /// We allow orders to be matched when undercapitalized; i.e. the respective
    /// balance does not cover the full volume of the order.
    pub fn get_balance_and_fee_for_order(&self, order: &Order) -> Option<(Balance, Fee, Balance)> {
        // The mint the local party will be spending if the order is matched
        let order_mint = match order.side {
            OrderSide::Buy => order.quote_mint.clone(),
            OrderSide::Sell => order.base_mint.clone(),
        };

        // Find a balance and fee to associate with this order
        // Choose the first fee for simplicity
        let balance = self.balances.get(&order_mint)?;

        // Choose the first non-default fee
        let fee = self.fees.iter().find(|fee| !fee.is_default())?;
        let fee_balance = self.balances.get(&fee.gas_addr.clone())?;
        if fee_balance.amount < fee.gas_token_amount {
            return None;
        }

        Some((balance.clone(), fee.clone(), fee_balance.clone()))
    }

    /// Settle a match on the given order into the wallet
    pub fn apply_match(
        &mut self,
        match_res: &MatchResult,
        order_id: &OrderIdentifier,
    ) -> Result<(), String> {
        // Subtract the matched volume from the order
        let order = self.orders.get_mut(order_id).unwrap();
        order.amount =
            order.amount.checked_sub(match_res.base_amount).expect("order volume underflow");

        // Select the correct mints and amounts based on the order side
        let base = match_res.base_mint.clone();
        let quote = match_res.quote_mint.clone();
        let bast_amt = match_res.base_amount;
        let quote_amt = match_res.quote_amount;
        let (send_mint, send_amount, receive_mint, receive_amount) = match order.side {
            OrderSide::Buy => (quote, quote_amt, base, bast_amt),
            OrderSide::Sell => (base, bast_amt, quote, quote_amt),
        };

        // Update the balances
        let send_balance = self.balances.get_mut(&send_mint).unwrap();
        send_balance.amount =
            send_balance.amount.checked_sub(send_amount).expect("balance underflow");

        if !self.balances.contains_key(&receive_mint) {
            self.add_balance(Balance { mint: receive_mint.clone(), amount: 0 })?;
        }

        let recv_balance = self.balances.get_mut(&receive_mint).unwrap();
        recv_balance.amount =
            recv_balance.amount.checked_add(receive_amount).expect("balance overflow");

        // Update the public shares of the wallet, reblinding the wallet should be done
        // separately
        let (_, new_public_share) = create_wallet_shares_from_private(
            &self.clone().into(),
            &self.private_shares,
            self.blinder,
        );
        self.blinded_public_shares = new_public_share;

        // Invalidate the Merkle opening
        self.invalidate_merkle_opening();
        Ok(())
    }

    /// Update a wallet from a given set of private and (blinded) public secret
    /// shares
    pub fn update_from_shares(
        &mut self,
        private_shares: &SizedWalletShare,
        blinded_public_shares: &SizedWalletShare,
    ) {
        // Recover the wallet and update the balances, orders, fees
        let wallet = wallet_from_blinded_shares(private_shares, blinded_public_shares);

        self.blinder = wallet.blinder;
        self.balances = wallet.balances.into_iter().map(|b| (b.mint.clone(), b)).collect();

        // Preserve the order_ids, the indexmap should give a consistent ordering
        // between orders
        let order_ids = self.orders.keys().cloned();
        self.orders = order_ids.zip(wallet.orders).collect();

        self.fees = wallet.fees.to_vec();

        // Update the wallet shares
        self.private_shares = private_shares.clone();
        self.blinded_public_shares = blinded_public_shares.clone();

        // The Merkle proof is now invalid
        self.invalidate_merkle_opening();
    }
}

/// Metadata relevant to the wallet's network state
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletMetadata {
    /// The peers which are believed by the local node to be replicating a given
    /// wallet
    pub replicas: HashSet<WrappedPeerId>,
}

/// Defines mocks for the wallet used in testing
#[cfg(feature = "mocks")]
pub mod mocks {
    use std::{
        iter,
        sync::{atomic::AtomicUsize, Arc},
    };

    use circuit_types::{
        fixed_point::FixedPoint,
        keychain::{PublicKeyChain, PublicSigningKey, SecretIdentificationKey, SecretSigningKey},
        order::{Order, OrderSide},
        traits::BaseType,
        SizedWalletShare,
    };
    use constants::{Scalar, MERKLE_HEIGHT};
    use k256::ecdsa::SigningKey as K256SigningKey;
    use num_bigint::BigUint;
    use rand::thread_rng;
    use renegade_crypto::fields::scalar_to_biguint;
    use uuid::Uuid;

    use crate::{keyed_list::KeyedList, types::merkle::MerkleAuthenticationPath};

    use super::{KeyChain, PrivateKeyChain, Wallet, WalletMetadata};

    /// Create a mock empty wallet
    pub fn mock_empty_wallet() -> Wallet {
        // Create an initial wallet
        let mut rng = thread_rng();

        // Sample a valid signing key
        let key = K256SigningKey::random(&mut rng);
        let sk_root = Some(SecretSigningKey::from(&key));
        let pk_root = PublicSigningKey::from(key.verifying_key());

        let sk_match = SecretIdentificationKey::from(Scalar::random(&mut rng));
        let pk_match = sk_match.get_public_key();

        let mut wallet = Wallet {
            wallet_id: Uuid::new_v4(),
            orders: KeyedList::default(),
            balances: KeyedList::default(),
            fees: vec![],
            key_chain: KeyChain {
                public_keys: PublicKeyChain { pk_root, pk_match },
                secret_keys: PrivateKeyChain { sk_root, sk_match },
            },
            blinder: Scalar::random(&mut rng),
            private_shares: SizedWalletShare::from_scalars(&mut iter::repeat_with(|| {
                Scalar::random(&mut rng)
            })),
            blinded_public_shares: SizedWalletShare::from_scalars(&mut iter::repeat_with(|| {
                Scalar::random(&mut rng)
            })),
            metadata: WalletMetadata::default(),
            merkle_proof: Some(mock_merkle_path()),
            merkle_staleness: Arc::new(AtomicUsize::default()),
        };

        // Reblind the wallet so that the secret shares a valid sharing of the wallet
        wallet.reblind_wallet();
        wallet
    }

    /// Create a mock order
    pub fn mock_order() -> Order {
        let mut rng = thread_rng();
        let quote_mint = scalar_to_biguint(&Scalar::random(&mut rng));
        let base_mint = scalar_to_biguint(&Scalar::random(&mut rng));
        let amount = 10u64;
        let worst_case_price = FixedPoint::from_integer(100);
        let timestamp = 0u64;

        Order { quote_mint, base_mint, amount, worst_case_price, timestamp, side: OrderSide::Buy }
    }

    /// Create a mock Merkle path for a wallet
    pub fn mock_merkle_path() -> MerkleAuthenticationPath {
        let mut rng = thread_rng();
        MerkleAuthenticationPath::new(
            [Scalar::random(&mut rng); MERKLE_HEIGHT],
            BigUint::from(0u8),
            Scalar::random(&mut rng),
        )
    }
}

#[cfg(test)]
mod test {
    use circuit_types::balance::Balance;
    use constants::{MAX_BALANCES, MAX_ORDERS};
    use num_bigint::BigUint;
    use rand::{distributions::uniform::SampleRange, thread_rng};
    use uuid::Uuid;

    use super::mocks::{mock_empty_wallet, mock_order};

    /// Tests adding a balance to an empty wallet
    #[test]
    fn test_add_balance_append() {
        let mut wallet = mock_empty_wallet();
        let balance1 = Balance { mint: BigUint::from(1u8), amount: 10 };
        let balance2 = Balance { mint: BigUint::from(2u8), amount: 10 };
        wallet.add_balance(balance1.clone()).unwrap();
        wallet.add_balance(balance2.clone()).unwrap();

        assert_eq!(wallet.balances.len(), 2);
        assert_eq!(wallet.balances.index_of(&balance2.mint), Some(1));
    }

    /// Tests adding a balance when one already exists in the wallet
    #[test]
    fn test_add_balance_existing() {
        let mut wallet = mock_empty_wallet();
        let balance1 = Balance { mint: BigUint::from(1u8), amount: 10 };
        let balance2 = Balance { mint: BigUint::from(1u8), amount: 10 };
        wallet.add_balance(balance1.clone()).unwrap();
        wallet.add_balance(balance2.clone()).unwrap();

        assert_eq!(wallet.balances.len(), 1);
        assert_eq!(wallet.balances.index_of(&balance1.mint), Some(0));
        assert_eq!(wallet.balances.get(&balance1.mint).unwrap().amount, 20);
    }

    /// Tests adding a balance that overrides a zero'd balance
    #[test]
    fn test_add_balance_overwrite() {
        let mut wallet = mock_empty_wallet();

        // Fill the wallet
        for i in 0..MAX_BALANCES {
            let balance = Balance { mint: BigUint::from(i), amount: 10 };
            wallet.add_balance(balance).unwrap();
        }

        // Zero a random balance
        let mut rng = thread_rng();
        let idx = (0..MAX_BALANCES).sample_single(&mut rng);
        wallet.balances.get_index_mut(idx).unwrap().amount = 0;

        // Add a new balance
        let balance = Balance { mint: BigUint::from(42u8), amount: 10 };
        wallet.add_balance(balance.clone()).unwrap();

        // Check that the balance overrode the correct idx
        assert_eq!(wallet.balances.index_of(&balance.mint), Some(idx));
    }

    /// Tests adding a balance when the wallet is full
    #[test]
    #[should_panic(expected = "balances full")]
    fn test_add_balance_full() {
        let mut wallet = mock_empty_wallet();

        // Fill the wallet
        for i in 0..MAX_BALANCES {
            let balance = Balance { mint: BigUint::from(i), amount: 10 };
            wallet.add_balance(balance).unwrap();
        }

        // Attempt to add another balance
        let balance = Balance { mint: BigUint::from(42u8), amount: 10 };
        wallet.add_balance(balance).unwrap();
    }

    /// Tests adding an order that appends to the wallet
    #[test]
    fn test_add_order_append() {
        let mut wallet = mock_empty_wallet();

        // Add two orders to the wallet
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let order1 = mock_order();
        let order2 = mock_order();
        wallet.add_order(id1, order1).unwrap();
        wallet.add_order(id2, order2).unwrap();

        // Check that the orders were added
        assert_eq!(wallet.orders.len(), 2);
        assert_eq!(wallet.orders.index_of(&id1), Some(0));
        assert_eq!(wallet.orders.index_of(&id2), Some(1));
    }

    /// Tests adding an order that overwrites a default order
    #[test]
    fn test_add_order_overwrite() {
        let mut wallet = mock_empty_wallet();

        // Fill the orders with default orders
        for _ in 0..MAX_ORDERS {
            let id = Uuid::new_v4();
            let order = mock_order();
            wallet.add_order(id, order).unwrap();
        }

        // Zero a random order
        let mut rng = thread_rng();
        let idx = (0..MAX_ORDERS).sample_single(&mut rng);
        wallet.orders.get_index_mut(idx).unwrap().amount = 0;

        // Add a new order
        let id = Uuid::new_v4();
        let order = mock_order();
        wallet.add_order(id, order).unwrap();

        // Check that the order overrode the correct idx
        assert_eq!(wallet.orders.index_of(&id), Some(idx));
    }

    /// Tests adding an order when the wallet is full
    #[test]
    #[should_panic(expected = "orders full")]
    fn test_add_order_full() {
        let mut wallet = mock_empty_wallet();

        // Fill the wallet
        for _ in 0..MAX_ORDERS {
            let id = Uuid::new_v4();
            let order = mock_order();
            wallet.add_order(id, order).unwrap();
        }

        // Attempt to add another order
        let id = Uuid::new_v4();
        let order = mock_order();
        wallet.add_order(id, order).unwrap();
    }
}
