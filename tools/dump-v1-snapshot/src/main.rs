//! Decode every wallet from a v1 darkpool relayer snapshot's `wallet-info`
//! MDBX table and emit one JSONL row per wallet.
//!
//! Each row contains the fields both Track A (snapshot-balances sanity
//! check) and Track C (on-chain reconstruction) need downstream:
//!   - `wallet_id`
//!   - `balances` (mint, amount) — Track A's stage-1 input
//!   - `blinder`, `private_blinder_share`, `public_blinder` — for matching
//!      WalletUpdated events on-chain
//!   - `sk_root_k256_hex` (Option) — Track C derives blinder_seed +
//!      share_seed from this
//!   - `pk_root_uncompressed_hex` — for verifying Track C reconstruction
//!   - `symmetric_key_hex` — the HMAC key the user registered for API auth
//!   - `n_orders` — informational
//!
//! Output is a credential dump: it contains sk_root and symmetric_key for
//! every managed wallet. Treat the output file as max-sensitivity. Run
//! inside an isolated VM; do not write to shared mounts or backed-up paths.

use std::{
    io::{BufWriter, Write},
    path::PathBuf,
};

use clap::Parser;
use common::types::wallet::Wallet;
use eyre::{Result, WrapErr};
use k256::ecdsa::{SigningKey as K256SigningKey, VerifyingKey as K256VerifyingKey};
use serde::Serialize;
use state::storage::db::{DB, DbConfig};

/// Name of the wallets table in the relayer's MDBX database.
/// Mirrors `state::WALLETS_TABLE`, which is `pub(crate)`.
const WALLETS_TABLE_NAME: &str = "wallet-info";

#[derive(Parser, Debug)]
#[command(about = "Dump every wallet from a v1 relayer snapshot to JSONL")]
struct Cli {
    /// Path to the decompressed snapshot MDBX data file.
    #[arg(long)]
    snapshot: PathBuf,
    /// Output JSONL file. Defaults to stdout.
    #[arg(long, short)]
    out: Option<PathBuf>,
}

#[derive(Serialize)]
struct WalletOut {
    wallet_id: String,
    /// Current wallet blinder, hex (no `0x` prefix).
    blinder: String,
    /// Private share of the current blinder, hex.
    private_blinder_share: String,
    /// Public share of the current blinder (= blinder - private_blinder_share),
    /// hex. The on-chain `WalletUpdated(wallet_blinder_share)` event for the
    /// wallet's most recent update at snapshot time matches this value.
    public_blinder: String,
    /// Wallet nullifier at snapshot state: Poseidon(share_commitment, blinder).
    /// share_commitment = Poseidon(Poseidon(private_shares), public_shares).
    /// Match this against on-chain `NullifierSpent(uint256 indexed nullifier)`
    /// events between snapshot_block and attack_block to identify which
    /// wallets had post-snapshot activity. Does not require sk_root.
    nullifier: String,
    /// The public_blinder this wallet's next on-chain update will emit, computed
    /// by advancing the Poseidon hash chain (Wallet::next_public_blinder).
    /// Match against `WalletUpdated(uint256 indexed wallet_blinder_share)` to
    /// find the wallet's next post-snapshot tx. No sk_root required — the
    /// share/blinder streams advance deterministically from the wallet's
    /// current private_shares (see common/src/types/wallet/shares.rs:78-110).
    predicted_next_public_blinder: String,
    /// Per-mint balances at snapshot time. Zero-balance rows are kept for
    /// downstream invariant checks.
    balances: Vec<BalanceOut>,
    /// Whether the relayer holds sk_root for this wallet ("super relayer"
    /// mode). If false, the wallet cannot be on-chain-reconstructed by us
    /// and the user must self-recover.
    sk_root_present: bool,
    /// sk_root as raw 32-byte k256 SEC1 scalar, hex (no `0x` prefix).
    /// Null when sk_root_present is false.
    sk_root_k256_hex: Option<String>,
    /// pk_root as uncompressed SEC1 (65 bytes: 0x04 || x || y), hex.
    pk_root_uncompressed_hex: String,
    /// 32-byte HMAC key registered by the user for API auth, hex.
    symmetric_key_hex: String,
    /// Number of orders in the wallet (orders themselves not exposed).
    n_orders: usize,
}

#[derive(Serialize)]
struct BalanceOut {
    /// ERC-20 mint as a 0x-prefixed hex address.
    mint: String,
    /// Atomic units, decimal string (u128).
    amount: String,
}

fn scalar_hex(s: &constants::Scalar) -> String {
    renegade_crypto::fields::scalar_to_biguint(s).to_str_radix(16)
}

fn sk_root_k256_hex(
    sk: &circuit_types::keychain::SecretSigningKey,
) -> Option<String> {
    let k = K256SigningKey::try_from(sk).ok()?;
    Some(hex::encode(k.to_bytes()))
}

fn pk_root_uncompressed_hex(
    pk: &circuit_types::keychain::PublicSigningKey,
) -> String {
    let vk: K256VerifyingKey = pk.into();
    let encoded = vk.to_encoded_point(false /* compress */);
    hex::encode(encoded.as_bytes())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let path = cli
        .snapshot
        .canonicalize()
        .wrap_err_with(|| format!("could not canonicalize {:?}", cli.snapshot))?;
    let path_str = path
        .to_str()
        .ok_or_else(|| eyre::eyre!("snapshot path is not valid UTF-8: {:?}", path))?;

    eprintln!("opening snapshot at {path_str}");
    let config = DbConfig::new_with_path(path_str);
    let db = DB::new(&config).wrap_err("failed to open snapshot DB")?;

    let tx = db.new_read_tx().wrap_err("failed to begin read tx")?;
    let wallets: Vec<Wallet> = tx
        .get_all_wallets()
        .wrap_err("failed to read wallets table")?;
    eprintln!(
        "read {} wallets from `{}`",
        wallets.len(),
        WALLETS_TABLE_NAME
    );

    let writer: Box<dyn Write> = match &cli.out {
        Some(p) => {
            eprintln!("writing JSONL to {}", p.display());
            Box::new(
                std::fs::File::create(p)
                    .wrap_err_with(|| format!("failed to create {:?}", p))?,
            )
        }
        None => Box::new(std::io::stdout().lock()),
    };
    let mut writer = BufWriter::new(writer);

    let mut n_emitted: usize = 0;
    let mut n_with_sk_root: usize = 0;
    let mut n_nonzero_balance_rows: usize = 0;

    for w in &wallets {
        let priv_blinder = w.private_shares.blinder;
        let pub_blinder = w.blinder - priv_blinder;

        let balances: Vec<BalanceOut> = w
            .balances
            .values()
            .map(|b| BalanceOut {
                mint: format!("0x{:x}", b.mint),
                amount: b.amount.to_string(),
            })
            .collect();
        n_nonzero_balance_rows += balances.iter().filter(|b| b.amount != "0").count();

        let sk_root_hex = w
            .key_chain
            .secret_keys
            .sk_root
            .as_ref()
            .and_then(sk_root_k256_hex);
        if sk_root_hex.is_some() {
            n_with_sk_root += 1;
        }

        let out = WalletOut {
            wallet_id: w.wallet_id.to_string(),
            blinder: scalar_hex(&w.blinder),
            private_blinder_share: scalar_hex(&priv_blinder),
            public_blinder: scalar_hex(&pub_blinder),
            nullifier: scalar_hex(&w.get_wallet_nullifier()),
            predicted_next_public_blinder: scalar_hex(&w.next_public_blinder()),
            balances,
            sk_root_present: sk_root_hex.is_some(),
            sk_root_k256_hex: sk_root_hex,
            pk_root_uncompressed_hex: pk_root_uncompressed_hex(
                &w.key_chain.public_keys.pk_root,
            ),
            symmetric_key_hex: hex::encode(w.key_chain.secret_keys.symmetric_key.0),
            n_orders: w.orders.len(),
        };
        serde_json::to_writer(&mut writer, &out)?;
        writeln!(writer)?;
        n_emitted += 1;
    }

    writer.flush()?;
    eprintln!("---");
    eprintln!("wallets emitted:          {n_emitted}");
    eprintln!("wallets with sk_root:     {n_with_sk_root}");
    eprintln!(
        "wallets without sk_root:  {}",
        n_emitted - n_with_sk_root
    );
    eprintln!("non-zero balance entries: {n_nonzero_balance_rows}");
    Ok(())
}
