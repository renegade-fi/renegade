//! reconstruct-v1-balances-onchain
//!
//! For each wallet in the v1 relayer MDBX snapshot, walks the blinder
//! stream forward from snapshot state up to the attack block, decoding
//! each on-chain `WalletUpdated` event's transaction calldata to extract
//! authoritative balances at attack block. The reconstructed wallet state
//! is independently witnessed by signed on-chain transactions; the
//! relayer's cached `balances` field in the snapshot is not trusted.
//!
//! The math relies on the fact that v1 wallet blinder/share streams advance
//! deterministically via Poseidon hash-chaining from the wallet's current
//! `private_shares` — see `common/src/types/wallet/shares.rs:78-110` and
//! the memory note `reference_v1_blinder_stream_walking.md`. No `sk_root`
//! is required.
//!
//! Output is a credential-adjacent ledger (wallet identifiers + balances);
//! handle as sensitive. Run in the same isolated VM as the snapshot.

use std::collections::VecDeque;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

use alloy::consensus::Transaction;
use alloy::primitives::{Address, B256, keccak256};
use alloy::providers::ext::DebugApi;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::Filter;
use alloy::rpc::types::trace::geth::{
    CallFrame, GethDebugBuiltInTracerType, GethDebugTracerType, GethDebugTracingOptions, GethTrace,
};
use alloy_sol_types::{SolCall, sol};
use circuit_types::SizedWalletShare;
use circuit_types::traits::BaseType;
use clap::Parser;
use common::types::wallet::Wallet;
use constants::Scalar;
use darkpool_client::arbitrum::abi::{
    NEW_WALLET_SELECTOR, PROCESS_ATOMIC_MATCH_SETTLE_SELECTOR,
    PROCESS_ATOMIC_MATCH_SETTLE_WITH_RECEIVER_SELECTOR,
    PROCESS_MALLEABLE_ATOMIC_MATCH_SETTLE_SELECTOR,
    PROCESS_MALLEABLE_ATOMIC_MATCH_SETTLE_WITH_RECEIVER_SELECTOR,
    PROCESS_MATCH_SETTLE_SELECTOR, REDEEM_FEE_SELECTOR,
    SETTLE_OFFLINE_FEE_SELECTOR, SETTLE_ONLINE_RELAYER_FEE_SELECTOR,
    UPDATE_WALLET_SELECTOR,
};
use darkpool_client::arbitrum::contract_types::types::ValidMatchSettleAtomicStatement as ContractValidMatchSettleAtomicStatement;
use darkpool_client::arbitrum::helpers::{self as arb_helpers, deserialize_calldata};
use eyre::{Result, WrapErr, eyre};
use renegade_crypto::fields::scalar_to_biguint;
use serde::Serialize;
use state::storage::db::{DB, DbConfig};

// Wrapper-contract selector(s) we know about. The gas-sponsor function
// `sponsorAtomicMatchSettleWithRefundOptions` is Renegade's own gas sponsor
// (see renegade-stylus-contracts/contracts-stylus/src/contracts/gas_sponsor.rs:195).
// Its first 5 args mirror processAtomicMatchSettleWithReceiver's, so we can
// extract the inner `valid_match_settle_atomic_statement` from its calldata
// and reuse the existing statement deserializer.
const SPONSOR_ATOMIC_MATCH_SETTLE_WITH_REFUND_OPTIONS_SELECTOR: [u8; 4] = [0x21, 0x15, 0x94, 0xb7];

sol! {
    function sponsorAtomicMatchSettleWithRefundOptions(
        address receiver,
        bytes internal_party_match_payload,
        bytes valid_match_settle_atomic_statement,
        bytes match_proofs,
        bytes match_linking_proofs,
        address refund_address,
        uint256 nonce,
        bool refund_native_eth,
        uint256 refund_amount,
        bytes signature
    ) external payable returns (uint256);
}

fn parse_shares_from_sponsor_atomic_match_settle_with_refund_options(
    calldata: &[u8],
) -> Result<SizedWalletShare> {
    let call = sponsorAtomicMatchSettleWithRefundOptionsCall::abi_decode(calldata)
        .wrap_err("decode gas-sponsor call")?;
    let statement = deserialize_calldata::<ContractValidMatchSettleAtomicStatement>(
        &call.valid_match_settle_atomic_statement,
    )
    .map_err(|e| eyre!("decode atomic match statement from sponsor wrapper: {e:?}"))?;
    let mut shares = statement.internal_party_modified_shares.into_iter().map(Scalar::new);
    Ok(SizedWalletShare::from_scalars(&mut shares))
}

/// The Arbitrum One v1 darkpool proxy. Frozen post-attack.
const PROXY_ADDR_STR: &str = "0x30bD8eAb29181F790D7e495786d4B96d7AfDC518";
/// Block of the attack transaction. We reconstruct up to and INCLUDING
/// ATTACK_BLOCK - 1.
const ATTACK_BLOCK: u64 = 461_301_926;

#[derive(Parser, Debug)]
#[command(about = "Reconstruct v1 wallet balances at attack block from on-chain calldata")]
struct Cli {
    /// Path to the decompressed MDBX snapshot
    #[arg(long)]
    snapshot: PathBuf,
    /// Arbitrum One RPC URL. Defaults to $RPC_URL.
    #[arg(long, env = "RPC_URL")]
    rpc_url: String,
    /// If set, process only this wallet (UUID). Default: all 1914 wallets.
    #[arg(long)]
    wallet_id: Option<String>,
    /// Output JSONL file. Defaults to stdout.
    #[arg(long, short)]
    out: Option<PathBuf>,
    /// Stop after this many wallets (for testing). 0 = no limit.
    #[arg(long, default_value_t = 0)]
    limit: usize,
}

#[derive(Serialize)]
struct ReconstructionOut {
    wallet_id: String,
    /// Reconstructed balances at the last pre-attack on-chain update for
    /// this wallet. Comes from on-chain calldata, not from the snapshot.
    balances: Vec<BalanceOut>,
    /// The block number of the wallet's latest pre-attack on-chain update.
    last_update_block: u64,
    /// The tx hash that posted the latest pre-attack wallet state.
    last_update_tx: String,
    /// How many post-snapshot updates we replayed. 0 = wallet was idle in
    /// the staleness window; snapshot balance is authoritative for it.
    n_post_snapshot_updates: usize,
    /// Final wallet blinder, hex. For debugging.
    final_blinder_hex: String,
    /// Whether snapshot's recorded balances matched our reconstructed
    /// balances at the snapshot moment (sanity check). `None` when the
    /// snapshot baseline tx had an unknown function selector (e.g., a
    /// wrapper contract we can't decode) and we couldn't verify.
    snapshot_matches_chain: Option<bool>,
    /// True if the walking loop stopped early (e.g., due to an unknown
    /// selector in a post-snapshot update). When true, `balances` reflects
    /// the wallet state at `last_update_block`, NOT at attack block.
    partial_reconstruction: bool,
    /// Human-readable reason for partial reconstruction, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    partial_reason: Option<String>,
}

#[derive(Serialize)]
struct BalanceOut {
    /// 40-char hex address with leading zeros.
    mint: String,
    /// Atomic units as decimal string (u128).
    amount: String,
}

fn scalar_hex(s: &Scalar) -> String {
    scalar_to_biguint(s).to_str_radix(16)
}

fn scalar_to_b256(s: &Scalar) -> B256 {
    // Big-endian 32-byte representation, matching how the contract emits
    // wallet_blinder_share as a uint256 indexed topic.
    let big = scalar_to_biguint(s);
    let mut bytes = big.to_bytes_be();
    if bytes.len() < 32 {
        let mut padded = vec![0u8; 32 - bytes.len()];
        padded.extend(bytes);
        bytes = padded;
    } else if bytes.len() > 32 {
        // Shouldn't happen for BN254 scalars but guard anyway.
        bytes = bytes[bytes.len() - 32..].to_vec();
    }
    B256::from_slice(&bytes)
}

fn balance_to_out(b: &circuit_types::balance::Balance) -> BalanceOut {
    BalanceOut {
        mint: format!("0x{:040x}", b.mint),
        amount: b.amount.to_string(),
    }
}

/// Find the on-chain WalletUpdated log whose topic1 equals
/// `public_blinder_share`. Each wallet's blinder share is unique (the
/// contract enforces this via `mark_public_blinder_used`), so we expect
/// exactly one result; the function returns the first match.
fn wallet_updated_topic0() -> B256 {
    keccak256(b"WalletUpdated(uint256)")
}

async fn find_walletupdated_log(
    provider: &impl Provider,
    proxy: Address,
    public_blinder: &Scalar,
    from_block: u64,
    to_block: u64,
) -> Result<Option<alloy::rpc::types::Log>> {
    let topic1 = scalar_to_b256(public_blinder);
    let filter = Filter::new()
        .address(proxy)
        .event_signature(wallet_updated_topic0())
        .topic1(topic1)
        .from_block(from_block)
        .to_block(to_block);

    let logs = provider
        .get_logs(&filter)
        .await
        .wrap_err("eth_getLogs failed")?;

    Ok(logs.into_iter().next())
}

/// Fallback for txs whose top-level function selector isn't one of the
/// known darkpool entrypoints (gas sponsors, CoW Protocol's `settle`,
/// ERC-4337 `handleOps`, etc.). Uses `debug_traceTransaction` to walk the
/// call tree, finds every internal call to the proxy, and tries to parse
/// each one — returns the first whose parsed shares match the target
/// public_blinder.
///
/// Modeled on the v1 darkpool-client's
/// `fetch_public_shares_for_unknown_selector`
/// (`darkpool-client/src/client/event_indexing.rs:220`).
async fn try_parse_via_call_trace(
    provider: &impl Provider,
    proxy: Address,
    tx_hash: B256,
    target_public_blinder: Scalar,
) -> Result<circuit_types::SizedWalletShare> {
    let opts = GethDebugTracingOptions {
        tracer: Some(GethDebugTracerType::BuiltInTracer(
            GethDebugBuiltInTracerType::CallTracer,
        )),
        ..Default::default()
    };
    let trace = provider
        .debug_trace_transaction(tx_hash, opts)
        .await
        .wrap_err("debug_traceTransaction")?;
    let global = match trace {
        GethTrace::CallTracer(frame) => frame,
        other => return Err(eyre!("unexpected trace shape: {other:?}")),
    };

    // BFS the call tree, collect every call where the receiver is the proxy.
    let mut darkpool_calls: Vec<CallFrame> = Vec::new();
    let mut queue: VecDeque<CallFrame> = VecDeque::from([global]);
    while let Some(frame) = queue.pop_front() {
        if frame.to == Some(proxy) {
            darkpool_calls.push(frame.clone());
        }
        queue.extend(frame.calls);
    }

    if darkpool_calls.is_empty() {
        return Err(eyre!(
            "no calls into the proxy found in trace of {tx_hash}"
        ));
    }

    for call in darkpool_calls {
        let calldata: Vec<u8> = call.input.to_vec();
        if calldata.len() < 4 {
            continue;
        }
        let selector: [u8; 4] = calldata[..4].try_into().unwrap();
        if let Ok(shares) = arb_parse_shares(selector, &calldata, target_public_blinder)
            && shares.blinder == target_public_blinder
        {
            return Ok(shares);
        }
    }

    Err(eyre!(
        "no inner darkpool call in tx {tx_hash} parsed to public_blinder=0x{}",
        scalar_hex(&target_public_blinder),
    ))
}

/// Compute the wallet's next `(blinder, private_shares)` by hash-chaining
/// from the current state, matching `Wallet::reblind_wallet` in
/// `common/src/types/wallet/shares.rs:88-110`.
fn predicted_next_state(
    wallet: &Wallet,
) -> (Scalar, circuit_types::SizedWalletShare) {
    use circuit_types::SizedWalletShare;
    use circuit_types::traits::BaseType;
    use renegade_crypto::hash::evaluate_hash_chain;

    let scalars = wallet.private_shares.to_scalars();
    let n_shares = scalars.len();

    // (new_blinder, new_blinder_private_share) = hash_chain(current_blinder_share, 2)
    let chained = evaluate_hash_chain(wallet.private_shares.blinder, 2);
    let new_blinder = chained[0];
    let new_blinder_private = chained[1];

    // The new private shares (excluding the blinder share itself) come from
    // hash-chaining the second-to-last private share.
    let mut new_private = evaluate_hash_chain(scalars[n_shares - 2], n_shares - 1);
    new_private.push(new_blinder_private);

    let new_private_shares =
        SizedWalletShare::from_scalars(&mut new_private.into_iter());

    (new_blinder, new_private_shares)
}

/// Reconstruct one wallet's balances at the latest pre-attack block.
async fn reconstruct_wallet(
    provider: &impl Provider,
    proxy: Address,
    mut wallet: Wallet,
) -> Result<ReconstructionOut> {
    let wallet_id_str = wallet.wallet_id.to_string();
    tracing::info!(target: "reconstruct", "starting wallet {}", wallet_id_str);

    // 1. Locate the snapshot's own WalletUpdated log → defines our starting block.
    let snap_pub_blinder = wallet.public_blinder();
    let snap_log = find_walletupdated_log(
        provider,
        proxy,
        &snap_pub_blinder,
        0,
        ATTACK_BLOCK - 1,
    )
    .await?
    .ok_or_else(|| {
        eyre!(
            "snapshot baseline not found on chain for wallet {} (public_blinder=0x{})",
            wallet_id_str,
            scalar_hex(&snap_pub_blinder),
        )
    })?;
    let mut current_block = snap_log
        .block_number
        .ok_or_else(|| eyre!("snapshot log missing block_number"))?;
    let mut last_update_tx = snap_log
        .transaction_hash
        .map(|h| format!("0x{}", hex::encode(h)))
        .unwrap_or_default();

    // 2. Sanity: independently unblind the snapshot's on-chain calldata and
    //    compare against the relayer's cached balances. If they disagree
    //    here, the relayer state is corrupt for this wallet. Non-fatal:
    //    a parse failure on the baseline tx (e.g., wrapper-contract
    //    selector we don't recognize) leaves `snapshot_matches_chain =
    //    None` so the wallet still gets walked forward from snapshot state.
    let snapshot_matches_chain: Option<bool> =
        match verify_snapshot_against_chain(provider, proxy, &wallet, &snap_log).await {
            Ok(true) => Some(true),
            Ok(false) => {
                tracing::warn!(
                    target: "reconstruct",
                    wallet = %wallet_id_str,
                    "snapshot balances DISAGREE with on-chain decoded state at snapshot time"
                );
                Some(false)
            }
            Err(e) => {
                tracing::warn!(
                    target: "reconstruct",
                    wallet = %wallet_id_str,
                    "snapshot baseline verify skipped: {e:#}"
                );
                None
            }
        };

    // 3. Walk forward. Errors during decoding (e.g., unknown wrapper
    //    selector for the next-update tx) are treated as "stop here";
    //    emit balances as of the last successful update with a
    //    `partial_reconstruction` flag rather than failing the wallet
    //    outright. The CoW Protocol settle wrapper and ERC-4337 handleOps
    //    are real cases this path hits.
    let mut n_updates: usize = 0;
    let mut partial = false;
    let mut partial_reason: Option<String> = None;
    loop {
        let (next_blinder, next_private_shares) = predicted_next_state(&wallet);
        let next_pub_blinder = next_blinder - next_private_shares.blinder;

        let log = find_walletupdated_log(
            provider,
            proxy,
            &next_pub_blinder,
            current_block + 1,
            ATTACK_BLOCK - 1,
        )
        .await?;
        let log = match log {
            Some(l) => l,
            None => break, // No more updates before attack
        };

        // Fetch tx; extract calldata; decode new blinded_public_shares.
        let tx_hash = log
            .transaction_hash
            .ok_or_else(|| eyre!("log missing tx hash"))?;
        let tx = provider
            .get_transaction_by_hash(tx_hash)
            .await
            .wrap_err("eth_getTransactionByHash")?
            .ok_or_else(|| eyre!("tx {} not found", tx_hash))?;
        let calldata: Vec<u8> = tx.input().to_vec();
        if calldata.len() < 4 {
            return Err(eyre!("tx {} has <4 calldata bytes", tx_hash));
        }
        let selector: [u8; 4] = calldata[..4].try_into().unwrap();
        // Fast path: top-level selector is a known darkpool entrypoint.
        // Fallback: walk debug_trace for the inner darkpool call. Handles
        // wrapper contracts (gas sponsors, CoW Protocol, ERC-4337).
        let parse_result = match arb_parse_shares(selector, &calldata, next_pub_blinder) {
            Ok(s) => Ok(s),
            Err(top_err) => {
                tracing::debug!(
                    target: "reconstruct",
                    wallet = %wallet_id_str,
                    tx = %tx_hash,
                    selector = format!("0x{}", hex::encode(selector)),
                    "top-level parse failed, trying trace fallback: {top_err:#}"
                );
                try_parse_via_call_trace(provider, proxy, tx_hash, next_pub_blinder)
                    .await
                    .map_err(|trace_err| eyre!("top: {top_err:#} | trace: {trace_err:#}"))
            }
        };
        match parse_result {
            Ok(new_public_shares) => {
                wallet.update_from_shares(&next_private_shares, &new_public_shares);
                n_updates += 1;
                current_block = log
                    .block_number
                    .ok_or_else(|| eyre!("log missing block_number"))?;
                last_update_tx = format!("0x{}", hex::encode(tx_hash));
                tracing::debug!(
                    target: "reconstruct",
                    wallet = %wallet_id_str,
                    block = current_block,
                    update_idx = n_updates,
                    "applied post-snapshot update"
                );
            }
            Err(e) => {
                // Stop here; emit partial reconstruction.
                let next_block = log
                    .block_number
                    .ok_or_else(|| eyre!("log missing block_number"))?;
                let reason = format!(
                    "stopped at block {next_block} tx 0x{} selector 0x{}: {e:#}",
                    hex::encode(tx_hash),
                    hex::encode(selector),
                );
                tracing::warn!(
                    target: "reconstruct",
                    wallet = %wallet_id_str,
                    "{reason}"
                );
                partial = true;
                partial_reason = Some(reason);
                break;
            }
        }
    }

    Ok(ReconstructionOut {
        wallet_id: wallet_id_str,
        balances: wallet.balances.values().map(balance_to_out).collect(),
        last_update_block: current_block,
        last_update_tx,
        n_post_snapshot_updates: n_updates,
        final_blinder_hex: scalar_hex(&wallet.blinder),
        snapshot_matches_chain,
        partial_reconstruction: partial,
        partial_reason,
    })
}

/// Fetch the snapshot baseline tx, decode the wallet's blinded_public_shares
/// from its calldata, unblind with the snapshot's private_shares + blinder,
/// and compare balances. Returns true iff everything agrees.
async fn verify_snapshot_against_chain(
    provider: &impl Provider,
    proxy: Address,
    wallet: &Wallet,
    snap_log: &alloy::rpc::types::Log,
) -> Result<bool> {
    use circuit_types::native_helpers::wallet_from_blinded_shares;

    let tx_hash = snap_log
        .transaction_hash
        .ok_or_else(|| eyre!("snapshot log missing tx_hash"))?;
    let tx = provider
        .get_transaction_by_hash(tx_hash)
        .await
        .wrap_err("eth_getTransactionByHash for snapshot baseline")?
        .ok_or_else(|| eyre!("snapshot baseline tx {} not found", tx_hash))?;
    let calldata: Vec<u8> = tx.input().to_vec();
    if calldata.len() < 4 {
        return Ok(false);
    }
    let selector: [u8; 4] = calldata[..4].try_into().unwrap();
    let chain_public_shares = match arb_parse_shares(selector, &calldata, wallet.public_blinder()) {
        Ok(s) => s,
        Err(_) => {
            // Wrapper contract — fall back to the call trace.
            try_parse_via_call_trace(provider, proxy, tx_hash, wallet.public_blinder()).await?
        }
    };
    let chain_wallet =
        wallet_from_blinded_shares(&wallet.private_shares, &chain_public_shares);

    // Compare the SET of (mint, amount) pairs for entries that actually
    // hold value. The relayer's KeyedList accumulates orphaned (mint, 0)
    // entries when a slot is zeroed and reused — the circuit's slot vec
    // only has the slot's current contents. Both structures encode the
    // same active wallet state but in different shapes; filtering out
    // zero-amount entries (and zero-mint padding slots) compares the only
    // thing that affects repayment.
    use std::collections::HashSet;
    let snap_active: HashSet<(num_bigint::BigUint, u128)> = wallet
        .balances
        .values()
        .filter(|b| b.amount > 0)
        .map(|b| (b.mint.clone(), b.amount))
        .collect();
    let chain_active: HashSet<(num_bigint::BigUint, u128)> = chain_wallet
        .balances
        .iter()
        .filter(|b| b.amount > 0)
        .map(|b| (b.mint.clone(), b.amount))
        .collect();
    Ok(snap_active == chain_active)
}

/// Wrapper around the v1 darkpool-client's per-selector share parsers.
fn arb_parse_shares(
    selector: [u8; 4],
    calldata: &[u8],
    public_blinder_share: Scalar,
) -> Result<circuit_types::SizedWalletShare> {
    match selector {
        NEW_WALLET_SELECTOR => Ok(arb_helpers::parse_shares_from_new_wallet(calldata)?),
        UPDATE_WALLET_SELECTOR => Ok(arb_helpers::parse_shares_from_update_wallet(calldata)?),
        PROCESS_MATCH_SETTLE_SELECTOR => Ok(
            arb_helpers::parse_shares_from_process_match_settle(calldata, public_blinder_share)?,
        ),
        PROCESS_ATOMIC_MATCH_SETTLE_SELECTOR => {
            Ok(arb_helpers::parse_shares_from_process_atomic_match_settle(calldata)?)
        }
        PROCESS_ATOMIC_MATCH_SETTLE_WITH_RECEIVER_SELECTOR => {
            Ok(arb_helpers::parse_shares_from_process_atomic_match_settle_with_receiver(calldata)?)
        }
        PROCESS_MALLEABLE_ATOMIC_MATCH_SETTLE_SELECTOR => {
            Ok(arb_helpers::parse_shares_from_process_malleable_atomic_match_settle(calldata)?)
        }
        PROCESS_MALLEABLE_ATOMIC_MATCH_SETTLE_WITH_RECEIVER_SELECTOR => Ok(
            arb_helpers::parse_shares_from_process_malleable_atomic_match_settle_with_receiver(
                calldata,
            )?,
        ),
        SETTLE_ONLINE_RELAYER_FEE_SELECTOR => {
            Ok(arb_helpers::parse_shares_from_settle_online_relayer_fee(
                calldata,
                public_blinder_share,
            )?)
        }
        SETTLE_OFFLINE_FEE_SELECTOR => {
            Ok(arb_helpers::parse_shares_from_settle_offline_fee(calldata)?)
        }
        REDEEM_FEE_SELECTOR => Ok(arb_helpers::parse_shares_from_redeem_fee(calldata)?),
        SPONSOR_ATOMIC_MATCH_SETTLE_WITH_REFUND_OPTIONS_SELECTOR => {
            parse_shares_from_sponsor_atomic_match_settle_with_refund_options(calldata)
        }
        other => Err(eyre!("unknown function selector: 0x{}", hex::encode(other))),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "reconstruct=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let proxy: Address = PROXY_ADDR_STR.parse()?;

    let provider = ProviderBuilder::new()
        .connect_http(cli.rpc_url.parse()?);

    // Open snapshot
    let path_str = cli
        .snapshot
        .canonicalize()?
        .to_str()
        .ok_or_else(|| eyre!("snapshot path is not UTF-8"))?
        .to_string();
    let config = DbConfig::new_with_path(&path_str);
    let db = DB::new(&config).wrap_err("opening snapshot DB")?;
    let tx = db.new_read_tx()?;
    let wallets: Vec<Wallet> = tx
        .get_all_wallets()
        .wrap_err("reading wallets from snapshot")?;
    tracing::info!("read {} wallets from snapshot", wallets.len());

    let to_process: Vec<Wallet> = if let Some(wid_str) = &cli.wallet_id {
        let wid = uuid::Uuid::parse_str(wid_str)
            .wrap_err_with(|| format!("--wallet-id is not a UUID: {wid_str}"))?;
        wallets.into_iter().filter(|w| w.wallet_id == wid).collect()
    } else if cli.limit > 0 {
        wallets.into_iter().take(cli.limit).collect()
    } else {
        wallets
    };
    if to_process.is_empty() {
        return Err(eyre!("no wallets selected for processing"));
    }
    tracing::info!("processing {} wallets", to_process.len());

    let writer: Box<dyn Write> = match &cli.out {
        Some(p) => Box::new(std::fs::File::create(p)?),
        None => Box::new(std::io::stdout().lock()),
    };
    let mut writer = BufWriter::new(writer);

    let mut n_ok = 0;
    let mut n_err = 0;
    for (idx, w) in to_process.into_iter().enumerate() {
        match reconstruct_wallet(&provider, proxy, w).await {
            Ok(out) => {
                serde_json::to_writer(&mut writer, &out)?;
                writeln!(&mut writer)?;
                n_ok += 1;
                if idx % 10 == 0 {
                    tracing::info!(
                        "progress: {} ok, {} err, n_updates_for_last={}",
                        n_ok,
                        n_err,
                        out.n_post_snapshot_updates
                    );
                }
            }
            Err(e) => {
                tracing::error!("reconstruction failed: {e:#}");
                n_err += 1;
            }
        }
    }
    writer.flush()?;
    tracing::info!("done. ok={n_ok} err={n_err}");
    Ok(())
}
