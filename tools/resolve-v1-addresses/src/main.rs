//! resolve-v1-addresses — phase 5 of the refactored v1-refund pipeline.
//!
//! Pure transform. Reads:
//!   - `wallet-views.jsonl`           (phase 3) — wallet_id, pk_root_eth_addr
//!   - `external-transfers.jsonl`     (phase 1) — proxy ExternalTransfer index
//!   - `update-wallet-txs.jsonl`      (phase 1) — tx cache w/ pre-computed
//!                                                old_pk_root_eth_addr
//!   - HSE `external_transfers.csv`              — per-wallet event list
//!
//! For each wallet without a HSE-recorded `on_chain_addr`, attempts:
//!   1. **pk_root_match** — for each candidate tx_hash in the index, look up
//!      its `old_pk_root_eth_addr` in the tx cache; equal to snapshot
//!      pk_root_eth_addr → verified.
//!   2. **unique_amount_consensus** — if ≥1 of the wallet's HSE events maps
//!      to a globally unique `(mint, is_withdrawal, amount)` tuple in the
//!      index and all such unique-tuple matches yield the same `account`,
//!      accept it.

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;

use alloy_primitives::{Address, B256, U256};
use clap::Parser;
use eyre::{Result, WrapErr};
use serde::{Deserialize, Serialize};

#[derive(Parser, Debug)]
struct Cli {
    /// wallet-views.jsonl produced by phase 3 (derive-wallet-views.py).
    #[arg(long)]
    wallet_views: PathBuf,
    /// HSE external_transfers.csv.
    #[arg(long)]
    hse_xfers: PathBuf,
    /// Phase-1 output: proxy ExternalTransfer index.
    #[arg(long)]
    xfer_index: PathBuf,
    /// Phase-1 output: per-tx cache w/ old_pk_root_eth_addr.
    #[arg(long)]
    tx_cache: PathBuf,
    /// Output JSONL.
    #[arg(long, short)]
    out: PathBuf,
    /// Optional: resolve only this wallet (debugging).
    #[arg(long)]
    wallet_id: Option<String>,
    /// Limit number of wallets processed (0 = no limit).
    #[arg(long, default_value_t = 0)]
    limit: usize,
}

// === Input schemas === //

#[derive(Deserialize)]
struct WalletViewRow {
    wallet_id: String,
    pk_root_eth_addr: String,
    #[allow(dead_code)]
    blinder_snapshot: String,
    #[allow(dead_code)]
    is_internal: bool,
    #[allow(dead_code)]
    sk_root_present: bool,
}

#[derive(Deserialize)]
struct XferIndexRow {
    block: u64,
    tx_hash: String,
    #[allow(dead_code)]
    log_index: u64,
    account: String,
    mint: String,
    is_withdrawal: bool,
    amount: String,
}

#[derive(Deserialize)]
struct TxCacheRow {
    tx_hash: String,
    #[allow(dead_code)]
    block: u64,
    #[allow(dead_code)]
    from: String,
    #[allow(dead_code)]
    selector: String,
    #[allow(dead_code)]
    is_update_wallet: bool,
    old_pk_root_eth_addr: Option<String>,
}

#[derive(Deserialize, Clone)]
struct HseRow {
    wallet_id: String,
    mint: String,
    amount: String,
    is_withdrawal: String, // 't' or 'f'
    #[allow(dead_code)]
    timestamp: String,
    on_chain_addr: Option<String>,
}

// === Output schema === //

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum ResolutionOut {
    Verified {
        wallet_id: String,
        owner_address: String,
        verification: &'static str,
        verifying_tx: String,
        verifying_block: u64,
        candidates_tried: usize,
    },
    ResolvedByUniqueAmount {
        wallet_id: String,
        owner_address: String,
        verification: &'static str,
        unique_match_count: usize,
        sample_tx: String,
        sample_block: u64,
        candidates_tried: usize,
    },
    Unresolved {
        wallet_id: String,
        reason: String,
        candidates_tried: usize,
    },
}

// === In-memory types === //

#[derive(Clone)]
struct EventRecord {
    tx_hash: B256,
    block_number: u64,
    account: Address,
}

type IndexKey = (Address, bool, [u8; 32]);
type EventIndex = HashMap<IndexKey, Vec<EventRecord>>;
/// `tx_hash → old_pk_root_eth_addr`. Missing keys: tx not in cache.
/// Value `None`: tx is not a direct updateWallet, so no pk_root recorded.
type TxCache = HashMap<B256, Option<Address>>;

// === Loaders === //

fn parse_mint(s: &str) -> Result<Address> {
    let stripped = s.trim().trim_start_matches("0x");
    let with_prefix = format!("0x{stripped}");
    with_prefix
        .parse::<Address>()
        .wrap_err_with(|| format!("bad mint hex: {s}"))
}

fn parse_addr(s: &str) -> Result<Address> {
    let stripped = s.trim().trim_start_matches("0x");
    let with_prefix = format!("0x{stripped}");
    with_prefix
        .parse::<Address>()
        .wrap_err_with(|| format!("bad addr hex: {s}"))
}

fn parse_b256(s: &str) -> Result<B256> {
    let stripped = s.trim().trim_start_matches("0x");
    let with_prefix = format!("0x{stripped}");
    with_prefix
        .parse::<B256>()
        .wrap_err_with(|| format!("bad B256 hex: {s}"))
}

fn amount_to_key_bytes(a: &U256) -> [u8; 32] {
    a.to_be_bytes::<32>()
}

fn parse_is_withdrawal(s: &str) -> bool {
    matches!(s.to_lowercase().as_str(), "t" | "true" | "1")
}

fn load_xfer_index(path: &PathBuf) -> Result<EventIndex> {
    let mut idx: EventIndex = HashMap::new();
    let f = std::fs::File::open(path).wrap_err_with(|| format!("open {}", path.display()))?;
    let mut n = 0usize;
    for line in BufReader::new(f).lines() {
        let line = line?;
        let row: XferIndexRow = serde_json::from_str(&line)?;
        let mint = parse_mint(&row.mint)?;
        let account = parse_addr(&row.account)?;
        let tx_hash = parse_b256(&row.tx_hash)?;
        let amount = U256::from_str_radix(&row.amount, 10)?;
        let key: IndexKey = (mint, row.is_withdrawal, amount_to_key_bytes(&amount));
        idx.entry(key).or_default().push(EventRecord {
            tx_hash,
            block_number: row.block,
            account,
        });
        n += 1;
    }
    tracing::info!("xfer index: {} events, {} unique keys", n, idx.len());
    Ok(idx)
}

fn load_tx_cache(path: &PathBuf) -> Result<TxCache> {
    let mut cache: TxCache = HashMap::new();
    let f = std::fs::File::open(path).wrap_err_with(|| format!("open {}", path.display()))?;
    let mut n_total = 0usize;
    let mut n_with_pk = 0usize;
    for line in BufReader::new(f).lines() {
        let line = line?;
        let row: TxCacheRow = serde_json::from_str(&line)?;
        let tx_hash = parse_b256(&row.tx_hash)?;
        let pk = match row.old_pk_root_eth_addr.as_deref() {
            Some(a) => {
                n_with_pk += 1;
                Some(parse_addr(a)?)
            }
            None => None,
        };
        cache.insert(tx_hash, pk);
        n_total += 1;
    }
    tracing::info!(
        "tx cache: {} txs ({} with old_pk_root_eth_addr)",
        n_total,
        n_with_pk
    );
    Ok(cache)
}

fn load_wallet_views(path: &PathBuf) -> Result<HashMap<String, Address>> {
    let mut out: HashMap<String, Address> = HashMap::new();
    let f = std::fs::File::open(path).wrap_err_with(|| format!("open {}", path.display()))?;
    for line in BufReader::new(f).lines() {
        let line = line?;
        let row: WalletViewRow = serde_json::from_str(&line)?;
        out.insert(row.wallet_id, parse_addr(&row.pk_root_eth_addr)?);
    }
    Ok(out)
}

fn load_hse(
    path: &PathBuf,
) -> Result<(HashMap<String, Vec<HseRow>>, HashMap<String, String>)> {
    let mut events: HashMap<String, Vec<HseRow>> = HashMap::new();
    let mut known: HashMap<String, String> = HashMap::new();
    let mut rdr = csv::Reader::from_path(path)?;
    for row in rdr.deserialize::<HseRow>() {
        let row = row?;
        if let Some(addr) = row.on_chain_addr.as_ref() {
            let addr = addr.trim().to_lowercase();
            if !addr.is_empty() {
                known.insert(row.wallet_id.clone(), addr);
            }
        }
        events.entry(row.wallet_id.clone()).or_default().push(row);
    }
    Ok((events, known))
}

// === Resolution === //

fn resolve_one(
    wallet_id: &str,
    pk_root_addr: Address,
    events: &[HseRow],
    index: &EventIndex,
    tx_cache: &TxCache,
) -> ResolutionOut {
    let mut sorted = events.to_vec();
    // Most-recent first: pk_root matches are likeliest on the wallet's
    // most recent updateWallet.
    sorted.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    let mut per_event_candidates: Vec<&Vec<EventRecord>> = Vec::new();
    let mut unique_matches: Vec<&EventRecord> = Vec::new();
    let mut total_candidates = 0usize;
    let mut tried: HashSet<B256> = HashSet::new();

    for ev in sorted.iter() {
        let mint = match parse_mint(&ev.mint) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let amount = match U256::from_str_radix(ev.amount.trim_start_matches('-'), 10) {
            Ok(a) => a,
            Err(_) => continue,
        };
        let is_w = parse_is_withdrawal(&ev.is_withdrawal);
        let key: IndexKey = (mint, is_w, amount_to_key_bytes(&amount));
        let candidates = match index.get(&key) {
            Some(v) => v,
            None => continue,
        };
        total_candidates += candidates.len();
        per_event_candidates.push(candidates);
        if candidates.len() == 1 {
            unique_matches.push(&candidates[0]);
        }
    }

    // Tier 1.
    for cands in per_event_candidates.iter() {
        for cand in cands.iter() {
            if !tried.insert(cand.tx_hash) {
                continue;
            }
            // Look up the tx's old_pk_root_eth_addr in the cache. Missing tx
            // = not yet ingested. Missing pk = wrapper/non-updateWallet tx.
            if let Some(Some(on_chain_addr)) = tx_cache.get(&cand.tx_hash) {
                if *on_chain_addr == pk_root_addr {
                    return ResolutionOut::Verified {
                        wallet_id: wallet_id.to_string(),
                        owner_address: format!("0x{:x}", cand.account),
                        verification: "pk_root_match",
                        verifying_tx: format!("0x{}", hex::encode(cand.tx_hash)),
                        verifying_block: cand.block_number,
                        candidates_tried: total_candidates,
                    };
                }
            }
        }
    }

    // Tier 2.
    if !unique_matches.is_empty() {
        let accounts: HashSet<Address> = unique_matches.iter().map(|r| r.account).collect();
        if accounts.len() == 1 {
            let sample = unique_matches[0];
            return ResolutionOut::ResolvedByUniqueAmount {
                wallet_id: wallet_id.to_string(),
                owner_address: format!("0x{:x}", sample.account),
                verification: "unique_amount_consensus",
                unique_match_count: unique_matches.len(),
                sample_tx: format!("0x{}", hex::encode(sample.tx_hash)),
                sample_block: sample.block_number,
                candidates_tried: total_candidates,
            };
        }
        return ResolutionOut::Unresolved {
            wallet_id: wallet_id.to_string(),
            reason: format!(
                "unique-tuple matches disagree on account: {:?}",
                accounts
                    .iter()
                    .map(|a| format!("0x{:x}", a))
                    .collect::<Vec<_>>()
            ),
            candidates_tried: total_candidates,
        };
    }

    let probed_with_pk = tried
        .iter()
        .filter(|h| matches!(tx_cache.get(*h), Some(Some(_))))
        .count();
    ResolutionOut::Unresolved {
        wallet_id: wallet_id.to_string(),
        reason: format!(
            "no candidate verified ({} considered, {} unique txs probed, {} had pk_root in cache). \
             pk_root may have rotated, or wallet has no raw updateWallet txs.",
            total_candidates,
            tried.len(),
            probed_with_pk,
        ),
        candidates_tried: total_candidates,
    }
}

// === main === //

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "resolve=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();

    tracing::info!("loading wallet views: {}", cli.wallet_views.display());
    let views = load_wallet_views(&cli.wallet_views)?;
    tracing::info!("  {} wallets", views.len());

    tracing::info!("loading xfer index: {}", cli.xfer_index.display());
    let index = load_xfer_index(&cli.xfer_index)?;

    tracing::info!("loading tx cache: {}", cli.tx_cache.display());
    let tx_cache = load_tx_cache(&cli.tx_cache)?;

    tracing::info!("loading HSE xfers: {}", cli.hse_xfers.display());
    let (events_by_wid, known_by_wid) = load_hse(&cli.hse_xfers)?;
    tracing::info!(
        "  {} HSE wallets ({} with on_chain_addr already)",
        events_by_wid.len(),
        known_by_wid.len()
    );

    let force_one = cli.wallet_id.as_ref();
    let mut to_process: Vec<(String, Address)> = Vec::new();
    for (wid, _ev) in &events_by_wid {
        if known_by_wid.contains_key(wid) && force_one.map(|f| f != wid).unwrap_or(true) {
            continue;
        }
        match views.get(wid) {
            Some(addr) => to_process.push((wid.clone(), *addr)),
            None => tracing::warn!("wallet {} in HSE but not in wallet-views — skipping", wid),
        }
    }
    if let Some(only) = force_one {
        to_process.retain(|(w, _)| w == only);
    }
    if cli.limit > 0 {
        to_process.truncate(cli.limit);
    }
    tracing::info!("processing {} wallets", to_process.len());

    if let Some(parent) = cli.out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let out_file = std::fs::File::create(&cli.out)?;
    let mut writer = BufWriter::new(out_file);

    let mut n_verified = 0usize;
    let mut n_consensus = 0usize;
    let mut n_unresolved = 0usize;
    for (idx, (wid, pk_addr)) in to_process.iter().enumerate() {
        let events = events_by_wid.get(wid).cloned().unwrap_or_default();
        let result = resolve_one(wid, *pk_addr, &events, &index, &tx_cache);
        match &result {
            ResolutionOut::Verified { .. } => n_verified += 1,
            ResolutionOut::ResolvedByUniqueAmount { .. } => n_consensus += 1,
            ResolutionOut::Unresolved { .. } => n_unresolved += 1,
        }
        serde_json::to_writer(&mut writer, &result)?;
        writeln!(&mut writer)?;
        if (idx + 1) % 100 == 0 {
            tracing::info!(
                "progress: {}/{}  pk_match={}  consensus={}  unresolved={}",
                idx + 1,
                to_process.len(),
                n_verified,
                n_consensus,
                n_unresolved
            );
        }
    }
    writer.flush()?;
    tracing::info!(
        "done. pk_match={n_verified} consensus={n_consensus} unresolved={n_unresolved}"
    );
    Ok(())
}
