//! Boot-time guard against restoring raft state from a dead epoch
//!
//! A non-seed node restores its persisted raft state on boot. If the seed has
//! since wiped and re-bootstrapped the cluster (same node-id, fresh term-1
//! log), the restored log belongs to a DEAD epoch: its log-ids collide with
//! the new epoch's entries, so openraft acks the leader's `AppendEntries`
//! without storing them, the membership entry that would adopt this node is
//! silently swallowed, and the node hangs in `await_promotion`
//! ("timeout ... local-node-adoption") forever.
//!
//! The tell is in the restored membership itself: a worker restoring
//! current-epoch state finds its own node-id in the restored effective
//! membership (it was adopted before it restarted); a worker restoring
//! dead-epoch state does not. A stale-epoch log has no value on a worker --
//! the seed holds the authoritative state and a fresh learner re-syncs in
//! seconds -- so the recovery is to purge the raft + replicated state and
//! continue down the fresh-node path ("non-seed node with no existing state,
//! awaiting adoption by the seed").
//!
//! The seed NEVER purges: its persisted state is the cluster's only
//! authoritative copy. The seed's analogue of this guard is the fail-fast
//! stale-identity check in the node-startup task.

use std::fs;

use libmdbx::TransactionKind;
use openraft::{EntryPayload, LogId, Membership};
use util::log_task;
use util::logging::Outcome;
use util::err_str;

use crate::{
    ALL_TABLES, RAFT_LOGS_TABLE, RAFT_METADATA_TABLE,
    logging::Task,
    replication::{
        Entry, Node, NodeId,
        error::ReplicationError,
        state_machine::{EXCLUDED_TABLES, snapshot_data_path, snapshot_zip_path},
    },
    storage::{db::DB, tx::StateTxn},
};

/// The restored effective membership and the log-id it is anchored at
type RestoredMembership = (Option<LogId<NodeId>>, Membership<NodeId, Node>);

/// Purge the persisted raft + replicated state if it was restored from a dead
/// epoch, returning whether a purge occurred.
///
/// The guard fires iff ALL of the following hold:
/// - the node is NOT the seed (`is_seed` is false); the seed's state is the
///   cluster's authoritative copy and is never purged here,
/// - there is persisted raft state with a non-empty effective membership (a
///   fresh volume has none, so it is untouched),
/// - the restored effective membership does NOT contain this node's own
///   node-id, neither as a voter nor as a learner. A node present in its
///   restored membership is on the normal healthy restart path and keeps its
///   state.
///
/// Must run BEFORE the state machine restores a snapshot and before the raft
/// core starts, so that a stale snapshot is never applied (and never hydrates
/// the in-memory matching engine) and openraft never observes the stale state.
pub(crate) fn purge_if_stale_epoch(
    db: &DB,
    snapshot_dir: &str,
    my_node_id: NodeId,
    is_seed: bool,
) -> Result<bool, ReplicationError> {
    // The seed never purges, regardless of what its restored state looks like
    if is_seed {
        return Ok(false);
    }

    // Read the restored effective membership. `None` covers both an empty DB
    // (fresh volume) and persisted state with no membership anchor, neither of
    // which can be classified as a dead epoch.
    let tx = db.new_read_tx()?;
    let membership = restored_effective_membership(&tx)?;
    tx.commit()?;

    let Some((membership_log_id, membership)) = membership else {
        return Ok(false);
    };

    // An empty membership cannot place this node in or out of an epoch
    if membership.nodes().next().is_none() {
        return Ok(false);
    }

    // Healthy restart: the restored membership contains this node (as a voter
    // or a learner), so the state is from the live epoch -- keep it
    if membership.get_node(&my_node_id).is_some() {
        return Ok(false);
    }

    let member_ids: Vec<NodeId> = membership.nodes().map(|(id, _)| *id).collect();
    log_task!(
        Task::RaftLifecycle,
        Outcome::Failed,
        my_node_id = my_node_id,
        restored_member_ids = ?member_ids,
        membership_log_id = ?membership_log_id,
        "restored raft state is from a dead epoch (local node-id not in the restored effective \
         membership); purging raft + replicated state and rejoining as a fresh learner"
    );

    purge_replicated_state(db, snapshot_dir)?;

    log_task!(
        Task::RaftLifecycle,
        Outcome::Ok,
        "purged stale-epoch raft state; continuing on the fresh-node path"
    );
    Ok(true)
}

/// Read the effective membership of the persisted raft state: the last
/// membership entry in the retained log, or the snapshot metadata's membership
/// if it is anchored at a higher log index (the retained log may contain
/// entries older than the snapshot's applied point). This mirrors how openraft
/// reconstructs the effective membership on startup.
fn restored_effective_membership<T: TransactionKind>(
    tx: &StateTxn<'_, T>,
) -> Result<Option<RestoredMembership>, ReplicationError> {
    // Start from the membership anchored in the snapshot metadata, if any
    let mut effective: Option<RestoredMembership> = None;
    if let Some(archived_meta) = tx.get_snapshot_metadata()? {
        let meta = archived_meta.deserialize_with()?;
        let stored = meta.last_membership;
        effective = Some((*stored.log_id(), stored.membership().clone()));
    }

    // Scan the retained log (ascending) for membership entries anchored at a
    // higher index than the snapshot's
    let mut cursor = tx.logs_cursor()?;
    cursor.seek_first()?;
    for record in cursor.into_iter() {
        let (_, archived_entry) = record?;
        let entry: Entry = archived_entry.deserialize_with()?;
        if let EntryPayload::Membership(membership) = entry.payload {
            let newer = effective
                .as_ref()
                .map_or(true, |(id, _)| id.map_or(0, |i| i.index) < entry.log_id.index);
            if newer {
                effective = Some((Some(entry.log_id), membership));
            }
        }
    }

    Ok(effective)
}

/// Purge the persisted raft state and all replicated data, leaving the node
/// byte-equivalent to a fresh node's empty DB for every replicated table.
///
/// Ordering matters for crash safety:
/// 1. Delete the snapshot files FIRST. If we crashed after clearing the DB but
///    before deleting the snapshot, the next boot would restore the stale
///    snapshot into an otherwise-empty DB -- resurrecting the dead-epoch
///    membership without the log/vote context this guard keys on. Deleting the
///    files first means a crash leaves the stale DB intact, and the guard
///    simply fires again on the next boot.
/// 2. Clear all raft + replicated tables in a SINGLE write tx, so the DB purge
///    itself is atomic: either the node boots with its full stale state (guard
///    re-fires) or fully fresh.
fn purge_replicated_state(db: &DB, snapshot_dir: &str) -> Result<(), ReplicationError> {
    for path in [snapshot_zip_path(snapshot_dir), snapshot_data_path(snapshot_dir)] {
        if path.exists() {
            fs::remove_file(&path).map_err(err_str!(ReplicationError::Snapshot))?;
        }
    }

    let tx = db.new_write_tx()?;
    for table in purged_tables() {
        tx.clear_table(table)?;
    }
    tx.commit()?;

    Ok(())
}

/// The tables cleared by the purge: the raft's own storage (log entries, vote,
/// last-purged log-id, and snapshot metadata -- the latter three all live in
/// `RAFT_METADATA_TABLE`) plus every replicated table.
///
/// Node-local, non-replicated tables (`EXCLUDED_TABLES` minus the raft
/// tables: peer info, cluster membership, node metadata, relayer fees) are
/// preserved -- they are populated from gossip or boot config, not through
/// consensus, exactly the set a snapshot install also leaves untouched.
fn purged_tables() -> impl Iterator<Item = &'static str> {
    ALL_TABLES.into_iter().filter(|t| {
        !EXCLUDED_TABLES.contains(t) || *t == RAFT_LOGS_TABLE || *t == RAFT_METADATA_TABLE
    })
}

#[cfg(test)]
mod test {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;

    use openraft::{
        EntryPayload, LeaderId, LogId, Membership, SnapshotMeta, StoredMembership, Vote,
    };

    use crate::replication::state_machine::snapshot_zip_path;
    use crate::replication::{Entry, Node, NodeId};
    use crate::storage::db::DB;
    use crate::test_helpers::mock_db;
    use crate::{ACCOUNTS_TABLE, NODE_METADATA_TABLE};

    use super::purge_if_stale_epoch;

    /// The seed's node-id in the stale epoch
    const SEED_ID: NodeId = 1;
    /// A (dead) worker node-id from the stale epoch
    const OLD_WORKER_ID: NodeId = 2;
    /// The local node's id, absent from the stale epoch's membership
    const MY_ID: NodeId = 99;

    /// The keys used for the replicated and node-local marker values
    const TEST_KEY: &str = "test-key";
    /// The value used for the marker values
    const TEST_VALUE: &str = "test-value";

    /// Build a membership whose nodes are the given ids, with the seed as the
    /// only voter (all other ids are learners)
    fn membership_of(ids: &[NodeId]) -> Membership<NodeId, Node> {
        let nodes: BTreeMap<NodeId, Node> =
            ids.iter().map(|id| (*id, Node::default())).collect();
        Membership::new(vec![BTreeSet::from([SEED_ID])], nodes)
    }

    /// Write persisted raft state (a membership log entry + vote) and marker
    /// values into a replicated and a node-local table
    fn write_persisted_state(db: &DB, member_ids: &[NodeId]) {
        let leader = LeaderId::new(1 /* term */, SEED_ID);
        let membership_entry = Entry {
            log_id: LogId::new(leader, 5 /* index */),
            payload: EntryPayload::Membership(membership_of(member_ids)),
        };
        let blank = Entry { log_id: LogId::new(leader, 6), payload: EntryPayload::Blank };

        let tx = db.new_write_tx().unwrap();
        tx.append_log_entries(vec![membership_entry, blank]).unwrap();
        tx.set_last_vote(&Vote::new(1 /* term */, SEED_ID)).unwrap();
        tx.commit().unwrap();

        // Replicated data (purged) and node-local data (preserved)
        let (k, v) = (TEST_KEY.to_string(), TEST_VALUE.to_string());
        db.write(ACCOUNTS_TABLE, &k, &v).unwrap();
        db.write(NODE_METADATA_TABLE, &k, &v).unwrap();
    }

    /// Assert that the persisted raft + replicated state is intact
    fn assert_state_intact(db: &DB) {
        let k = TEST_KEY.to_string();
        let tx = db.new_read_tx().unwrap();
        assert!(tx.last_raft_log().unwrap().is_some());
        assert!(tx.get_last_vote().unwrap().is_some());
        tx.commit().unwrap();
        let account: Option<String> = db.read(ACCOUNTS_TABLE, &k).unwrap();
        assert_eq!(account, Some(TEST_VALUE.to_string()));
    }

    /// Assert that the raft + replicated state matches a fresh node's empty
    /// DB: no log entries, no vote, no snapshot metadata, no replicated data.
    /// These are exactly the anchors openraft's startup and the log store's
    /// `get_log_state` read, so an empty result is indistinguishable from a
    /// fresh volume. Node-local data must survive.
    fn assert_state_purged(db: &DB) {
        let k = TEST_KEY.to_string();
        let tx = db.new_read_tx().unwrap();
        assert!(tx.last_raft_log().unwrap().is_none());
        assert!(tx.get_last_vote().unwrap().is_none());
        assert!(tx.get_last_purged_log_id().unwrap().is_none());
        assert!(tx.get_snapshot_metadata().unwrap().is_none());
        tx.commit().unwrap();

        let account: Option<String> = db.read(ACCOUNTS_TABLE, &k).unwrap();
        assert_eq!(account, None, "replicated data must be purged");
        let node_local: Option<String> = db.read(NODE_METADATA_TABLE, &k).unwrap();
        assert_eq!(
            node_local,
            Some(TEST_VALUE.to_string()),
            "node-local data must be preserved"
        );
    }

    /// Stale state whose membership is missing the local node-id is purged,
    /// including any on-disk snapshot archive
    #[test]
    fn test_stale_epoch_state_purged() {
        let db = mock_db();
        let snapshot_dir = db.path().to_string();
        write_persisted_state(&db, &[SEED_ID, OLD_WORKER_ID]);

        // Plant a stale snapshot archive, it must be deleted with the state
        let archive = snapshot_zip_path(&snapshot_dir);
        fs::write(&archive, b"stale-snapshot").unwrap();

        let purged =
            purge_if_stale_epoch(&db, &snapshot_dir, MY_ID, false /* is_seed */).unwrap();
        assert!(purged);
        assert_state_purged(&db);
        assert!(!archive.exists(), "stale snapshot archive must be deleted");
    }

    /// A membership stored only in the snapshot metadata (no membership entry
    /// in the retained log) still classifies the epoch
    #[test]
    fn test_stale_epoch_from_snapshot_metadata_purged() {
        let db = mock_db();
        let snapshot_dir = db.path().to_string();

        let leader = LeaderId::new(1 /* term */, SEED_ID);
        let meta = SnapshotMeta {
            last_log_id: Some(LogId::new(leader, 10)),
            last_membership: StoredMembership::new(
                Some(LogId::new(leader, 8)),
                membership_of(&[SEED_ID, OLD_WORKER_ID]),
            ),
            snapshot_id: "test-snapshot".to_string(),
        };
        let tx = db.new_write_tx().unwrap();
        tx.set_snapshot_metadata(&meta).unwrap();
        tx.set_last_vote(&Vote::new(1 /* term */, SEED_ID)).unwrap();
        tx.commit().unwrap();

        let purged =
            purge_if_stale_epoch(&db, &snapshot_dir, MY_ID, false /* is_seed */).unwrap();
        assert!(purged);

        let tx = db.new_read_tx().unwrap();
        assert!(tx.get_snapshot_metadata().unwrap().is_none());
        assert!(tx.get_last_vote().unwrap().is_none());
    }

    /// A node whose restored membership contains its own id (here as a
    /// learner, the production worker role) keeps its state: the normal
    /// healthy restart path
    #[test]
    fn test_current_epoch_state_preserved() {
        let db = mock_db();
        let snapshot_dir = db.path().to_string();
        write_persisted_state(&db, &[SEED_ID, MY_ID]);

        let purged =
            purge_if_stale_epoch(&db, &snapshot_dir, MY_ID, false /* is_seed */).unwrap();
        assert!(!purged);
        assert_state_intact(&db);
    }

    /// A snapshot membership containing the local node overrides an OLDER
    /// stale membership entry in the retained log (the log may retain entries
    /// from before the snapshot's applied point)
    #[test]
    fn test_snapshot_membership_overrides_older_log_membership() {
        let db = mock_db();
        let snapshot_dir = db.path().to_string();
        // Log membership at index 5 lacks the local node...
        write_persisted_state(&db, &[SEED_ID, OLD_WORKER_ID]);

        // ...but the snapshot's membership at index 8 contains it
        let leader = LeaderId::new(1 /* term */, SEED_ID);
        let meta = SnapshotMeta {
            last_log_id: Some(LogId::new(leader, 10)),
            last_membership: StoredMembership::new(
                Some(LogId::new(leader, 8)),
                membership_of(&[SEED_ID, MY_ID]),
            ),
            snapshot_id: "test-snapshot".to_string(),
        };
        let tx = db.new_write_tx().unwrap();
        tx.set_snapshot_metadata(&meta).unwrap();
        tx.commit().unwrap();

        let purged =
            purge_if_stale_epoch(&db, &snapshot_dir, MY_ID, false /* is_seed */).unwrap();
        assert!(!purged);
        assert_state_intact(&db);
    }

    /// An empty DB (fresh volume) is untouched
    #[test]
    fn test_empty_state_untouched() {
        let db = mock_db();
        let snapshot_dir = db.path().to_string();

        let purged =
            purge_if_stale_epoch(&db, &snapshot_dir, MY_ID, false /* is_seed */).unwrap();
        assert!(!purged);
    }

    /// The seed never purges, even with state that would otherwise classify
    /// as a dead epoch
    #[test]
    fn test_seed_never_purges() {
        let db = mock_db();
        let snapshot_dir = db.path().to_string();
        write_persisted_state(&db, &[SEED_ID, OLD_WORKER_ID]);

        let purged =
            purge_if_stale_epoch(&db, &snapshot_dir, MY_ID, true /* is_seed */).unwrap();
        assert!(!purged);
        assert_state_intact(&db);
    }
}
