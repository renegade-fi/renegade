//! Remote type shims and wrapper types for rkyv serialization of openraft types
//!
//! This module provides remote type shims and wrapper types to enable rkyv
//! serialization for openraft types that don't natively support rkyv.

use std::collections::{BTreeMap, BTreeSet};

use itertools::Itertools;
use rkyv::{Archive, Deserialize, Serialize};

use crate::{
    replication::{Entry, Node, NodeId, TypeConfig},
    state_transition::Proposal,
    storage::traits::RkyvWith,
};

use openraft::{EntryPayload, LeaderId, LogId, Membership, SnapshotMeta, StoredMembership, Vote};

// ---------------------
// | Remote Type Shims |
// ---------------------

// --- LeaderId --- //

/// Remote type shim for `openraft::LeaderId<NodeId>`
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq, Eq, Clone, Copy)]
#[rkyv(derive(Debug, PartialEq, Eq))]
#[rkyv(remote = LeaderId<NodeId>)]
#[rkyv(archived = ArchivedLeaderId)]
pub struct LeaderIdDef {
    /// The term of the leader
    pub term: u64,
    /// The node ID of the leader
    pub node_id: NodeId,
}

impl From<LeaderIdDef> for LeaderId<NodeId> {
    fn from(value: LeaderIdDef) -> Self {
        LeaderId::new(value.term, value.node_id)
    }
}

// --- LogId --- //

/// A type alias for a with-wrapped LogId
pub type WithLogId = RkyvWith<LogId<NodeId>, LogIdDef>;

/// Remote type shim for `openraft::LogId<NodeId>`
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq, Eq, Clone, Copy)]
#[rkyv(derive(Debug, PartialEq, Eq))]
#[rkyv(remote = LogId<NodeId>)]
#[rkyv(archived = ArchivedLogId)]
pub struct LogIdDef {
    /// The leader ID associated with this log entry
    #[rkyv(with = LeaderIdDef)]
    pub leader_id: LeaderId<NodeId>,
    /// The index of the log entry
    pub index: u64,
}

impl From<LogIdDef> for LogId<NodeId> {
    fn from(value: LogIdDef) -> Self {
        LogId::new(value.leader_id, value.index)
    }
}

// --- Vote --- //

/// A type alias for a with-wrapped vote value
pub type WithVote = RkyvWith<Vote<NodeId>, VoteDef>;

/// Remote type shim for `openraft::Vote<NodeId>`
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq, Eq, Clone, Copy)]
#[rkyv(derive(Debug, PartialEq, Eq))]
#[rkyv(remote = Vote<NodeId>)]
#[rkyv(archived = ArchivedVote)]
pub struct VoteDef {
    /// The leader ID being voted for
    #[rkyv(with = LeaderIdDef)]
    pub leader_id: LeaderId<NodeId>,
    /// Whether the vote is committed
    pub committed: bool,
}

impl From<VoteDef> for Vote<NodeId> {
    fn from(value: VoteDef) -> Self {
        Vote { leader_id: value.leader_id, committed: value.committed }
    }
}

// --- Membership --- //

/// Type for serializing `Membership<NodeId, Node>`
#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(derive(Debug))]
#[rkyv(remote = Membership<NodeId, Node>)]
pub struct MembershipDef {
    /// Multi configs of members.
    ///
    /// AKA a joint config in original raft paper.
    #[rkyv(getter = Membership::get_joint_config)]
    pub configs: Vec<BTreeSet<NodeId>>,

    /// Additional info of all nodes, e.g., the connecting host and port.
    ///
    /// A node-id key that is in `nodes` but is not in `configs` is a
    /// **learner**.
    #[rkyv(getter = get_membership_nodes)]
    pub nodes: Vec<(NodeId, Node)>,
}

fn get_membership_nodes(membership: &Membership<NodeId, Node>) -> Vec<(NodeId, Node)> {
    membership.nodes().map(|(id, node)| (*id, *node)).collect_vec()
}

impl From<MembershipDef> for Membership<NodeId, Node> {
    fn from(value: MembershipDef) -> Self {
        let nodes = value.nodes.into_iter().collect::<BTreeMap<_, _>>();
        Membership::new(value.configs, nodes)
    }
}

// --- EntryPayload --- //

/// Type for serializing `EntryPayload<TypeConfig>`
///
/// For Blank and Normal variants, we can use proper remote types.
/// For Membership variant, we serialize the entire EntryPayload as bytes
/// since Membership can't be properly remote-typed.
#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(remote = EntryPayload<TypeConfig>)]
#[rkyv(derive(Debug))]
pub enum EntryPayloadDef {
    /// A blank entry (heartbeat)
    Blank,
    /// A membership change entry
    Membership(#[rkyv(with = MembershipDef)] Membership<NodeId, Node>),
    /// A normal entry containing a proposal
    Normal(Proposal),
}

impl From<EntryPayloadDef> for EntryPayload<TypeConfig> {
    fn from(value: EntryPayloadDef) -> Self {
        match value {
            EntryPayloadDef::Blank => EntryPayload::Blank,
            EntryPayloadDef::Membership(membership) => EntryPayload::Membership(membership),
            EntryPayloadDef::Normal(proposal) => EntryPayload::Normal(proposal),
        }
    }
}

// --- StoredMembership (serialized as bytes) --- //

/// Type for serializing `StoredMembership<NodeId, Node>`
#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(derive(Debug))]
#[rkyv(remote = StoredMembership<NodeId, Node>)]
pub struct StoredMembershipDef {
    /// The log ID of the membership
    #[rkyv(with = rkyv::with::Map<LogIdDef>, getter = StoredMembership::log_id)]
    pub log_id: Option<LogId<NodeId>>,
    /// The membership
    #[rkyv(with = MembershipDef, getter = StoredMembership::membership)]
    pub membership: Membership<NodeId, Node>,
}

impl From<StoredMembershipDef> for StoredMembership<NodeId, Node> {
    fn from(value: StoredMembershipDef) -> Self {
        StoredMembership::new(value.log_id, value.membership)
    }
}

// --- SnapshotMeta --- //

/// A type alias for a with-wrapped snapshot meta value
pub type WithSnapshotMeta = RkyvWith<SnapshotMeta<NodeId, Node>, SnapshotMetaDef>;

/// Type for serializing `SnapshotMeta<NodeId, Node>`
///
/// We serialize StoredMembership as bytes since it can't be properly
/// remote-typed.
#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(remote = SnapshotMeta<NodeId, Node>)]
#[rkyv(derive(Debug))]
pub struct SnapshotMetaDef {
    /// The last log ID included in the snapshot
    #[rkyv(with = rkyv::with::Map<LogIdDef>)]
    pub last_log_id: Option<LogId<NodeId>>,
    /// The membership stored in the snapshot (serialized as bytes)
    #[rkyv(with = StoredMembershipDef)]
    pub last_membership: StoredMembership<NodeId, Node>,
    /// The snapshot ID
    pub snapshot_id: String,
}

impl From<SnapshotMetaDef> for SnapshotMeta<NodeId, Node> {
    fn from(value: SnapshotMetaDef) -> Self {
        SnapshotMeta {
            last_log_id: value.last_log_id,
            last_membership: value.last_membership,
            snapshot_id: value.snapshot_id,
        }
    }
}

// --- Entry --- //

/// A type alias for a with-wrapped entry value
pub type WithEntry = RkyvWith<Entry, EntryDef>;

/// Type for serializing `Entry` (which is `openraft::Entry<TypeConfig>`)
#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(remote = Entry)]
#[rkyv(derive(Debug))]
pub struct EntryDef {
    /// The log ID of the entry
    #[rkyv(with = LogIdDef)]
    pub log_id: LogId<NodeId>,
    /// The payload of the entry
    #[rkyv(with = EntryPayloadDef)]
    pub payload: EntryPayload<TypeConfig>,
}

impl From<EntryDef> for Entry {
    fn from(value: EntryDef) -> Self {
        Entry { log_id: value.log_id, payload: value.payload }
    }
}
