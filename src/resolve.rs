// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! Deterministic configuration merge with priorities, ties and locks.
//!
//! Rules:
//! 1. Fragments apply in ascending [`Priority`]; within one priority all fragments apply together.
//!    Values follow JSON Merge Patch (RFC 7396): maps merge per field, other values replace,
//!    `null` deletes.
//! 2. **Ties**: if fragments of *different issuers at the same priority* make incompatible
//!    changes to the same path (or to a path and one of its descendants), *none* of those
//!    changes applies. The value from lower priorities stays, and a [`ConflictKind::Tie`] is
//!    reported.
//! 3. **Locks**: a locked path can only be changed by the lock's owners (the issuers of the
//!    lowest-priority fragments locking it) or by issuers holding the lock-override right.
//!    Blocked changes are reported as [`ConflictKind::Locked`].
//!
//! Every rule depends only on the set of fragments, never on input order.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};

use crate::{
    cbor::{self, Value},
    crypto::{KeyId, sha256},
    rights::Priority,
};

/// What kind of conflict was detected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConflictKind {
    /// Different issuers at the same priority changed the same configuration path incompatibly.
    Tie,
    /// A change to a locked path by an issuer that may not change it.
    Locked,
    /// Different issuers at the same (highest) priority deploy different artifacts.
    DeploymentTie,
    /// One issuer signed two different documents with the same version.
    Equivocation,
}

impl ConflictKind {
    const fn as_str(self) -> &'static str {
        match self {
            ConflictKind::Tie => "tie",
            ConflictKind::Locked => "locked",
            ConflictKind::DeploymentTie => "deployment-tie",
            ConflictKind::Equivocation => "equivocation",
        }
    }
}

/// A conflict, ready to be surfaced in reported state, events, logs and UIs.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Conflict {
    /// Stable id: the same conflict on many devices has the same id.
    pub id: [u8; 32],
    /// What kind of conflict this is.
    pub kind: ConflictKind,
    /// Component concerned.
    pub component: String,
    /// Configuration path concerned (empty for deployment and equivocation conflicts).
    pub path: Vec<String>,
    /// Priority at which the conflicting change was attempted.
    pub priority: Priority,
    /// Key ids of all issuers involved, sorted.
    pub issuers: Vec<KeyId>,
    /// Digests of all documents involved, sorted.
    pub documents: Vec<[u8; 32]>,
    /// SHA-256 of each conflicting value (values themselves may be secret), sorted.
    pub values: Vec<[u8; 32]>,
}

impl Conflict {
    pub(crate) fn new(
        kind: ConflictKind,
        component: &str,
        path: Vec<String>,
        priority: Priority,
        issuers: impl IntoIterator<Item = KeyId>,
        documents: impl IntoIterator<Item = [u8; 32]>,
        values: impl IntoIterator<Item = [u8; 32]>,
    ) -> Conflict {
        let issuers: Vec<KeyId> = issuers
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let documents: Vec<[u8; 32]> = documents
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let values: Vec<[u8; 32]> = values
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let id_input = Value::Array(alloc::vec![
            Value::text("weft-conflict-v1"),
            Value::text(kind.as_str()),
            Value::text(component),
            Value::Array(path.iter().map(|s| Value::text(s)).collect()),
            Value::Array(documents.iter().map(|d| Value::Bytes(d.to_vec())).collect()),
        ]);
        let id = sha256(&cbor::encode(&id_input).unwrap_or_default());
        Conflict {
            id,
            kind,
            component: String::from(component),
            path,
            priority,
            issuers,
            documents,
            values,
        }
    }
}

/// One configuration fragment, as seen by the merge.
pub(crate) struct Fragment<'a> {
    pub priority: Priority,
    pub issuer: KeyId,
    pub digest: [u8; 32],
    pub values: &'a Value,
    pub locks: &'a BTreeSet<Vec<String>>,
    pub may_override_locks: bool,
}

/// A single change derived from a fragment.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Op {
    /// The path must be a map (created or replacing a non-map value).
    EnsureMap,
    /// The path takes this non-map value.
    Set(Value),
    /// The path is removed.
    Delete,
}

impl Op {
    fn value_hash(&self) -> [u8; 32] {
        let v = match self {
            Op::EnsureMap => Value::Map(Vec::new()),
            Op::Set(v) => v.clone(),
            Op::Delete => Value::Null,
        };
        sha256(&cbor::encode(&v).unwrap_or_default())
    }
}

struct Change<'a> {
    path: Vec<String>,
    op: Op,
    fragment: &'a Fragment<'a>,
}

struct LockOwner {
    issuers: BTreeSet<KeyId>,
    documents: BTreeSet<[u8; 32]>,
}

/// Merges all fragments of one component. Returns the effective configuration and conflicts.
pub(crate) fn resolve(component: &str, fragments: &[Fragment<'_>]) -> (Value, Vec<Conflict>) {
    let locks = lock_owners(fragments);
    let mut by_priority: BTreeMap<Priority, Vec<&Fragment<'_>>> = BTreeMap::new();
    for f in fragments {
        by_priority.entry(f.priority).or_default().push(f);
    }
    let mut target = Value::Map(Vec::new());
    let mut conflicts = Vec::new();
    for (priority, level) in by_priority {
        let mut changes: Vec<Change<'_>> = Vec::new();
        for f in level {
            let mut path = Vec::new();
            flatten(f.values, &mut path, f, &mut changes);
        }
        changes.sort_by(|a, b| {
            a.path
                .cmp(&b.path)
                .then(a.fragment.issuer.cmp(&b.fragment.issuer))
        });
        let tied = find_ties(component, priority, &changes, &mut conflicts);
        for (index, change) in changes.iter().enumerate() {
            if !tied.contains(&index) {
                apply(component, &mut target, change, &locks, &mut conflicts);
            }
        }
    }
    (target, conflicts)
}

/// Lock owners: for each locked path, the issuers of the lowest-priority fragments locking it.
fn lock_owners(fragments: &[Fragment<'_>]) -> BTreeMap<Vec<String>, LockOwner> {
    let mut lowest: BTreeMap<&Vec<String>, Priority> = BTreeMap::new();
    for f in fragments {
        for path in f.locks {
            let p = lowest.entry(path).or_insert(f.priority);
            *p = (*p).min(f.priority);
        }
    }
    let mut owners: BTreeMap<Vec<String>, LockOwner> = BTreeMap::new();
    for f in fragments {
        for path in f.locks {
            if lowest.get(path) == Some(&f.priority) {
                let owner = owners.entry(path.clone()).or_insert_with(|| LockOwner {
                    issuers: BTreeSet::new(),
                    documents: BTreeSet::new(),
                });
                owner.issuers.insert(f.issuer);
                owner.documents.insert(f.digest);
            }
        }
    }
    owners
}

/// Turns a merge patch into individual changes. Within one fragment no two changes conflict.
fn flatten<'a>(
    value: &Value,
    path: &mut Vec<String>,
    fragment: &'a Fragment<'a>,
    out: &mut Vec<Change<'a>>,
) {
    let Value::Map(entries) = value else {
        return;
    };
    if !path.is_empty() {
        out.push(Change {
            path: path.clone(),
            op: Op::EnsureMap,
            fragment,
        });
    }
    for (key, child) in entries {
        let Some(name) = key.as_text() else {
            continue; // rejected at parse time; skip defensively
        };
        path.push(String::from(name));
        match child {
            Value::Null => out.push(Change {
                path: path.clone(),
                op: Op::Delete,
                fragment,
            }),
            Value::Map(_) => flatten(child, path, fragment, out),
            other => out.push(Change {
                path: path.clone(),
                op: Op::Set(other.clone()),
                fragment,
            }),
        }
        path.pop();
    }
}

/// Finds incompatible changes between different issuers at one priority. `changes` is sorted by
/// path, so all descendants of a path directly follow it.
fn find_ties(
    component: &str,
    priority: Priority,
    changes: &[Change<'_>],
    conflicts: &mut Vec<Conflict>,
) -> BTreeSet<usize> {
    let mut tied = BTreeSet::new();
    // Group pairwise ties by the shallower path, so one place yields one conflict.
    let mut groups: BTreeMap<Vec<String>, Vec<usize>> = BTreeMap::new();
    for (i, a) in changes.iter().enumerate() {
        let rest = changes.get(i.saturating_add(1)..).unwrap_or_default();
        for (offset, b) in rest.iter().enumerate() {
            if !b.path.starts_with(&a.path) {
                break; // no further descendants of `a`
            }
            if a.fragment.issuer == b.fragment.issuer || compatible(a, b) {
                continue;
            }
            let j = i.saturating_add(1).saturating_add(offset);
            tied.insert(i);
            tied.insert(j);
            let group = groups.entry(a.path.clone()).or_default();
            group.push(i);
            group.push(j);
        }
    }
    for (path, members) in groups {
        let involved: Vec<&Change<'_>> = members.iter().filter_map(|&i| changes.get(i)).collect();
        conflicts.push(Conflict::new(
            ConflictKind::Tie,
            component,
            path,
            priority,
            involved.iter().map(|c| c.fragment.issuer),
            involved.iter().map(|c| c.fragment.digest),
            involved.iter().map(|c| c.op.value_hash()),
        ));
    }
    tied
}

/// `a.path` is `b.path` or an ancestor of it.
fn compatible(a: &Change<'_>, b: &Change<'_>) -> bool {
    if a.path == b.path {
        a.op == b.op
    } else {
        // An ancestor that stays a map is compatible with anything below it.
        a.op == Op::EnsureMap
    }
}

fn apply(
    component: &str,
    target: &mut Value,
    change: &Change<'_>,
    locks: &BTreeMap<Vec<String>, LockOwner>,
    conflicts: &mut Vec<Conflict>,
) {
    let Some((last, parents)) = change.path.split_last() else {
        return;
    };
    // Walk to the parent map; ancestors were ensured by earlier changes (sorted by path).
    let mut node = target;
    for name in parents {
        let Value::Map(entries) = node else {
            return; // an ancestor change was blocked or tied
        };
        let Some((_, child)) = entries
            .iter_mut()
            .find(|(k, _)| k.as_text() == Some(name.as_str()))
        else {
            return;
        };
        node = child;
    }
    let Value::Map(entries) = node else {
        return;
    };
    let index = entries
        .iter()
        .position(|(k, _)| k.as_text() == Some(last.as_str()));
    let current = index.and_then(|i| entries.get(i)).map(|(_, v)| v);
    let changes_something = match (&change.op, current) {
        (Op::EnsureMap, Some(Value::Map(_))) | (Op::Delete, None) => false,
        (Op::Set(v), Some(c)) => v != c,
        _ => true,
    };
    if !changes_something {
        return;
    }
    if let Some(owner) = blocking_lock(change, locks) {
        conflicts.push(Conflict::new(
            ConflictKind::Locked,
            component,
            change.path.clone(),
            change.fragment.priority,
            owner
                .issuers
                .iter()
                .copied()
                .chain([change.fragment.issuer]),
            owner
                .documents
                .iter()
                .copied()
                .chain([change.fragment.digest]),
            [change.op.value_hash()],
        ));
        return;
    }
    match (&change.op, index) {
        (Op::Delete, Some(i)) => {
            entries.remove(i);
        }
        (Op::Set(v), Some(i)) => {
            if let Some((_, slot)) = entries.get_mut(i) {
                *slot = v.clone();
            }
        }
        (Op::EnsureMap, Some(i)) => {
            if let Some((_, slot)) = entries.get_mut(i) {
                *slot = Value::Map(Vec::new());
            }
        }
        (Op::Set(v), None) => entries.push((Value::text(last), v.clone())),
        (Op::EnsureMap, None) => entries.push((Value::text(last), Value::Map(Vec::new()))),
        (Op::Delete, None) => {}
    }
}

/// The lock (if any) that forbids this change for its issuer.
fn blocking_lock<'l>(
    change: &Change<'_>,
    locks: &'l BTreeMap<Vec<String>, LockOwner>,
) -> Option<&'l LockOwner> {
    if change.fragment.may_override_locks {
        return None;
    }
    locks.iter().find_map(|(locked, owner)| {
        let related = change.path.starts_with(locked) || locked.starts_with(&change.path);
        (related && !owner.issuers.contains(&change.fragment.issuer)).then_some(owner)
    })
}
