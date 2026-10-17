//! Deterministic configuration merge: JSON Merge Patch (RFC 7396) semantics plus scope locks.
//!
//! Fragments are applied in a fixed order (scope priority, then issuer key id). A path locked by
//! one scope cannot be changed by fragments of any other scope; such attempts are skipped and
//! reported as conflicts, never applied silently.

use alloc::{collections::BTreeMap, string::String, vec::Vec};

use crate::{cbor::Value, rights::Scope};

/// A change that was blocked by a lock.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Conflict {
    /// Component whose configuration was being merged.
    pub component: String,
    /// The blocked path.
    pub path: Vec<String>,
    /// Scope of the fragment that tried to change it.
    pub scope: Scope,
    /// Scope that owns the lock.
    pub locked_by: Scope,
}

/// Lock owners: for every locked path, the lowest-priority scope that locked it.
pub(crate) type Locks = BTreeMap<Vec<String>, Scope>;

pub(crate) struct Merge<'a> {
    pub component: &'a str,
    pub scope: Scope,
    pub locks: &'a Locks,
    pub conflicts: &'a mut Vec<Conflict>,
}

impl Merge<'_> {
    /// Applies `patch` to `target`.
    pub fn apply(&mut self, target: &mut Value, patch: &Value) {
        let mut path = Vec::new();
        self.merge(target, patch, &mut path);
    }

    fn merge(&mut self, target: &mut Value, patch: &Value, path: &mut Vec<String>) {
        let Value::Map(patch_entries) = patch else {
            if target != patch && !self.blocked(path) {
                *target = patch.clone();
            }
            return;
        };
        if !matches!(target, Value::Map(_)) {
            // Replacing a non-map with a map replaces the whole subtree.
            if self.blocked(path) {
                return;
            }
            *target = Value::Map(Vec::new());
        }
        let Value::Map(target_entries) = target else {
            return;
        };
        for (key, value) in patch_entries {
            let Some(name) = key.as_text() else {
                continue; // rejected at parse time; skip defensively
            };
            path.push(String::from(name));
            let existing = target_entries
                .iter()
                .position(|(k, _)| k.as_text() == Some(name));
            match (value, existing) {
                (Value::Null, Some(index)) => {
                    if !self.blocked(path) {
                        target_entries.remove(index);
                    }
                }
                (Value::Null, None) => {}
                (_, Some(index)) => {
                    if let Some((_, slot)) = target_entries.get_mut(index) {
                        self.merge(slot, value, path);
                    }
                }
                (_, None) => {
                    let mut slot = Value::Null;
                    self.merge(&mut slot, &strip_nulls(value), path);
                    if slot != Value::Null {
                        target_entries.push((key.clone(), slot));
                    }
                }
            }
            path.pop();
        }
    }

    /// Whether changing `path` is blocked by another scope's lock; records the conflict.
    fn blocked(&mut self, path: &[String]) -> bool {
        let owner = self.locks.iter().find_map(|(locked, owner)| {
            let related = locked.starts_with(path) || path.starts_with(locked);
            (related && *owner != self.scope).then_some(*owner)
        });
        if let Some(locked_by) = owner {
            self.conflicts.push(Conflict {
                component: String::from(self.component),
                path: path.to_vec(),
                scope: self.scope,
                locked_by,
            });
            true
        } else {
            false
        }
    }
}

/// RFC 7396: `null` inside a newly created object means "absent".
fn strip_nulls(value: &Value) -> Value {
    match value {
        Value::Map(entries) => Value::Map(
            entries
                .iter()
                .filter(|(_, v)| *v != Value::Null)
                .map(|(k, v)| (k.clone(), strip_nulls(v)))
                .collect(),
        ),
        other => other.clone(),
    }
}
