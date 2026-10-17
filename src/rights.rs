// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! Rights carried by delegations, and the narrowing rule.
//!
//! The effective rights of a delegated key are the *intersection* of its issuer's rights and
//! the rights the delegation declares. Narrowing therefore holds by construction: a delegation
//! can never grant more than its issuer has, whatever it claims.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
};

/// Configuration scopes, ordered from lowest to highest priority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    /// Whole fleet of a tenant.
    Fleet,
    /// A group of devices selected by labels.
    Group,
    /// A site.
    Site,
    /// A single device.
    Device,
    /// Changes made on site (technician, local UI).
    Local,
}

impl Scope {
    /// All scopes, lowest priority first.
    pub const ALL: [Scope; 5] = [
        Scope::Fleet,
        Scope::Group,
        Scope::Site,
        Scope::Device,
        Scope::Local,
    ];

    /// Parses the document representation.
    pub fn parse(s: &str) -> Option<Scope> {
        match s {
            "fleet" => Some(Scope::Fleet),
            "group" => Some(Scope::Group),
            "site" => Some(Scope::Site),
            "device" => Some(Scope::Device),
            "local" => Some(Scope::Local),
            _ => None,
        }
    }

    /// The document representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Scope::Fleet => "fleet",
            Scope::Group => "group",
            Scope::Site => "site",
            Scope::Device => "device",
            Scope::Local => "local",
        }
    }
}

/// Things a key may be allowed to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Action {
    /// Sign configuration fragments.
    ConfigWrite,
    /// Sign deployments (which artifact a component runs).
    Deploy,
    /// Delegate (a subset of) its own rights to other keys.
    Delegate,
}

impl Action {
    /// All actions.
    pub const ALL: [Action; 3] = [Action::ConfigWrite, Action::Deploy, Action::Delegate];

    /// Parses the document representation.
    pub fn parse(s: &str) -> Option<Action> {
        match s {
            "config.write" => Some(Action::ConfigWrite),
            "deploy" => Some(Action::Deploy),
            "delegate" => Some(Action::Delegate),
            _ => None,
        }
    }
}

/// What a key may do, for whom, and when.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Rights {
    /// The tenant these rights belong to.
    pub tenant: String,
    /// Allowed actions.
    pub actions: BTreeSet<Action>,
    /// Allowed scopes for configuration and deployments.
    pub scopes: BTreeSet<Scope>,
    /// Component patterns: `*` (all), `prefix/*`, or an exact component name.
    pub components: BTreeSet<String>,
    /// Required device labels: documents must select at least these labels with these values.
    pub labels: BTreeMap<String, String>,
    /// Valid from (seconds since the Unix epoch, inclusive).
    pub not_before: u64,
    /// Valid until (seconds since the Unix epoch, inclusive).
    pub not_after: u64,
}

impl Rights {
    /// Unrestricted rights within one tenant (held by trust anchors).
    pub fn full(tenant: &str) -> Rights {
        Rights {
            tenant: String::from(tenant),
            actions: Action::ALL.into_iter().collect(),
            scopes: Scope::ALL.into_iter().collect(),
            components: [String::from("*")].into_iter().collect(),
            labels: BTreeMap::new(),
            not_before: 0,
            not_after: u64::MAX,
        }
    }

    /// The intersection of two sets of rights, or `None` if nothing remains.
    pub fn intersect(&self, other: &Rights) -> Option<Rights> {
        if self.tenant != other.tenant {
            return None;
        }
        let actions: BTreeSet<Action> =
            self.actions.intersection(&other.actions).copied().collect();
        let scopes: BTreeSet<Scope> = self.scopes.intersection(&other.scopes).copied().collect();
        let mut components = BTreeSet::new();
        for a in &self.components {
            for b in &other.components {
                if pattern_covers(a, b) {
                    components.insert(b.clone());
                } else if pattern_covers(b, a) {
                    components.insert(a.clone());
                }
            }
        }
        let mut labels = self.labels.clone();
        for (k, v) in &other.labels {
            match labels.get(k) {
                Some(existing) if existing != v => return None, // contradictory requirements
                _ => {
                    labels.insert(k.clone(), v.clone());
                }
            }
        }
        let not_before = self.not_before.max(other.not_before);
        let not_after = self.not_after.min(other.not_after);
        if actions.is_empty()
            || scopes.is_empty()
            || components.is_empty()
            || not_before > not_after
        {
            return None;
        }
        Some(Rights {
            tenant: self.tenant.clone(),
            actions,
            scopes,
            components,
            labels,
            not_before,
            not_after,
        })
    }

    /// Whether these rights allow `action` at `scope` on `component` for a document selecting
    /// `selector`, at time `now`.
    pub fn allows(
        &self,
        action: Action,
        scope: Scope,
        component: &str,
        selector: &BTreeMap<String, String>,
        now: u64,
    ) -> bool {
        self.actions.contains(&action)
            && self.scopes.contains(&scope)
            && self
                .components
                .iter()
                .any(|p| pattern_matches(p, component))
            && self.labels.iter().all(|(k, v)| selector.get(k) == Some(v))
            && self.is_valid_at(now)
    }

    /// Whether `now` lies in the validity window.
    pub fn is_valid_at(&self, now: u64) -> bool {
        self.not_before <= now && now <= self.not_after
    }
}

/// Whether `pattern` matches the component name `component`.
pub fn pattern_matches(pattern: &str, component: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some("") => true,
        Some(prefix) if prefix.ends_with('/') => component.starts_with(prefix),
        _ => pattern == component,
    }
}

/// Whether every component matched by `inner` is also matched by `outer`.
pub fn pattern_covers(outer: &str, inner: &str) -> bool {
    match (outer.strip_suffix('*'), inner.strip_suffix('*')) {
        (Some(""), _) => true,
        (Some(o), Some(i)) if o.ends_with('/') => i.starts_with(o),
        (Some(o), None) if o.ends_with('/') => inner.starts_with(o),
        _ => outer == inner,
    }
}

/// Whether a component pattern is well-formed.
pub fn pattern_is_valid(pattern: &str) -> bool {
    !pattern.is_empty()
        && match pattern.strip_suffix('*') {
            Some(prefix) => (prefix.is_empty() || prefix.ends_with('/')) && !prefix.contains('*'),
            None => !pattern.contains('*'),
        }
}
