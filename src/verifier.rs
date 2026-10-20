// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! The state-transition function: documents in, decisions out.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};
use core::cmp::Reverse;

use crate::{
    cbor::{self, Limits},
    cose::Sign1,
    crypto::{KeyId, PublicKey, sha256},
    doc::{self, Doc, Target},
    resolve::{Conflict, ConflictKind, Fragment, resolve},
    rights::{Action, Priority, Rights},
};

/// Maximum delegation chain length below a trust anchor.
pub const MAX_CHAIN_DEPTH: usize = 8;
/// Maximum number of distinct rights sets one key may accumulate (bounds work per step).
pub const MAX_RIGHTS_PER_KEY: usize = 8;

/// A root of trust for one tenant. Anchors hold full rights within their tenant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustAnchor {
    /// Tenant this anchor is authoritative for.
    pub tenant: String,
    /// The anchor's public key.
    pub key: PublicKey,
}

/// Facts about the device, supplied by the (untrusted) shell.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceFacts {
    /// The device's tenant.
    pub tenant: String,
    /// The device's labels (site, line, model, ...).
    pub labels: BTreeMap<String, String>,
    /// A lower bound on the current time from a trusted source, or 0 if unknown.
    pub trusted_time: u64,
    /// Artifact currently installed per component (SHA-256).
    pub installed: BTreeMap<String, [u8; 32]>,
    /// Hash of the configuration currently applied per component.
    pub applied_config: BTreeMap<String, [u8; 32]>,
}

/// Which kind of versioned document a slot tracks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// Configuration fragments.
    Config,
    /// Deployments.
    Deployment,
}

/// One versioned stream of documents: (kind, priority, issuer, component).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Slot {
    /// Document kind.
    pub kind: Kind,
    /// Priority the documents are signed at.
    pub priority: Priority,
    /// Issuer's key id.
    pub issuer: KeyId,
    /// Target component.
    pub component: String,
}

/// The highest accepted document in a slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mark {
    /// Highest accepted version.
    pub version: u64,
    /// SHA-256 of the accepted document.
    pub digest: [u8; 32],
}

/// State carried between steps. The shell persists it; the verifier never does I/O.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifierState {
    /// Trusted lower bound on time; only ever increases.
    pub time_floor: u64,
    /// Anti-rollback marks per slot; versions only ever increase.
    pub marks: BTreeMap<Slot, Mark>,
    /// Revoked keys; only ever grows.
    pub revoked: BTreeSet<KeyId>,
}

/// Something the executor should do. The executor accepts nothing else.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Instruction {
    /// Install the artifact with this SHA-256 for the component.
    Install {
        /// Component.
        component: String,
        /// SHA-256 of the artifact; the executor re-checks it before use.
        artifact: [u8; 32],
    },
    /// Apply this configuration (deterministic CBOR) to the component.
    ApplyConfig {
        /// Component.
        component: String,
        /// SHA-256 of `config`.
        hash: [u8; 32],
        /// The effective configuration.
        config: Vec<u8>,
    },
}

/// Why a document was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Reason {
    /// Not a valid `COSE_Sign1` message or document.
    Malformed,
    /// Signed by a key that has no rights here.
    UnknownSigner,
    /// Validly signed by a key that is now revoked, or a valid delegation to one.
    Revoked,
    /// Signature does not verify, or algorithm does not match the key.
    BadSignature,
    /// Document is for another tenant.
    WrongTenant,
    /// The signer's rights do not cover this document.
    Unauthorized,
    /// The signer's rights cover it, but not at the current trusted time.
    Expired,
    /// Lower version than already accepted for this slot.
    Rollback,
    /// Same version as an accepted document, different content.
    Equivocation,
}

/// A rejected input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Rejection {
    /// SHA-256 of the input bytes.
    pub digest: [u8; 32],
    /// Why it was rejected.
    pub reason: Reason,
}

/// The outcome of one step.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Decisions {
    /// Actions for the executor, sorted.
    pub actions: Vec<Instruction>,
    /// Inputs that are current and should be kept by the shell, sorted by digest.
    pub accepted: Vec<[u8; 32]>,
    /// Valid inputs replaced by a newer version (the shell may delete them), sorted.
    pub superseded: Vec<[u8; 32]>,
    /// Inputs that are valid but not addressed to this device, sorted.
    pub ignored: Vec<[u8; 32]>,
    /// Rejected inputs, sorted.
    pub rejected: Vec<Rejection>,
    /// Conflicts (ties, blocked lock changes, deployment ties, equivocation), sorted. Surface
    /// these in reported state and events; [`Conflict::id`] is stable across devices.
    pub conflicts: Vec<Conflict>,
    /// Components without actions because a previously accepted document is missing from the
    /// input (fail safe: no decision on incomplete information), sorted.
    pub withheld: Vec<String>,
}

struct Input {
    digest: [u8; 32],
    sign1: Sign1,
    doc: Doc,
}

struct Candidate<'a> {
    input: &'a Input,
    issuer: KeyId,
    target: &'a Target,
    /// Whether the issuer may change paths locked by others (for this document).
    may_override_locks: bool,
}

type Keys = BTreeMap<KeyId, (PublicKey, Vec<Rights>)>;

/// Working state of one step.
struct Ctx<'f> {
    facts: &'f DeviceFacts,
    next: VerifierState,
    out: Decisions,
    /// Trusted time used for all checks in this step.
    now: u64,
    /// Highest `issued_at` among accepted documents; becomes the next time floor.
    issued_max: u64,
    withheld: BTreeSet<String>,
    /// Public keys of revoked keys, where known (revoked anchors, and subjects of validly
    /// signed delegations). Lets `Revoked` mean "validly signed by a revoked key".
    revoked_keys: BTreeMap<KeyId, PublicKey>,
}

impl Ctx<'_> {
    fn accept(&mut self, input: &Input) {
        self.out.accepted.push(input.digest);
        self.issued_max = self.issued_max.max(input.doc.header().issued_at);
    }

    fn reject(&mut self, digest: [u8; 32], reason: Reason) {
        self.out.rejected.push(Rejection { digest, reason });
    }

    /// Records an equivocation: the component is withheld until the issuer fixes it.
    fn equivocation(&mut self, slot: &Slot, documents: impl IntoIterator<Item = [u8; 32]>) {
        self.out.conflicts.push(Conflict::new(
            ConflictKind::Equivocation,
            &slot.component,
            Vec::new(),
            slot.priority,
            [slot.issuer],
            documents,
            [],
        ));
        self.withheld.insert(slot.component.clone());
    }
}

/// Runs one verification step.
///
/// Pure and deterministic: the same arguments always give the same result, whatever the order
/// of `inputs`. Never panics.
pub fn step(
    state: &VerifierState,
    anchors: &[TrustAnchor],
    facts: &DeviceFacts,
    inputs: &[&[u8]],
    limits: &Limits,
) -> (VerifierState, Decisions) {
    let now = state.time_floor.max(facts.trusted_time);
    let mut ctx = Ctx {
        facts,
        next: state.clone(),
        out: Decisions::default(),
        now,
        issued_max: now,
        withheld: BTreeSet::new(),
        revoked_keys: BTreeMap::new(),
    };
    let roots: Vec<&TrustAnchor> = anchors
        .iter()
        .filter(|a| a.tenant == facts.tenant)
        .collect();

    let (all_digests, parsed) = parse_inputs(&mut ctx, inputs, limits);
    apply_revocations(&mut ctx, &roots, &parsed);
    let keys = build_key_graph(&mut ctx, &roots, &parsed);
    let slots = authorize_documents(&mut ctx, &keys, &parsed);
    let winners = select_winners(&mut ctx, slots);

    // A previously accepted document that is missing from the input means incomplete
    // information: decide nothing for that component. (A document that is present but now
    // rejected, e.g. expired or revoked, is a legitimate removal and does not block.)
    let missing: Vec<String> = ctx
        .next
        .marks
        .iter()
        .filter(|(_, mark)| !all_digests.contains(&mark.digest))
        .map(|(slot, _)| slot.component.clone())
        .collect();
    ctx.withheld.extend(missing);

    plan_deployments(&mut ctx, &winners);
    plan_configs(&mut ctx, &winners);
    finish(ctx)
}

/// 1. Parse, deduplicate and order all inputs by digest (order independence).
///
/// @relation(VER-022, scope=function)
fn parse_inputs(
    ctx: &mut Ctx<'_>,
    inputs: &[&[u8]],
    limits: &Limits,
) -> (BTreeSet<[u8; 32]>, Vec<Input>) {
    let by_digest: BTreeMap<[u8; 32], &[u8]> = inputs.iter().map(|b| (sha256(b), *b)).collect();
    let all_digests = by_digest.keys().copied().collect();
    let mut parsed = Vec::new();
    for (digest, bytes) in by_digest {
        let input = Sign1::parse(bytes, limits).ok().and_then(|sign1| {
            let payload = cbor::decode(&sign1.payload, limits).ok()?;
            let doc = doc::parse(&payload).ok()?;
            Some(Input { digest, sign1, doc })
        });
        match input {
            Some(input) => parsed.push(input),
            None => ctx.reject(digest, Reason::Malformed),
        }
    }
    (all_digests, parsed)
}

/// 2. Revocations by trust anchors. Monotonic: the revoked set only grows.
///
/// @relation(VER-012, scope=function)
fn apply_revocations(ctx: &mut Ctx<'_>, roots: &[&TrustAnchor], parsed: &[Input]) {
    for input in parsed {
        let Doc::Revocation { header, key_id } = &input.doc else {
            continue;
        };
        if !roots.iter().any(|a| signed_by(input, &a.key)) {
            ctx.reject(input.digest, Reason::UnknownSigner);
        } else if header.tenant != ctx.facts.tenant {
            ctx.reject(input.digest, Reason::WrongTenant);
        } else {
            ctx.next.revoked.insert(*key_id);
            ctx.accept(input);
        }
    }
}

/// 3. Delegation graph: effective rights per key, intersected along every chain.
///
/// @relation(VER-008, VER-009, VER-027, scope=function)
fn build_key_graph(ctx: &mut Ctx<'_>, roots: &[&TrustAnchor], parsed: &[Input]) -> Keys {
    let mut keys = Keys::new();
    for anchor in roots {
        let id = anchor.key.key_id();
        if ctx.next.revoked.contains(&id) {
            ctx.revoked_keys.insert(id, anchor.key.clone());
        } else {
            keys.insert(
                id,
                (
                    anchor.key.clone(),
                    alloc::vec![Rights::full(&ctx.facts.tenant)],
                ),
            );
        }
    }
    let delegations: Vec<&Input> = parsed
        .iter()
        .filter(|i| matches!(i.doc, Doc::Delegation { .. }))
        .collect();
    let mut used = BTreeSet::new();
    let mut bad = BTreeSet::new();
    let mut to_revoked = BTreeSet::new();
    for _ in 0..MAX_CHAIN_DEPTH {
        let mut changed = false;
        for input in &delegations {
            let Doc::Delegation {
                header,
                subject,
                rights,
            } = &input.doc
            else {
                continue;
            };
            if header.tenant != ctx.facts.tenant || bad.contains(&input.digest) {
                continue;
            }
            let Some((issuer_key, issuer_rights)) =
                kid_of(&input.sign1).and_then(|id| keys.get(&id))
            else {
                continue; // issuer may become known in a later round
            };
            if !signed_by(input, issuer_key) {
                bad.insert(input.digest);
                continue;
            }
            let subject_id = subject.key_id();
            if ctx.next.revoked.contains(&subject_id) {
                // Validly signed by a known issuer: the revoked key itself is now known.
                to_revoked.insert(input.digest);
                ctx.revoked_keys
                    .entry(subject_id)
                    .or_insert_with(|| subject.clone());
                continue;
            }
            let derived: Vec<Rights> = issuer_rights
                .iter()
                .filter(|r| r.actions.contains(&Action::Delegate) && r.is_valid_at(ctx.now))
                .filter_map(|r| r.intersect(rights))
                .collect();
            if derived.is_empty() {
                continue;
            }
            let entry = keys
                .entry(subject_id)
                .or_insert_with(|| (subject.clone(), Vec::new()));
            if entry.0 != *subject {
                continue; // key id collision: never merge different keys
            }
            for r in derived {
                if !entry.1.contains(&r) && entry.1.len() < MAX_RIGHTS_PER_KEY {
                    entry.1.push(r);
                    changed = true;
                }
            }
            used.insert(input.digest);
        }
        if !changed {
            break;
        }
    }
    for input in delegations {
        if used.contains(&input.digest) {
            ctx.accept(input);
        } else if bad.contains(&input.digest) {
            ctx.reject(input.digest, Reason::BadSignature);
        } else if to_revoked.contains(&input.digest) {
            ctx.reject(input.digest, Reason::Revoked);
        } else {
            let reason = signer_problem(input, &keys, ctx).unwrap_or(Reason::Unauthorized);
            ctx.reject(input.digest, reason);
        }
    }
    keys
}

/// 4. Config fragments and deployments: check signer, signature, rights and targeting.
///
/// @relation(VER-010, VER-025, scope=function)
fn authorize_documents<'a>(
    ctx: &mut Ctx<'_>,
    keys: &Keys,
    parsed: &'a [Input],
) -> BTreeMap<Slot, Vec<Candidate<'a>>> {
    let mut slots: BTreeMap<Slot, Vec<Candidate<'a>>> = BTreeMap::new();
    for input in parsed {
        let (kind, action, target) = match &input.doc {
            Doc::Config { target, .. } => (Kind::Config, Action::ConfigWrite, target),
            Doc::Deployment { target, .. } => (Kind::Deployment, Action::Deploy, target),
            _ => continue,
        };
        if let Some(reason) = signer_problem(input, keys, ctx) {
            ctx.reject(input.digest, reason);
            continue;
        }
        let Some((issuer, (key, rights))) =
            kid_of(&input.sign1).and_then(|id| keys.get(&id).map(|k| (id, k)))
        else {
            ctx.reject(input.digest, Reason::UnknownSigner);
            continue;
        };
        if !signed_by(input, key) {
            ctx.reject(input.digest, Reason::BadSignature);
            continue;
        }
        let (priority, component) = (target.priority, target.component.as_str());
        let allowed_at = |t: &dyn Fn(&Rights) -> u64| {
            rights
                .iter()
                .any(|r| r.allows(action, priority, component, &target.selector, t(r)))
        };
        if !allowed_at(&|_| ctx.now) {
            let reason = if allowed_at(&|r| r.not_before) {
                Reason::Expired
            } else {
                Reason::Unauthorized
            };
            ctx.reject(input.digest, reason);
            continue;
        }
        if !target
            .selector
            .iter()
            .all(|(k, v)| ctx.facts.labels.get(k) == Some(v))
        {
            ctx.out.ignored.push(input.digest);
            continue;
        }
        let may_override_locks = rights.iter().any(|r| {
            r.allows(
                Action::OverrideLocks,
                priority,
                component,
                &target.selector,
                ctx.now,
            )
        });
        let slot = Slot {
            kind,
            priority,
            issuer,
            component: target.component.clone(),
        };
        slots.entry(slot).or_default().push(Candidate {
            input,
            issuer,
            target,
            may_override_locks,
        });
    }
    slots
}

/// 5. Per slot: newest version wins; enforce anti-rollback and detect equivocation.
///
/// @relation(VER-018, VER-019, VER-020, scope=function)
fn select_winners<'a>(
    ctx: &mut Ctx<'_>,
    slots: BTreeMap<Slot, Vec<Candidate<'a>>>,
) -> Vec<Candidate<'a>> {
    let mut winners = Vec::new();
    for (slot, mut candidates) in slots {
        candidates.sort_by_key(|c| (Reverse(c.target.version), c.input.digest));
        let mut iter = candidates.into_iter();
        let Some(best) = iter.next() else { continue };
        let rest: Vec<Candidate<'a>> = iter.collect();
        let mark = ctx.next.marks.get(&slot).copied();
        let version = best.target.version;
        let same_version: Vec<[u8; 32]> = rest
            .iter()
            .filter(|c| c.target.version == version)
            .map(|c| c.input.digest)
            .collect();
        let equivocation = !same_version.is_empty();
        if equivocation {
            // Two different documents with one version: the issuer equivocates.
            ctx.reject(best.input.digest, Reason::Equivocation);
            for digest in &same_version {
                ctx.reject(*digest, Reason::Equivocation);
            }
            ctx.equivocation(&slot, same_version.into_iter().chain([best.input.digest]));
        } else {
            match mark {
                Some(m) if version < m.version => ctx.reject(best.input.digest, Reason::Rollback),
                Some(m) if version == m.version && best.input.digest != m.digest => {
                    ctx.reject(best.input.digest, Reason::Equivocation);
                    ctx.equivocation(&slot, [best.input.digest, m.digest]);
                }
                _ => {
                    ctx.next.marks.insert(
                        slot.clone(),
                        Mark {
                            version,
                            digest: best.input.digest,
                        },
                    );
                    ctx.accept(best.input);
                    winners.push(best);
                }
            }
        }
        let floor = mark.map_or(0, |m| m.version);
        for c in rest.iter().filter(|c| c.target.version != version) {
            if c.target.version < floor {
                ctx.reject(c.input.digest, Reason::Rollback);
            } else {
                ctx.out.superseded.push(c.input.digest);
            }
        }
    }
    winners
}

/// 6a. Deployments: the highest priority wins. Different artifacts from different issuers at
/// that priority are a conflict: nothing is installed and the current version keeps running.
///
/// @relation(VER-013, VER-016, VER-026, scope=function)
fn plan_deployments(ctx: &mut Ctx<'_>, winners: &[Candidate<'_>]) {
    let mut by_component: BTreeMap<&str, Vec<(&Candidate<'_>, [u8; 32])>> = BTreeMap::new();
    for w in winners {
        if let Doc::Deployment { artifact, .. } = &w.input.doc {
            by_component
                .entry(w.target.component.as_str())
                .or_default()
                .push((w, *artifact));
        }
    }
    for (component, docs) in by_component {
        if ctx.withheld.contains(component) {
            continue;
        }
        let Some(top) = docs.iter().map(|(c, _)| c.target.priority).max() else {
            continue;
        };
        let at_top: Vec<&(&Candidate<'_>, [u8; 32])> = docs
            .iter()
            .filter(|(c, _)| c.target.priority == top)
            .collect();
        let artifacts: BTreeSet<[u8; 32]> = at_top.iter().map(|(_, a)| *a).collect();
        let mut chosen = artifacts.iter();
        match (chosen.next(), chosen.next()) {
            (Some(artifact), None) => {
                if ctx.facts.installed.get(component) != Some(artifact) {
                    ctx.out.actions.push(Instruction::Install {
                        component: String::from(component),
                        artifact: *artifact,
                    });
                }
            }
            (Some(_), Some(_)) => ctx.out.conflicts.push(Conflict::new(
                ConflictKind::DeploymentTie,
                component,
                Vec::new(),
                top,
                at_top.iter().map(|(c, _)| c.issuer),
                at_top.iter().map(|(c, _)| c.input.digest),
                artifacts.iter().copied(),
            )),
            (None, _) => {}
        }
    }
}

/// 6b. Configuration: merge by priority, with ties and locks (see [`crate::resolve`]).
///
/// @relation(VER-026, scope=function)
fn plan_configs(ctx: &mut Ctx<'_>, winners: &[Candidate<'_>]) {
    let mut by_component: BTreeMap<&str, Vec<Fragment<'_>>> = BTreeMap::new();
    for w in winners {
        if let Doc::Config { values, locks, .. } = &w.input.doc {
            by_component
                .entry(w.target.component.as_str())
                .or_default()
                .push(Fragment {
                    priority: w.target.priority,
                    issuer: w.issuer,
                    digest: w.input.digest,
                    values,
                    locks,
                    may_override_locks: w.may_override_locks,
                });
        }
    }
    for (component, fragments) in by_component {
        if ctx.withheld.contains(component) {
            continue;
        }
        let (effective, conflicts) = resolve(component, &fragments);
        ctx.out.conflicts.extend(conflicts);
        let Ok(config) = cbor::encode(&effective) else {
            ctx.withheld.insert(String::from(component));
            continue;
        };
        let hash = sha256(&config);
        if ctx.facts.applied_config.get(component) != Some(&hash) {
            ctx.out.actions.push(Instruction::ApplyConfig {
                component: String::from(component),
                hash,
                config,
            });
        }
    }
}

/// Canonical ordering of all outputs.
///
/// @relation(VER-021, VER-022, scope=function)
fn finish(ctx: Ctx<'_>) -> (VerifierState, Decisions) {
    let Ctx {
        mut next,
        mut out,
        issued_max,
        withheld,
        ..
    } = ctx;
    next.time_floor = issued_max;
    out.withheld = withheld.into_iter().collect();
    out.actions.sort();
    out.accepted.sort_unstable();
    out.accepted.dedup();
    out.superseded.sort_unstable();
    out.superseded.dedup();
    out.ignored.sort_unstable();
    out.rejected.sort_unstable();
    out.rejected.dedup();
    out.conflicts.sort();
    (next, out)
}

/// @relation(VER-007, scope=function)
fn kid_of(sign1: &Sign1) -> Option<KeyId> {
    <KeyId>::try_from(sign1.kid.as_slice()).ok()
}

/// Verifies the input's signature with `key`, including that the header algorithm matches.
fn signed_by(input: &Input, key: &PublicKey) -> bool {
    if input.sign1.alg != key.alg.cose_id() || kid_of(&input.sign1) != Some(key.key_id()) {
        return false;
    }
    match input.sign1.signed_bytes() {
        Ok(message) => key.verify(&message, &input.sign1.signature),
        Err(_) => false,
    }
}

/// Classifies why an input's signer cannot act here, if it cannot.
///
/// @relation(VER-011, VER-012, scope=function)
fn signer_problem(input: &Input, keys: &Keys, ctx: &Ctx<'_>) -> Option<Reason> {
    if input.doc.header().tenant != ctx.facts.tenant {
        return Some(Reason::WrongTenant);
    }
    let Some(id) = kid_of(&input.sign1) else {
        return Some(Reason::UnknownSigner);
    };
    if ctx.next.revoked.contains(&id) {
        // Only a valid signature by the revoked key makes this a revoked document; anything
        // else claiming that key id is forged or unknown.
        return Some(match ctx.revoked_keys.get(&id) {
            Some(key) if signed_by(input, key) => Reason::Revoked,
            Some(_) => Reason::BadSignature,
            None => Reason::UnknownSigner,
        });
    }
    if !keys.contains_key(&id) {
        return Some(Reason::UnknownSigner);
    }
    None
}
