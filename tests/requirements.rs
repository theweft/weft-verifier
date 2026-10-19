// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! Requirements gate: requirements/*.sdoc against the relation markers in src/ and tests/.
//!
//! - Every marker names a known requirement.
//! - Every Active requirement verified by Test is referenced from src/ and from tests/.
//! - Requirement ids are unique.
//!
//! `StrictDoc` renders the same links as HTML (`just requirements`); this test is the CI gate.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    missing_docs
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

// Split so that this file does not contain a marker itself.
const MARKER: &str = concat!("@rel", "ation(");

struct Requirement {
    status: String,
    verification: String,
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn files(dir: &Path, ext: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(files(&path, ext));
        } else if path.extension().is_some_and(|e| e == ext) {
            out.push(path);
        }
    }
    out.sort();
    out
}

/// (uid, requirement) in file order, duplicates included.
fn requirements() -> Vec<(String, Requirement)> {
    let mut out = Vec::new();
    for path in files(&root().join("requirements"), "sdoc") {
        let src = fs::read_to_string(&path).unwrap();
        let mut current: Option<(String, Requirement)> = None;
        for line in src.lines() {
            if line == "[REQUIREMENT]" {
                out.extend(current.take());
                current = Some((
                    String::new(),
                    Requirement {
                        status: String::new(),
                        verification: String::new(),
                    },
                ));
            } else if let Some((uid, req)) = current.as_mut() {
                if let Some(v) = line.strip_prefix("UID: ") {
                    *uid = v.trim().to_string();
                } else if let Some(v) = line.strip_prefix("STATUS: ") {
                    req.status = v.trim().to_string();
                } else if let Some(v) = line.strip_prefix("VERIFICATION: ") {
                    req.verification = v.trim().to_string();
                }
            }
        }
        out.extend(current);
    }
    out
}

/// Requirement id -> locations (`file:line`) of markers under `dir`.
fn references(dir: &str) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for path in files(&root().join(dir), "rs") {
        let src = fs::read_to_string(&path).unwrap();
        let rel = path.strip_prefix(root()).unwrap().display().to_string();
        for (n, line) in src.lines().enumerate() {
            let Some(start) = line.find(MARKER) else {
                continue;
            };
            let args = &line[start + MARKER.len()..];
            let args = &args[..args.find(')').unwrap_or(args.len())];
            for item in args.split(',').map(str::trim) {
                if !item.is_empty() && !item.starts_with("scope=") && !item.starts_with("role=") {
                    out.entry(item.to_string())
                        .or_default()
                        .push(format!("{rel}:{}", n + 1));
                }
            }
        }
    }
    out
}

#[test]
fn requirement_ids_are_unique_and_complete() {
    let reqs = requirements();
    assert!(!reqs.is_empty(), "no requirements found");
    let mut seen = BTreeSet::new();
    for (uid, req) in &reqs {
        assert!(!uid.is_empty(), "requirement without UID");
        assert!(seen.insert(uid.clone()), "duplicate requirement {uid}");
        assert!(!req.status.is_empty(), "{uid}: missing STATUS");
        assert!(!req.verification.is_empty(), "{uid}: missing VERIFICATION");
    }
}

#[test]
fn every_marker_names_a_known_requirement() {
    let known: BTreeSet<String> = requirements().into_iter().map(|(uid, _)| uid).collect();
    let mut unknown = Vec::new();
    for dir in ["src", "tests"] {
        for (id, locations) in references(dir) {
            if !known.contains(&id) {
                unknown.push(format!("{id} at {}", locations.join(", ")));
            }
        }
    }
    assert!(unknown.is_empty(), "unknown requirements: {unknown:#?}");
}

#[test]
fn active_requirements_are_implemented_and_tested() {
    let implemented = references("src");
    let tested = references("tests");
    let mut missing = Vec::new();
    for (uid, req) in requirements() {
        if req.status != "Active" {
            continue;
        }
        if !implemented.contains_key(&uid) {
            missing.push(format!("{uid}: no implementation marker in src/"));
        }
        if req.verification == "Test" && !tested.contains_key(&uid) {
            missing.push(format!("{uid}: no test marker in tests/"));
        }
    }
    assert!(missing.is_empty(), "requirements gate: {missing:#?}");
}
