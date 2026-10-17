// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! Test helpers: keys, document builders and signing (signing never lives in the verifier).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    dead_code,
    missing_docs,
    clippy::assert_is_empty,
    clippy::cloned_ref_to_slice_refs
)]

use ed25519_dalek::{Signer, SigningKey};
use weft_verifier::{
    DeviceFacts, TrustAnchor,
    cbor::{self, Value},
    cose,
    crypto::{Algorithm, PublicKey},
};

pub const TENANT: &str = "acme";
pub const NOW: u64 = 1_800_000_000;

pub struct Key {
    sk: SigningKey,
    pub pk: PublicKey,
}

pub fn key(seed: u8) -> Key {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let pk = PublicKey {
        alg: Algorithm::Ed25519,
        bytes: sk.verifying_key().to_bytes().to_vec(),
    };
    Key { sk, pk }
}

pub fn anchor(k: &Key) -> TrustAnchor {
    TrustAnchor {
        tenant: TENANT.into(),
        key: k.pk.clone(),
    }
}

/// Signs `payload` as a `COSE_Sign1` message.
pub fn sign(k: &Key, payload: &Value) -> Vec<u8> {
    let payload = cbor::encode(payload).unwrap();
    let protected = cose::protected_header(k.pk.alg.cose_id(), &k.pk.key_id()).unwrap();
    let tbs = cose::sig_structure(&protected, &payload).unwrap();
    let signature = k.sk.sign(&tbs).to_bytes();
    cose::encode_sign1(&protected, &payload, &signature).unwrap()
}

pub fn texts(items: &[&str]) -> Value {
    Value::Array(items.iter().map(|s| Value::text(s)).collect())
}

pub fn labels(pairs: &[(&str, &str)]) -> Value {
    Value::Map(
        pairs
            .iter()
            .map(|(k, v)| (Value::text(k), Value::text(v)))
            .collect(),
    )
}

pub struct Grant<'a> {
    pub actions: &'a [&'a str],
    pub scopes: &'a [&'a str],
    pub components: &'a [&'a str],
    pub labels: &'a [(&'a str, &'a str)],
    pub not_before: u64,
    pub not_after: u64,
}

impl Default for Grant<'_> {
    fn default() -> Self {
        Grant {
            actions: &["config.write", "deploy", "delegate"],
            scopes: &["fleet", "group", "site", "device", "local"],
            components: &["*"],
            labels: &[],
            not_before: 0,
            not_after: u64::MAX >> 1,
        }
    }
}

pub fn delegation(subject: &Key, grant: &Grant<'_>) -> Value {
    Value::map([
        ("v", Value::Int(1)),
        ("type", Value::text("delegation")),
        ("tenant", Value::text(TENANT)),
        ("issued_at", Value::Int(1)),
        (
            "subject",
            Value::map([
                ("alg", Value::Int(subject.pk.alg.cose_id())),
                ("key", Value::Bytes(subject.pk.bytes.clone())),
            ]),
        ),
        (
            "rights",
            Value::map([
                ("actions", texts(grant.actions)),
                ("scopes", texts(grant.scopes)),
                ("components", texts(grant.components)),
                ("labels", labels(grant.labels)),
                (
                    "not_before",
                    Value::Int(i64::try_from(grant.not_before).unwrap()),
                ),
                (
                    "not_after",
                    Value::Int(i64::try_from(grant.not_after).unwrap()),
                ),
            ]),
        ),
    ])
}

pub struct Frag<'a> {
    pub scope: &'a str,
    pub component: &'a str,
    pub selector: &'a [(&'a str, &'a str)],
    pub version: i64,
    pub values: Value,
    pub locks: &'a [&'a [&'a str]],
}

pub fn config(f: &Frag<'_>) -> Value {
    let locks = Value::Array(f.locks.iter().map(|path| texts(path)).collect());
    Value::map([
        ("v", Value::Int(1)),
        ("type", Value::text("config")),
        ("tenant", Value::text(TENANT)),
        ("issued_at", Value::Int(1)),
        ("scope", Value::text(f.scope)),
        ("component", Value::text(f.component)),
        ("selector", labels(f.selector)),
        ("version", Value::Int(f.version)),
        ("values", f.values.clone()),
        ("locks", locks),
    ])
}

pub fn deployment(scope: &str, component: &str, version: i64, artifact: [u8; 32]) -> Value {
    Value::map([
        ("v", Value::Int(1)),
        ("type", Value::text("deployment")),
        ("tenant", Value::text(TENANT)),
        ("issued_at", Value::Int(1)),
        ("scope", Value::text(scope)),
        ("component", Value::text(component)),
        ("version", Value::Int(version)),
        ("artifact", Value::Bytes(artifact.to_vec())),
    ])
}

pub fn revocation(target: &Key) -> Value {
    Value::map([
        ("v", Value::Int(1)),
        ("type", Value::text("revocation")),
        ("tenant", Value::text(TENANT)),
        ("issued_at", Value::Int(1)),
        ("key_id", Value::Bytes(target.pk.key_id().to_vec())),
    ])
}

pub fn facts(device_labels: &[(&str, &str)]) -> DeviceFacts {
    DeviceFacts {
        tenant: TENANT.into(),
        labels: device_labels
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect(),
        trusted_time: NOW,
        ..DeviceFacts::default()
    }
}

pub fn digest(bytes: &[u8]) -> [u8; 32] {
    weft_verifier::crypto::sha256(bytes)
}
