// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! Strict input structure: COSE headers, document fields and key identity.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

mod common;

use common::{Frag, anchor, config, digest, facts, key, sign};
use ed25519_dalek::Signer;
use weft_verifier::{
    Reason, VerifierState,
    cbor::{self, Limits, Value},
    cose::{self, Sign1},
    step,
};

const ALG: i64 = -8;

fn app_config() -> Value {
    config(&Frag {
        scope: "fleet",
        component: "app",
        selector: &[],
        version: 1,
        values: Value::map([("rate", Value::Int(5))]),
        locks: &[],
    })
}

fn reason(doc: &[u8], signer: &common::Key) -> Option<Reason> {
    let (_, d) = step(
        &VerifierState::default(),
        &[anchor(signer)],
        &facts(&[]),
        &[doc],
        &Limits::DEFAULT,
    );
    let id = digest(doc);
    d.rejected.iter().find(|r| r.digest == id).map(|r| r.reason)
}

fn with_header(header: &Value) -> Vec<u8> {
    let protected = cbor::encode(header).unwrap();
    cose::encode_sign1(&protected, b"payload", &[0; 64]).unwrap()
}

/// @relation(VER-004, scope=function)
#[test]
fn well_formed_sign1_is_parsed() {
    let k = key(1);
    let msg = sign(&k, &app_config());
    let parsed = Sign1::parse(&msg, &Limits::DEFAULT).unwrap();
    assert_eq!(parsed.alg, ALG);
    assert_eq!(parsed.kid, k.pk.key_id().to_vec());
}

/// @relation(VER-004, scope=function)
#[test]
fn unprotected_header_must_be_empty() {
    let k = key(1);
    let Value::Array(mut parts) = cbor::decode(&sign(&k, &app_config()), &Limits::DEFAULT).unwrap()
    else {
        panic!("not an array");
    };
    parts[1] = Value::Map(vec![(Value::Int(4), Value::Bytes(vec![1; 16]))]);
    let msg = cbor::encode(&Value::Array(parts)).unwrap();
    assert!(Sign1::parse(&msg, &Limits::DEFAULT).is_err());
}

/// @relation(VER-004, scope=function)
#[test]
fn protected_header_must_be_exactly_alg_and_kid() {
    let kid = Value::Bytes(vec![1; 16]);
    let extra = with_header(&Value::Map(vec![
        (Value::Int(1), Value::Int(ALG)),
        (Value::Int(3), Value::text("text/plain")),
        (Value::Int(4), kid.clone()),
    ]));
    let missing_kid = with_header(&Value::Map(vec![(Value::Int(1), Value::Int(ALG))]));
    let wrong_type = with_header(&Value::Map(vec![
        (Value::Int(1), Value::text("EdDSA")),
        (Value::Int(4), kid),
    ]));
    for msg in [extra, missing_kid, wrong_type] {
        assert!(Sign1::parse(&msg, &Limits::DEFAULT).is_err());
    }
}

/// @relation(VER-005, scope=function)
#[test]
fn unknown_document_fields_are_rejected() {
    let root = key(1);
    let Value::Map(mut entries) = app_config() else {
        panic!("not a map");
    };
    entries.push((Value::text("comment"), Value::text("ignored by devices?")));
    let doc = sign(&root, &Value::Map(entries));
    assert_eq!(reason(&doc, &root), Some(Reason::Malformed));
}

/// @relation(VER-007, scope=function)
#[test]
fn key_id_of_another_key_does_not_borrow_its_authority() {
    let root = key(1);
    let attacker = key(2);
    let payload = cbor::encode(&app_config()).unwrap();
    // Claims the anchor's key id, but is signed by the attacker.
    let protected = cose::protected_header(ALG, &root.pk.key_id()).unwrap();
    let tbs = cose::sig_structure(&protected, &payload).unwrap();
    let signature = attacker.sk.sign(&tbs).to_bytes();
    let doc = cose::encode_sign1(&protected, &payload, &signature).unwrap();
    assert_eq!(reason(&doc, &root), Some(Reason::BadSignature));
}
