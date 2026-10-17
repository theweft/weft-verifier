//! ECDSA P-256 (the algorithm TPMs and secure elements provide). Requires `--features p256`.
#![cfg(feature = "p256")]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    missing_docs,
    clippy::assert_is_empty,
    clippy::cloned_ref_to_slice_refs
)]

use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use weft_verifier::{
    DeviceFacts, Instruction, TrustAnchor, VerifierState,
    cbor::{self, Limits, Value},
    cose,
    crypto::{Algorithm, PublicKey},
    step,
};

fn deployment() -> Value {
    Value::map([
        ("v", Value::Int(1)),
        ("type", Value::text("deployment")),
        ("tenant", Value::text("acme")),
        ("issued_at", Value::Int(1)),
        ("scope", Value::text("fleet")),
        ("component", Value::text("os")),
        ("version", Value::Int(1)),
        ("artifact", Value::Bytes(vec![3; 32])),
    ])
}

#[test]
fn p256_signed_deployment_is_accepted_and_tampering_detected() {
    let sk = SigningKey::from_slice(&[7; 32]).unwrap();
    let point = sk.verifying_key().to_sec1_point(false);
    let pk = PublicKey {
        alg: Algorithm::EcdsaP256,
        bytes: point.as_bytes().to_vec(),
    };
    let payload = cbor::encode(&deployment()).unwrap();
    let protected = cose::protected_header(Algorithm::EcdsaP256.cose_id(), &pk.key_id()).unwrap();
    let tbs = cose::sig_structure(&protected, &payload).unwrap();
    let signature: Signature = sk.sign(&tbs);
    let doc = cose::encode_sign1(&protected, &payload, &signature.to_bytes()).unwrap();

    let anchors = [TrustAnchor {
        tenant: "acme".into(),
        key: pk,
    }];
    let facts = DeviceFacts {
        tenant: "acme".into(),
        ..DeviceFacts::default()
    };
    let (_, d) = step(
        &VerifierState::default(),
        &anchors,
        &facts,
        &[&doc],
        &Limits::DEFAULT,
    );
    assert_eq!(
        d.actions,
        vec![Instruction::Install {
            component: "os".into(),
            artifact: [3; 32]
        }]
    );

    let mut tampered = doc.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let (_, d) = step(
        &VerifierState::default(),
        &anchors,
        &facts,
        &[&tampered],
        &Limits::DEFAULT,
    );
    assert!(d.actions.is_empty());
}
