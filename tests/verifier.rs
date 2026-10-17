//! End-to-end behaviour of `step`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    missing_docs,
    clippy::assert_is_empty,
    clippy::cloned_ref_to_slice_refs
)]

mod common;

use common::{
    Frag, Grant, NOW, TENANT, anchor, config, delegation, deployment, digest, facts, key,
    revocation, sign,
};
use weft_verifier::{
    Decisions, DeviceFacts, Instruction, Reason, TrustAnchor, VerifierState,
    cbor::{self, Limits, Value},
    rights::Scope,
    step,
};

fn run(
    state: &VerifierState,
    anchors: &[TrustAnchor],
    f: &DeviceFacts,
    inputs: &[Vec<u8>],
) -> (VerifierState, Decisions) {
    let refs: Vec<&[u8]> = inputs.iter().map(Vec::as_slice).collect();
    step(state, anchors, f, &refs, &Limits::DEFAULT)
}

fn reason_of(d: &Decisions, doc: &[u8]) -> Option<Reason> {
    let id = digest(doc);
    d.rejected.iter().find(|r| r.digest == id).map(|r| r.reason)
}

fn applied_config(d: &Decisions, component: &str) -> Option<Value> {
    d.actions.iter().find_map(|a| match a {
        Instruction::ApplyConfig {
            component: c,
            config,
            ..
        } if c == component => Some(cbor::decode(config, &Limits::DEFAULT).unwrap()),
        _ => None,
    })
}

fn frag<'a>(scope: &'a str, component: &'a str, version: i64, values: Value) -> Frag<'a> {
    Frag {
        scope,
        component,
        selector: &[],
        version,
        values,
        locks: &[],
    }
}

#[test]
fn root_signed_config_is_applied() {
    let root = key(1);
    let doc = sign(
        &root,
        &config(&frag(
            "fleet",
            "app/pump",
            1,
            Value::map([("rate", Value::Int(5))]),
        )),
    );
    let (state, d) = run(
        &VerifierState::default(),
        &[anchor(&root)],
        &facts(&[]),
        &[doc.clone()],
    );
    assert_eq!(
        applied_config(&d, "app/pump"),
        Some(Value::map([("rate", Value::Int(5))]))
    );
    assert_eq!(d.accepted, vec![digest(&doc)]);
    assert!(d.rejected.is_empty());
    assert_eq!(state.marks.len(), 1);
    assert_eq!(state.time_floor, NOW);
}

#[test]
fn nothing_happens_without_trust_anchors() {
    let root = key(1);
    let doc = sign(&root, &config(&frag("fleet", "app", 1, Value::map([]))));
    let (_, d) = run(&VerifierState::default(), &[], &facts(&[]), &[doc.clone()]);
    assert!(d.actions.is_empty());
    assert_eq!(reason_of(&d, &doc), Some(Reason::UnknownSigner));
}

#[test]
fn already_applied_config_produces_no_action() {
    let root = key(1);
    let doc = sign(
        &root,
        &config(&frag("fleet", "app", 1, Value::map([("a", Value::Int(1))]))),
    );
    let (_, first) = run(
        &VerifierState::default(),
        &[anchor(&root)],
        &facts(&[]),
        &[doc.clone()],
    );
    let Some(Instruction::ApplyConfig { hash, .. }) = first.actions.first() else {
        panic!("expected ApplyConfig");
    };
    let mut f = facts(&[]);
    f.applied_config.insert("app".into(), *hash);
    let (_, second) = run(&VerifierState::default(), &[anchor(&root)], &f, &[doc]);
    assert!(second.actions.is_empty());
}

#[test]
fn delegation_narrows_rights() {
    let root = key(1);
    let site_admin = key(2);
    let grant = Grant {
        actions: &["config.write", "delegate"],
        scopes: &["site"],
        components: &["app/*"],
        labels: &[("site", "vienna")],
        ..Grant::default()
    };
    let deleg = sign(&root, &delegation(&site_admin, &grant));
    let ok = sign(
        &site_admin,
        &config(&Frag {
            selector: &[("site", "vienna")],
            ..frag("site", "app/pump", 1, Value::map([("rate", Value::Int(2))]))
        }),
    );
    let wrong_scope = sign(
        &site_admin,
        &config(&Frag {
            selector: &[("site", "vienna")],
            ..frag("fleet", "app/pump", 1, Value::map([]))
        }),
    );
    let wrong_site = sign(
        &site_admin,
        &config(&Frag {
            selector: &[("site", "graz")],
            ..frag("site", "app/pump", 1, Value::map([]))
        }),
    );
    let no_selector = sign(
        &site_admin,
        &config(&frag("site", "app/other", 1, Value::map([]))),
    );
    let not_app = sign(
        &site_admin,
        &config(&Frag {
            selector: &[("site", "vienna")],
            ..frag("site", "os", 1, Value::map([]))
        }),
    );
    let deploy = sign(&site_admin, &deployment("site", "app/pump", 1, [7; 32]));

    let inputs = [
        deleg.clone(),
        ok.clone(),
        wrong_scope.clone(),
        wrong_site.clone(),
        no_selector.clone(),
        not_app.clone(),
        deploy.clone(),
    ];
    let (_, d) = run(
        &VerifierState::default(),
        &[anchor(&root)],
        &facts(&[("site", "vienna")]),
        &inputs,
    );
    assert!(d.accepted.contains(&digest(&deleg)));
    assert!(d.accepted.contains(&digest(&ok)));
    for doc in [&wrong_scope, &wrong_site, &no_selector, &not_app, &deploy] {
        assert_eq!(reason_of(&d, doc), Some(Reason::Unauthorized));
    }
    assert_eq!(
        applied_config(&d, "app/pump"),
        Some(Value::map([("rate", Value::Int(2))]))
    );
}

#[test]
fn redelegation_cannot_widen_rights() {
    let root = key(1);
    let admin = key(2);
    let tech = key(3);
    let to_admin = sign(
        &root,
        &delegation(
            &admin,
            &Grant {
                components: &["app/*"],
                ..Grant::default()
            },
        ),
    );
    // The admin claims to grant everything; the technician still only gets app/*.
    let to_tech = sign(&admin, &delegation(&tech, &Grant::default()));
    let os = sign(&tech, &config(&frag("local", "os", 1, Value::map([]))));
    let app = sign(&tech, &config(&frag("local", "app/x", 1, Value::map([]))));
    let (_, d) = run(
        &VerifierState::default(),
        &[anchor(&root)],
        &facts(&[]),
        &[to_admin, to_tech, os.clone(), app.clone()],
    );
    assert_eq!(reason_of(&d, &os), Some(Reason::Unauthorized));
    assert!(d.accepted.contains(&digest(&app)));
}

#[test]
fn delegation_without_delegate_right_grants_nothing() {
    let root = key(1);
    let admin = key(2);
    let tech = key(3);
    let to_admin = sign(
        &root,
        &delegation(
            &admin,
            &Grant {
                actions: &["config.write"],
                ..Grant::default()
            },
        ),
    );
    let to_tech = sign(&admin, &delegation(&tech, &Grant::default()));
    let doc = sign(&tech, &config(&frag("local", "app", 1, Value::map([]))));
    let (_, d) = run(
        &VerifierState::default(),
        &[anchor(&root)],
        &facts(&[]),
        &[to_admin, to_tech.clone(), doc.clone()],
    );
    assert_eq!(reason_of(&d, &to_tech), Some(Reason::Unauthorized));
    assert_eq!(reason_of(&d, &doc), Some(Reason::UnknownSigner));
}

#[test]
fn expired_delegation_is_reported_as_expired() {
    let root = key(1);
    let admin = key(2);
    let deleg = sign(
        &root,
        &delegation(
            &admin,
            &Grant {
                not_after: NOW - 1,
                ..Grant::default()
            },
        ),
    );
    let doc = sign(&admin, &config(&frag("site", "app", 1, Value::map([]))));
    let (_, d) = run(
        &VerifierState::default(),
        &[anchor(&root)],
        &facts(&[]),
        &[deleg, doc.clone()],
    );
    assert_eq!(reason_of(&d, &doc), Some(Reason::Expired));
    assert!(d.actions.is_empty());
}

#[test]
fn locks_block_other_scopes_and_report_conflicts() {
    let root = key(1);
    let fleet = sign(
        &root,
        &config(&Frag {
            locks: &[&["alarm", "threshold"]],
            ..frag(
                "fleet",
                "app",
                1,
                Value::map([
                    ("alarm", Value::map([("threshold", Value::Int(85))])),
                    ("rate", Value::Int(1)),
                ]),
            )
        }),
    );
    let site = sign(
        &root,
        &config(&frag(
            "site",
            "app",
            1,
            Value::map([
                ("alarm", Value::map([("threshold", Value::Int(99))])),
                ("rate", Value::Int(2)),
            ]),
        )),
    );
    let (_, d) = run(
        &VerifierState::default(),
        &[anchor(&root)],
        &facts(&[]),
        &[site, fleet],
    );
    assert_eq!(
        applied_config(&d, "app"),
        Some(Value::map([
            ("alarm", Value::map([("threshold", Value::Int(85))])),
            ("rate", Value::Int(2)),
        ]))
    );
    assert_eq!(d.conflicts.len(), 1);
    let c = &d.conflicts[0];
    assert_eq!(c.path, vec!["alarm".to_string(), "threshold".to_string()]);
    assert_eq!((c.scope, c.locked_by), (Scope::Site, Scope::Fleet));
}

#[test]
fn merge_patch_null_deletes_and_higher_scope_wins() {
    let root = key(1);
    let fleet = sign(
        &root,
        &config(&frag(
            "fleet",
            "app",
            1,
            Value::map([("a", Value::Int(1)), ("b", Value::Int(1))]),
        )),
    );
    let device = sign(
        &root,
        &config(&frag(
            "device",
            "app",
            1,
            Value::map([("a", Value::Int(2)), ("b", Value::Null)]),
        )),
    );
    let (_, d) = run(
        &VerifierState::default(),
        &[anchor(&root)],
        &facts(&[]),
        &[device, fleet],
    );
    assert_eq!(
        applied_config(&d, "app"),
        Some(Value::map([("a", Value::Int(2))]))
    );
}

#[test]
fn rollback_is_rejected_and_newest_version_wins() {
    let root = key(1);
    let v1 = sign(
        &root,
        &config(&frag("fleet", "app", 1, Value::map([("x", Value::Int(1))]))),
    );
    let v2 = sign(
        &root,
        &config(&frag("fleet", "app", 2, Value::map([("x", Value::Int(2))]))),
    );
    let (state, d) = run(
        &VerifierState::default(),
        &[anchor(&root)],
        &facts(&[]),
        &[v1.clone(), v2.clone()],
    );
    assert_eq!(
        applied_config(&d, "app"),
        Some(Value::map([("x", Value::Int(2))]))
    );
    assert_eq!(d.superseded, vec![digest(&v1)]);

    // Later, someone replays v1 together with v2: v1 is a rollback, v2 stays.
    let (_, d) = run(
        &state,
        &[anchor(&root)],
        &facts(&[]),
        &[v1.clone(), v2.clone()],
    );
    assert_eq!(reason_of(&d, &v1), Some(Reason::Rollback));
    assert!(d.accepted.contains(&digest(&v2)));
}

#[test]
fn missing_accepted_document_withholds_component() {
    let root = key(1);
    let v2 = sign(&root, &config(&frag("fleet", "app", 2, Value::map([]))));
    let v1 = sign(&root, &config(&frag("fleet", "app", 1, Value::map([]))));
    let (state, _) = run(
        &VerifierState::default(),
        &[anchor(&root)],
        &facts(&[]),
        &[v2],
    );
    // The shell lost v2 and only presents v1.
    let (_, d) = run(&state, &[anchor(&root)], &facts(&[]), &[v1.clone()]);
    assert_eq!(reason_of(&d, &v1), Some(Reason::Rollback));
    assert_eq!(d.withheld, vec!["app".to_string()]);
    assert!(d.actions.is_empty());
}

#[test]
fn equivocation_is_rejected() {
    let root = key(1);
    let a = sign(
        &root,
        &config(&frag("fleet", "app", 3, Value::map([("x", Value::Int(1))]))),
    );
    let b = sign(
        &root,
        &config(&frag("fleet", "app", 3, Value::map([("x", Value::Int(2))]))),
    );
    let (_, d) = run(
        &VerifierState::default(),
        &[anchor(&root)],
        &facts(&[]),
        &[a.clone(), b.clone()],
    );
    assert_eq!(reason_of(&d, &a), Some(Reason::Equivocation));
    assert_eq!(reason_of(&d, &b), Some(Reason::Equivocation));
    assert_eq!(d.withheld, vec!["app".to_string()]);
}

#[test]
fn deployment_highest_scope_wins_and_installed_is_skipped() {
    let root = key(1);
    let fleet = sign(&root, &deployment("fleet", "os", 5, [1; 32]));
    let site = sign(&root, &deployment("site", "os", 1, [2; 32]));
    let (_, d) = run(
        &VerifierState::default(),
        &[anchor(&root)],
        &facts(&[]),
        &[fleet.clone(), site.clone()],
    );
    assert_eq!(
        d.actions,
        vec![Instruction::Install {
            component: "os".into(),
            artifact: [2; 32]
        }]
    );
    let mut f = facts(&[]);
    f.installed.insert("os".into(), [2; 32]);
    let (_, d) = run(
        &VerifierState::default(),
        &[anchor(&root)],
        &f,
        &[fleet, site],
    );
    assert!(d.actions.is_empty());
}

#[test]
fn documents_for_other_devices_are_ignored() {
    let root = key(1);
    let doc = sign(
        &root,
        &config(&Frag {
            selector: &[("line", "l2")],
            ..frag("group", "app", 1, Value::map([]))
        }),
    );
    let (_, d) = run(
        &VerifierState::default(),
        &[anchor(&root)],
        &facts(&[("line", "l1")]),
        &[doc.clone()],
    );
    assert_eq!(d.ignored, vec![digest(&doc)]);
    assert!(d.actions.is_empty());
}

#[test]
fn revocation_removes_a_key_permanently() {
    let root = key(1);
    let admin = key(2);
    let deleg = sign(&root, &delegation(&admin, &Grant::default()));
    let revoke = sign(&root, &revocation(&admin));
    let doc = sign(&admin, &config(&frag("site", "app", 1, Value::map([]))));
    let (state, d) = run(
        &VerifierState::default(),
        &[anchor(&root)],
        &facts(&[]),
        &[deleg.clone(), revoke, doc.clone()],
    );
    assert_eq!(reason_of(&d, &doc), Some(Reason::Revoked));
    assert!(state.revoked.contains(&admin.pk.key_id()));
    // Even without the revocation document, the key stays revoked.
    let (_, d) = run(&state, &[anchor(&root)], &facts(&[]), &[deleg, doc.clone()]);
    assert_eq!(reason_of(&d, &doc), Some(Reason::Revoked));
}

#[test]
fn only_anchors_can_revoke() {
    let root = key(1);
    let admin = key(2);
    let other = key(3);
    let deleg = sign(&root, &delegation(&admin, &Grant::default()));
    let revoke = sign(&admin, &revocation(&other));
    let (state, d) = run(
        &VerifierState::default(),
        &[anchor(&root)],
        &facts(&[]),
        &[deleg, revoke.clone()],
    );
    assert_eq!(reason_of(&d, &revoke), Some(Reason::UnknownSigner));
    assert!(state.revoked.is_empty());
}

#[test]
fn tampered_signature_and_wrong_tenant_are_rejected() {
    let root = key(1);
    let mut tampered = sign(&root, &config(&frag("fleet", "app", 1, Value::map([]))));
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let mut other_tenant = config(&frag("fleet", "app", 2, Value::map([])));
    if let Value::Map(entries) = &mut other_tenant {
        for (k, v) in entries.iter_mut() {
            if k.as_text() == Some("tenant") {
                *v = Value::text("evil");
            }
        }
    }
    let other_tenant = sign(&root, &other_tenant);
    let (_, d) = run(
        &VerifierState::default(),
        &[anchor(&root)],
        &facts(&[]),
        &[tampered.clone(), other_tenant.clone()],
    );
    assert_eq!(reason_of(&d, &tampered), Some(Reason::BadSignature));
    assert_eq!(reason_of(&d, &other_tenant), Some(Reason::WrongTenant));
    assert!(d.actions.is_empty());
}

#[test]
fn anchors_of_other_tenants_have_no_power() {
    let root = key(1);
    let foreign = TrustAnchor {
        tenant: "other".into(),
        key: root.pk.clone(),
    };
    let doc = sign(&root, &config(&frag("fleet", "app", 1, Value::map([]))));
    let (_, d) = run(
        &VerifierState::default(),
        &[foreign],
        &facts(&[]),
        &[doc.clone()],
    );
    assert_eq!(reason_of(&d, &doc), Some(Reason::UnknownSigner));
    assert_eq!(TENANT, "acme");
}

#[test]
fn signed_documents_advance_the_time_floor() {
    let root = key(1);
    let mut payload = config(&frag("fleet", "app", 1, Value::map([])));
    if let Value::Map(entries) = &mut payload {
        for (k, v) in entries.iter_mut() {
            if k.as_text() == Some("issued_at") {
                *v = Value::Int(i64::try_from(NOW + 100).unwrap());
            }
        }
    }
    let doc = sign(&root, &payload);
    let (state, _) = run(
        &VerifierState::default(),
        &[anchor(&root)],
        &facts(&[]),
        &[doc],
    );
    assert_eq!(state.time_floor, NOW + 100);
}

#[test]
fn result_is_independent_of_input_order() {
    let root = key(1);
    let admin = key(2);
    let docs = vec![
        sign(&root, &delegation(&admin, &Grant::default())),
        sign(
            &admin,
            &config(&frag("site", "app", 1, Value::map([("a", Value::Int(1))]))),
        ),
        sign(
            &root,
            &config(&frag("fleet", "app", 1, Value::map([("b", Value::Int(2))]))),
        ),
        sign(&root, &deployment("fleet", "os", 1, [9; 32])),
        b"garbage".to_vec(),
    ];
    let reference = run(
        &VerifierState::default(),
        &[anchor(&root)],
        &facts(&[]),
        &docs,
    );
    // All 120 permutations of five inputs.
    let mut indices: Vec<usize> = (0..docs.len()).collect();
    let mut count = 0;
    permute(&mut indices, 0, &mut |order| {
        let shuffled: Vec<Vec<u8>> = order.iter().map(|&i| docs[i].clone()).collect();
        assert_eq!(
            run(
                &VerifierState::default(),
                &[anchor(&root)],
                &facts(&[]),
                &shuffled
            ),
            reference
        );
        count += 1;
    });
    assert_eq!(count, 120);
}

fn permute(items: &mut Vec<usize>, k: usize, f: &mut dyn FnMut(&[usize])) {
    if k == items.len() {
        f(items);
        return;
    }
    for i in k..items.len() {
        items.swap(k, i);
        permute(items, k + 1, f);
        items.swap(k, i);
    }
}

#[test]
fn state_round_trips_through_cbor() {
    let root = key(1);
    let admin = key(2);
    let docs = vec![
        sign(&root, &config(&frag("fleet", "app", 4, Value::map([])))),
        sign(&root, &revocation(&admin)),
    ];
    let (state, _) = run(
        &VerifierState::default(),
        &[anchor(&root)],
        &facts(&[]),
        &docs,
    );
    let bytes = state.to_cbor().unwrap();
    assert_eq!(VerifierState::from_cbor(&bytes).unwrap(), state);
    assert!(VerifierState::from_cbor(&bytes[1..]).is_err());
}

#[test]
fn arbitrary_bytes_never_panic() {
    let root = key(1);
    let valid = sign(
        &root,
        &config(&frag("fleet", "app", 1, Value::map([("a", Value::Int(1))]))),
    );
    // Deterministic pseudo-random mutations of a valid document (xorshift).
    let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for _ in 0..2000 {
        let mut doc = valid.clone();
        let flips = (next() % 4) + 1;
        for _ in 0..flips {
            let i = usize::try_from(next() % (doc.len() as u64)).unwrap();
            doc[i] = u8::try_from(next() & 0xff).unwrap();
        }
        let len = usize::try_from(next() % (doc.len() as u64 + 1)).unwrap();
        doc.truncate(len);
        let _ = run(
            &VerifierState::default(),
            &[anchor(&root)],
            &facts(&[]),
            &[doc],
        );
    }
}
