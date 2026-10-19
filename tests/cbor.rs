// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! The CBOR layer accepts exactly the deterministic encoding and nothing else.
#![allow(
    clippy::unwrap_used,
    missing_docs,
    clippy::assert_is_empty,
    clippy::cloned_ref_to_slice_refs
)]

use weft_verifier::cbor::{CborError, Limits, Value, decode, encode};

fn dec(bytes: &[u8]) -> Result<Value, CborError> {
    decode(bytes, &Limits::DEFAULT)
}

/// @relation(VER-003, scope=function)
#[test]
fn round_trip() {
    let v = Value::map([
        ("a", Value::Int(-1)),
        ("bb", Value::Array(vec![Value::Bool(true), Value::Null])),
        ("c", Value::Bytes(vec![1, 2, 3])),
    ]);
    let bytes = encode(&v).unwrap();
    assert_eq!(dec(&bytes).unwrap(), v);
}

/// @relation(VER-003, scope=function)
#[test]
fn encoder_sorts_keys_length_first() {
    // "b" (shorter) sorts before "aa"; integer keys sort before text keys.
    let v = Value::Map(vec![
        (Value::text("aa"), Value::Int(1)),
        (Value::text("b"), Value::Int(2)),
        (Value::Int(7), Value::Int(3)),
    ]);
    let bytes = encode(&v).unwrap();
    assert_eq!(
        bytes,
        [0xa3, 0x07, 0x03, 0x61, b'b', 0x02, 0x62, b'a', b'a', 0x01]
    );
}

/// @relation(VER-001, scope=function)
#[test]
fn rejects_non_shortest_integer() {
    assert_eq!(dec(&[0x01]).unwrap(), Value::Int(1));
    assert_eq!(dec(&[0x18, 0x01]), Err(CborError::NotCanonical));
}

/// @relation(VER-001, scope=function)
#[test]
fn rejects_unsorted_and_duplicate_keys() {
    // {"b": 1, "a": 2}
    assert_eq!(
        dec(&[0xa2, 0x61, b'b', 0x01, 0x61, b'a', 0x02]),
        Err(CborError::KeyOrder)
    );
    // {"a": 1, "a": 2}
    assert_eq!(
        dec(&[0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02]),
        Err(CborError::KeyOrder)
    );
}

/// @relation(VER-001, scope=function)
#[test]
fn rejects_indefinite_lengths_floats_tags_and_undefined() {
    assert_eq!(dec(&[0x9f, 0x01, 0xff]), Err(CborError::Unsupported)); // [_ 1]
    assert_eq!(dec(&[0xf9, 0x3c, 0x00]), Err(CborError::Unsupported)); // 1.0 (f16)
    assert_eq!(dec(&[0xc1, 0x01]), Err(CborError::Unsupported)); // tag 1
    assert_eq!(dec(&[0xf7]), Err(CborError::Unsupported)); // undefined
}

/// @relation(VER-001, scope=function)
#[test]
fn rejects_integers_outside_i64() {
    // 2^64 - 1
    assert_eq!(
        dec(&[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
        Err(CborError::Unsupported)
    );
}

/// @relation(VER-001, scope=function)
#[test]
fn rejects_trailing_bytes_and_truncation() {
    assert_eq!(dec(&[0x01, 0x02]), Err(CborError::TrailingBytes));
    assert_eq!(dec(&[0x82, 0x01]), Err(CborError::TooManyItems)); // array claims 2, has 1 byte
    assert_eq!(dec(&[0x62, b'a']), Err(CborError::Malformed));
}

/// @relation(VER-002, scope=function)
#[test]
fn rejects_lying_lengths_before_allocating() {
    // Array header claiming 2^32 elements in a 5-byte input.
    assert_eq!(
        dec(&[0x9a, 0xff, 0xff, 0xff, 0xff]),
        Err(CborError::TooManyItems)
    );
}

/// @relation(VER-002, scope=function)
#[test]
fn enforces_depth_and_size_limits() {
    let mut deep = vec![0x81; 20];
    deep.push(0x01);
    assert_eq!(dec(&deep), Err(CborError::TooDeep));
    let small = Limits {
        max_len: 2,
        ..Limits::DEFAULT
    };
    assert_eq!(
        decode(&[0x83, 0x01, 0x02, 0x03], &small),
        Err(CborError::TooLong)
    );
}

/// @relation(VER-001, scope=function)
#[test]
fn rejects_invalid_utf8_and_non_scalar_keys() {
    assert_eq!(dec(&[0x61, 0xff]), Err(CborError::Malformed));
    // {[]: 1}
    assert_eq!(dec(&[0xa1, 0x80, 0x01]), Err(CborError::InvalidKey));
}
