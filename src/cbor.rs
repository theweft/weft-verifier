// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! Strict, deterministic CBOR (RFC 8949 §4.2).
//!
//! The verifier accepts exactly one encoding of every value. Decoding rejects anything that is
//! not in deterministic form: indefinite lengths, non-shortest integers and lengths, unsorted or
//! duplicate map keys, floats, tags, undefined and simple values, and integers outside `i64`.
//! Canonicality is checked by re-encoding the decoded value and comparing bytes, so the rule
//! is enforced by one encoder instead of many special cases.

use alloc::{string::String, vec::Vec};
use minicbor::{Decoder, Encoder, data::Type};

/// A decoded CBOR value, restricted to the subset the verifier accepts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// An integer in the `i64` range.
    Int(i64),
    /// A byte string.
    Bytes(Vec<u8>),
    /// A UTF-8 text string.
    Text(String),
    /// An array.
    Array(Vec<Value>),
    /// A map. Keys are `Int` or `Text`; the encoder sorts them, the decoder requires them sorted.
    Map(Vec<(Value, Value)>),
}

/// Resource limits for decoding untrusted input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum input length in bytes.
    pub max_len: usize,
    /// Maximum nesting depth of arrays and maps.
    pub max_depth: usize,
    /// Maximum total number of decoded values.
    pub max_items: usize,
}

impl Limits {
    /// Default limits for one signed document.
    pub const DEFAULT: Limits = Limits {
        max_len: 64 * 1024,
        max_depth: 16,
        max_items: 4096,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Why CBOR input was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CborError {
    /// Input exceeds [`Limits::max_len`].
    TooLong,
    /// Nesting exceeds [`Limits::max_depth`].
    TooDeep,
    /// More values than [`Limits::max_items`].
    TooManyItems,
    /// Not well-formed CBOR, or truncated.
    Malformed,
    /// Well-formed, but uses a feature outside the accepted subset.
    Unsupported,
    /// Map keys not in deterministic order, or duplicated.
    KeyOrder,
    /// A map key that is neither an integer nor a text string.
    InvalidKey,
    /// Bytes left over after the top-level value.
    TrailingBytes,
    /// Valid CBOR, but not the deterministic encoding of its value.
    NotCanonical,
}

/// Decodes `bytes` as exactly one value in deterministic encoding.
///
/// # Errors
///
/// Returns a [`CborError`] for any input outside the accepted subset.
pub fn decode(bytes: &[u8], limits: &Limits) -> Result<Value, CborError> {
    if bytes.len() > limits.max_len {
        return Err(CborError::TooLong);
    }
    let mut decoder = Decoder::new(bytes);
    let mut items = 0usize;
    let value = decode_value(&mut decoder, limits, 0, &mut items)?;
    if decoder.position() != bytes.len() {
        return Err(CborError::TrailingBytes);
    }
    if encode(&value)?.as_slice() != bytes {
        return Err(CborError::NotCanonical);
    }
    Ok(value)
}

fn decode_value(
    d: &mut Decoder<'_>,
    limits: &Limits,
    depth: usize,
    items: &mut usize,
) -> Result<Value, CborError> {
    if depth > limits.max_depth {
        return Err(CborError::TooDeep);
    }
    *items = items.checked_add(1).ok_or(CborError::TooManyItems)?;
    if *items > limits.max_items {
        return Err(CborError::TooManyItems);
    }
    let malformed = |_| CborError::Malformed;
    match d.datatype().map_err(malformed)? {
        Type::Null => {
            d.null().map_err(malformed)?;
            Ok(Value::Null)
        }
        Type::Bool => Ok(Value::Bool(d.bool().map_err(malformed)?)),
        Type::U8
        | Type::U16
        | Type::U32
        | Type::U64
        | Type::I8
        | Type::I16
        | Type::I32
        | Type::I64 => Ok(Value::Int(d.i64().map_err(|_| CborError::Unsupported)?)),
        Type::Bytes => Ok(Value::Bytes(d.bytes().map_err(malformed)?.to_vec())),
        Type::String => Ok(Value::Text(String::from(d.str().map_err(malformed)?))),
        Type::Array => {
            let header = d.array().map_err(malformed)?;
            let len = definite_len(d, header, limits)?;
            let mut out = Vec::with_capacity(len);
            let child = depth.checked_add(1).ok_or(CborError::TooDeep)?;
            for _ in 0..len {
                out.push(decode_value(d, limits, child, items)?);
            }
            Ok(Value::Array(out))
        }
        Type::Map => {
            let header = d.map().map_err(malformed)?;
            let len = definite_len(d, header, limits)?;
            let mut out: Vec<(Value, Value)> = Vec::with_capacity(len);
            let child = depth.checked_add(1).ok_or(CborError::TooDeep)?;
            let mut previous: Option<Vec<u8>> = None;
            for _ in 0..len {
                let key = decode_value(d, limits, child, items)?;
                if !matches!(key, Value::Int(_) | Value::Text(_)) {
                    return Err(CborError::InvalidKey);
                }
                let encoded = encode(&key)?;
                if previous.as_deref().is_some_and(|p| encoded.as_slice() <= p) {
                    return Err(CborError::KeyOrder);
                }
                previous = Some(encoded);
                let value = decode_value(d, limits, child, items)?;
                out.push((key, value));
            }
            Ok(Value::Map(out))
        }
        _ => Err(CborError::Unsupported),
    }
}

/// Validates a container length before allocating for it.
fn definite_len(d: &Decoder<'_>, len: Option<u64>, limits: &Limits) -> Result<usize, CborError> {
    let len = len.ok_or(CborError::Unsupported)?; // indefinite length
    let len = usize::try_from(len).map_err(|_| CborError::TooManyItems)?;
    // Every element takes at least one byte: a length beyond the remaining input is a lie.
    let remaining = d.input().len().saturating_sub(d.position());
    if len > limits.max_items || len > remaining {
        return Err(CborError::TooManyItems);
    }
    Ok(len)
}

/// Encodes `value` deterministically: shortest integers, definite lengths, sorted map keys.
///
/// # Errors
///
/// Returns [`CborError::InvalidKey`] for non-`Int`/`Text` map keys and
/// [`CborError::KeyOrder`] for duplicate keys.
pub fn encode(value: &Value) -> Result<Vec<u8>, CborError> {
    let mut encoder = Encoder::new(Vec::new());
    encode_into(&mut encoder, value)?;
    Ok(encoder.into_writer())
}

fn encode_into(e: &mut Encoder<Vec<u8>>, value: &Value) -> Result<(), CborError> {
    let err = |_| CborError::Malformed; // writing to a Vec cannot fail
    match value {
        Value::Null => {
            e.null().map_err(err)?;
        }
        Value::Bool(b) => {
            e.bool(*b).map_err(err)?;
        }
        Value::Int(i) => {
            e.i64(*i).map_err(err)?;
        }
        Value::Bytes(b) => {
            e.bytes(b).map_err(err)?;
        }
        Value::Text(s) => {
            e.str(s).map_err(err)?;
        }
        Value::Array(items) => {
            e.array(len_u64(items.len())).map_err(err)?;
            for item in items {
                encode_into(e, item)?;
            }
        }
        Value::Map(entries) => {
            let mut keyed: Vec<(Vec<u8>, &Value)> = Vec::with_capacity(entries.len());
            for (key, val) in entries {
                if !matches!(key, Value::Int(_) | Value::Text(_)) {
                    return Err(CborError::InvalidKey);
                }
                keyed.push((encode(key)?, val));
            }
            keyed.sort_by(|a, b| a.0.cmp(&b.0));
            if keyed.windows(2).any(|w| matches!(w, [a, b] if a.0 == b.0)) {
                return Err(CborError::KeyOrder);
            }
            e.map(len_u64(keyed.len())).map_err(err)?;
            for (key_bytes, val) in keyed {
                e.writer_mut().extend_from_slice(&key_bytes);
                encode_into(e, val)?;
            }
        }
    }
    Ok(())
}

fn len_u64(len: usize) -> u64 {
    // usize is at most 64 bits on every supported target.
    u64::try_from(len).unwrap_or(u64::MAX)
}

impl Value {
    /// Returns the text if this is a `Text` value.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(s) => Some(s),
            _ => None,
        }
    }

    /// Returns the integer if this is an `Int` value.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// Returns the bytes if this is a `Bytes` value.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// Returns the elements if this is an `Array` value.
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    /// Looks up a text key in a `Map` value.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(entries) => entries
                .iter()
                .find(|(k, _)| k.as_text() == Some(key))
                .map(|(_, v)| v),
            _ => None,
        }
    }

    /// Builds a map from text keys, in canonical key order (so it compares equal to the same
    /// map after an encode/decode round trip). Convenience for tooling and tests.
    pub fn map<const N: usize>(entries: [(&str, Value); N]) -> Value {
        let mut entries: Vec<(Value, Value)> = entries
            .into_iter()
            .map(|(k, v)| (Value::Text(String::from(k)), v))
            .collect();
        // Text keys sort length-first, then bytewise (RFC 8949 §4.2.1).
        entries.sort_by(|(a, _), (b, _)| match (a, b) {
            (Value::Text(a), Value::Text(b)) => {
                (a.len(), a.as_bytes()).cmp(&(b.len(), b.as_bytes()))
            }
            _ => core::cmp::Ordering::Equal,
        });
        Value::Map(entries)
    }

    /// Builds a text value.
    pub fn text(s: &str) -> Value {
        Value::Text(String::from(s))
    }
}
