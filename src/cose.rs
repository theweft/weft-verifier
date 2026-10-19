// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! Minimal `COSE_Sign1` (RFC 9052 §4.2) on top of the strict CBOR layer.
//!
//! Deliberately narrow: one signer, attached payload, empty external AAD, and *all* header
//! parameters protected (the unprotected header must be empty). The protected header contains
//! exactly `alg` (1) and `kid` (4). This keeps one CBOR implementation in the trusted path
//! instead of pulling in a general COSE library.

use alloc::vec::Vec;

use crate::cbor::{self, CborError, Limits, Value};

/// CBOR tag 18 (`COSE_Sign1`) as a single byte; optional in front of the array.
const TAG_SIGN1: u8 = 0xd2;
const HEADER_ALG: i64 = 1;
const HEADER_KID: i64 = 4;

/// A parsed, not yet verified `COSE_Sign1` message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sign1 {
    /// COSE algorithm id from the protected header.
    pub alg: i64,
    /// Key id from the protected header.
    pub kid: Vec<u8>,
    /// The serialized protected header, exactly as signed.
    pub protected: Vec<u8>,
    /// The payload, exactly as signed.
    pub payload: Vec<u8>,
    /// The signature bytes.
    pub signature: Vec<u8>,
}

/// Why a `COSE_Sign1` message was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CoseError {
    /// The CBOR layer rejected the input.
    Cbor(CborError),
    /// Valid CBOR, but not a `COSE_Sign1` structure this verifier accepts.
    Structure,
}

impl From<CborError> for CoseError {
    fn from(e: CborError) -> Self {
        CoseError::Cbor(e)
    }
}

impl Sign1 {
    /// Parses a `COSE_Sign1` message.
    ///
    /// # Errors
    ///
    /// Returns [`CoseError`] for malformed input or unsupported features.
    ///
    /// @relation(VER-004, scope=function)
    pub fn parse(bytes: &[u8], limits: &Limits) -> Result<Sign1, CoseError> {
        let body = match bytes.split_first() {
            Some((&TAG_SIGN1, rest)) => rest,
            _ => bytes,
        };
        let Value::Array(parts) = cbor::decode(body, limits)? else {
            return Err(CoseError::Structure);
        };
        let [
            Value::Bytes(protected),
            Value::Map(unprotected),
            Value::Bytes(payload),
            Value::Bytes(signature),
        ] = parts.as_slice()
        else {
            return Err(CoseError::Structure);
        };
        if !unprotected.is_empty() {
            return Err(CoseError::Structure);
        }
        let Value::Map(header) = cbor::decode(protected, limits)? else {
            return Err(CoseError::Structure);
        };
        let [
            (Value::Int(HEADER_ALG), Value::Int(alg)),
            (Value::Int(HEADER_KID), Value::Bytes(kid)),
        ] = header.as_slice()
        else {
            return Err(CoseError::Structure);
        };
        Ok(Sign1 {
            alg: *alg,
            kid: kid.clone(),
            protected: protected.clone(),
            payload: payload.clone(),
            signature: signature.clone(),
        })
    }

    /// The bytes the signature covers (the `Sig_structure`).
    ///
    /// # Errors
    ///
    /// Only fails if encoding fails, which cannot happen for well-typed input.
    pub fn signed_bytes(&self) -> Result<Vec<u8>, CoseError> {
        Ok(sig_structure(&self.protected, &self.payload)?)
    }
}

/// Encodes the `Sig_structure` `["Signature1", protected, h'', payload]` (RFC 9052 §4.4).
///
/// # Errors
///
/// Only fails if encoding fails, which cannot happen for well-typed input.
pub fn sig_structure(protected: &[u8], payload: &[u8]) -> Result<Vec<u8>, CborError> {
    cbor::encode(&Value::Array(alloc::vec![
        Value::text("Signature1"),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]))
}

/// Encodes a protected header with `alg` and `kid`. For signing tools and tests.
///
/// # Errors
///
/// Only fails if encoding fails, which cannot happen for well-typed input.
pub fn protected_header(alg: i64, kid: &[u8]) -> Result<Vec<u8>, CborError> {
    cbor::encode(&Value::Map(alloc::vec![
        (Value::Int(HEADER_ALG), Value::Int(alg)),
        (Value::Int(HEADER_KID), Value::Bytes(kid.to_vec())),
    ]))
}

/// Assembles an untagged `COSE_Sign1` message. For signing tools and tests.
///
/// # Errors
///
/// Only fails if encoding fails, which cannot happen for well-typed input.
pub fn encode_sign1(
    protected: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>, CborError> {
    cbor::encode(&Value::Array(alloc::vec![
        Value::Bytes(protected.to_vec()),
        Value::Map(Vec::new()),
        Value::Bytes(payload.to_vec()),
        Value::Bytes(signature.to_vec()),
    ]))
}
