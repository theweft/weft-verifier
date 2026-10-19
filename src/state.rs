// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! Deterministic CBOR encoding of [`VerifierState`] for persistence by the shell.
//!
//! Stored state is read back through the same strict decoder as any other input.

use alloc::{collections::BTreeMap, string::String, vec::Vec};

use crate::{
    VerifierState,
    cbor::{self, CborError, Limits, Value},
    rights::Priority,
    verifier::{Kind, Mark, Slot},
};

const STATE_VERSION: i64 = 1;

/// Why stored state could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateError {
    /// The CBOR layer rejected the bytes.
    Cbor(CborError),
    /// Valid CBOR, but not a state document of this version.
    Format,
}

impl From<CborError> for StateError {
    fn from(e: CborError) -> Self {
        StateError::Cbor(e)
    }
}

/// Limits for stored state (larger than for single documents).
pub const STATE_LIMITS: Limits = Limits {
    max_len: 1024 * 1024,
    max_depth: 8,
    max_items: 64 * 1024,
};

impl VerifierState {
    /// Encodes the state deterministically.
    ///
    /// # Errors
    ///
    /// Only fails if encoding fails, which cannot happen for well-typed state.
    ///
    /// @relation(VER-024, scope=function)
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        let marks = self
            .marks
            .iter()
            .map(|(slot, mark)| {
                Value::Array(alloc::vec![
                    Value::text(match slot.kind {
                        Kind::Config => "config",
                        Kind::Deployment => "deployment",
                    }),
                    Value::Int(i64::from(slot.priority)),
                    Value::Bytes(slot.issuer.to_vec()),
                    Value::Text(slot.component.clone()),
                    Value::Int(i64::try_from(mark.version).unwrap_or(i64::MAX)),
                    Value::Bytes(mark.digest.to_vec()),
                ])
            })
            .collect();
        let revoked = self
            .revoked
            .iter()
            .map(|k| Value::Bytes(k.to_vec()))
            .collect();
        cbor::encode(&Value::map([
            ("v", Value::Int(STATE_VERSION)),
            (
                "time_floor",
                Value::Int(i64::try_from(self.time_floor).unwrap_or(i64::MAX)),
            ),
            ("marks", Value::Array(marks)),
            ("revoked", Value::Array(revoked)),
        ]))
    }

    /// Decodes state written by [`VerifierState::to_cbor`].
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] for anything that is not exactly a valid state document.
    ///
    /// @relation(VER-024, scope=function)
    pub fn from_cbor(bytes: &[u8]) -> Result<VerifierState, StateError> {
        let value = cbor::decode(bytes, &STATE_LIMITS)?;
        let Value::Map(entries) = &value else {
            return Err(StateError::Format);
        };
        if entries.len() != 4 || value.get("v").and_then(Value::as_int) != Some(STATE_VERSION) {
            return Err(StateError::Format);
        }
        let time_floor = value
            .get("time_floor")
            .and_then(Value::as_int)
            .and_then(|i| u64::try_from(i).ok())
            .ok_or(StateError::Format)?;
        let mut marks = BTreeMap::new();
        for item in value
            .get("marks")
            .and_then(Value::as_array)
            .ok_or(StateError::Format)?
        {
            let [kind, priority, issuer, component, version, digest] =
                item.as_array().ok_or(StateError::Format)?
            else {
                return Err(StateError::Format);
            };
            let kind = match kind.as_text() {
                Some("config") => Kind::Config,
                Some("deployment") => Kind::Deployment,
                _ => return Err(StateError::Format),
            };
            let priority = priority
                .as_int()
                .and_then(|i| Priority::try_from(i).ok())
                .ok_or(StateError::Format)?;
            let issuer = bytes_n::<16>(issuer)?;
            let component = String::from(component.as_text().ok_or(StateError::Format)?);
            let version = version
                .as_int()
                .and_then(|i| u64::try_from(i).ok())
                .ok_or(StateError::Format)?;
            let digest = bytes_n::<32>(digest)?;
            marks.insert(
                Slot {
                    kind,
                    priority,
                    issuer,
                    component,
                },
                Mark { version, digest },
            );
        }
        let revoked = value
            .get("revoked")
            .and_then(Value::as_array)
            .ok_or(StateError::Format)?
            .iter()
            .map(bytes_n::<16>)
            .collect::<Result<_, _>>()?;
        Ok(VerifierState {
            time_floor,
            marks,
            revoked,
        })
    }
}

fn bytes_n<const N: usize>(value: &Value) -> Result<[u8; N], StateError> {
    value
        .as_bytes()
        .and_then(|b| <[u8; N]>::try_from(b).ok())
        .ok_or(StateError::Format)
}
