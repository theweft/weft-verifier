//! Signed document types and their strict decoding.
//!
//! Every document is a CBOR map with text keys. Unknown fields, missing fields and wrong types
//! are errors: the verifier never guesses.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};

use crate::{
    cbor::Value,
    crypto::{Algorithm, KeyId, PublicKey},
    rights::{Action, Rights, Scope, pattern_is_valid},
};

/// Document format version understood by this verifier.
pub const FORMAT_VERSION: i64 = 1;

/// Fields common to all documents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// Tenant the document belongs to.
    pub tenant: String,
    /// Signing time, seconds since the Unix epoch. Accepted documents raise the trusted time floor.
    pub issued_at: u64,
}

/// A decoded document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Doc {
    /// Delegates rights to another key.
    Delegation {
        /// Common fields.
        header: Header,
        /// The key receiving the rights.
        subject: PublicKey,
        /// Declared rights; effective rights are intersected with the issuer's.
        rights: Rights,
    },
    /// A configuration fragment.
    Config {
        /// Common fields.
        header: Header,
        /// Targeting and versioning.
        target: Target,
        /// Partial configuration values (a map; JSON Merge Patch semantics).
        values: Value,
        /// Paths that no other scope may change.
        locks: BTreeSet<Vec<String>>,
    },
    /// Which artifact a component should run.
    Deployment {
        /// Common fields.
        header: Header,
        /// Targeting and versioning.
        target: Target,
        /// SHA-256 of the artifact.
        artifact: [u8; 32],
    },
    /// Revokes a key. Only trust anchors may revoke (format version 1).
    Revocation {
        /// Common fields.
        header: Header,
        /// The revoked key.
        key_id: KeyId,
    },
}

/// Targeting and versioning shared by config fragments and deployments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    /// Scope of the issuer's change.
    pub scope: Scope,
    /// Component the document applies to.
    pub component: String,
    /// Devices must carry all these labels.
    pub selector: BTreeMap<String, String>,
    /// Monotonic version per (kind, scope, issuer, component).
    pub version: u64,
}

impl Doc {
    /// The common fields.
    pub fn header(&self) -> &Header {
        match self {
            Doc::Delegation { header, .. }
            | Doc::Config { header, .. }
            | Doc::Deployment { header, .. }
            | Doc::Revocation { header, .. } => header,
        }
    }
}

/// Why a document payload was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DocError {
    /// Not a map, or a field has the wrong type.
    Type,
    /// A required field is missing.
    Missing,
    /// A field this format version does not define.
    UnknownField,
    /// Unsupported format version or document type.
    Version,
    /// A field value is out of range or invalid.
    Invalid,
}

/// Decodes a document payload.
///
/// # Errors
///
/// Returns [`DocError`] for anything that is not exactly a valid document.
pub fn parse(value: &Value) -> Result<Doc, DocError> {
    let mut obj = Obj::new(value)?;
    if obj.req("v")?.as_int() != Some(FORMAT_VERSION) {
        return Err(DocError::Version);
    }
    let kind = text(obj.req("type")?)?;
    let header = Header {
        tenant: non_empty(text(obj.req("tenant")?)?)?,
        issued_at: uint(obj.req("issued_at")?)?,
    };
    let doc = match kind.as_str() {
        "delegation" => {
            let subject = public_key(obj.req("subject")?)?;
            let rights = rights(obj.req("rights")?, &header.tenant)?;
            Doc::Delegation {
                header,
                subject,
                rights,
            }
        }
        "config" => {
            let target = target(&mut obj)?;
            let values = obj.req("values")?.clone();
            check_config_values(&values, 0)?;
            if !matches!(values, Value::Map(_)) {
                return Err(DocError::Type);
            }
            let locks = match obj.opt("locks") {
                None => BTreeSet::new(),
                Some(v) => array(v)?
                    .iter()
                    .map(|path| {
                        let path = array(path)?
                            .iter()
                            .map(text)
                            .collect::<Result<Vec<_>, _>>()?;
                        if path.is_empty() {
                            Err(DocError::Invalid)
                        } else {
                            Ok(path)
                        }
                    })
                    .collect::<Result<_, _>>()?,
            };
            Doc::Config {
                header,
                target,
                values,
                locks,
            }
        }
        "deployment" => {
            let target = target(&mut obj)?;
            let artifact = fixed::<32>(obj.req("artifact")?)?;
            Doc::Deployment {
                header,
                target,
                artifact,
            }
        }
        "revocation" => Doc::Revocation {
            header,
            key_id: fixed::<16>(obj.req("key_id")?)?,
        },
        _ => return Err(DocError::Version),
    };
    obj.finish()?;
    Ok(doc)
}

fn target(obj: &mut Obj<'_>) -> Result<Target, DocError> {
    let scope = Scope::parse(&text(obj.req("scope")?)?).ok_or(DocError::Invalid)?;
    let component = non_empty(text(obj.req("component")?)?)?;
    if component.contains('*') {
        return Err(DocError::Invalid);
    }
    let selector = match obj.opt("selector") {
        None => BTreeMap::new(),
        Some(v) => string_map(v)?,
    };
    let version = uint(obj.req("version")?)?;
    Ok(Target {
        scope,
        component,
        selector,
        version,
    })
}

fn public_key(value: &Value) -> Result<PublicKey, DocError> {
    let mut obj = Obj::new(value)?;
    let alg = obj.req("alg")?.as_int().ok_or(DocError::Type)?;
    let alg = Algorithm::from_cose_id(alg).ok_or(DocError::Invalid)?;
    let bytes = obj.req("key")?.as_bytes().ok_or(DocError::Type)?.to_vec();
    obj.finish()?;
    Ok(PublicKey { alg, bytes })
}

fn rights(value: &Value, tenant: &str) -> Result<Rights, DocError> {
    let mut obj = Obj::new(value)?;
    let actions = array(obj.req("actions")?)?
        .iter()
        .map(|v| Action::parse(&text(v)?).ok_or(DocError::Invalid))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let scopes = array(obj.req("scopes")?)?
        .iter()
        .map(|v| Scope::parse(&text(v)?).ok_or(DocError::Invalid))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let components = array(obj.req("components")?)?
        .iter()
        .map(|v| {
            let p = text(v)?;
            if pattern_is_valid(&p) {
                Ok(p)
            } else {
                Err(DocError::Invalid)
            }
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let labels = match obj.opt("labels") {
        None => BTreeMap::new(),
        Some(v) => string_map(v)?,
    };
    let not_before = uint(obj.req("not_before")?)?;
    let not_after = uint(obj.req("not_after")?)?;
    obj.finish()?;
    Ok(Rights {
        tenant: String::from(tenant),
        actions,
        scopes,
        components,
        labels,
        not_before,
        not_after,
    })
}

/// Configuration values: maps must have text keys all the way down.
fn check_config_values(value: &Value, depth: usize) -> Result<(), DocError> {
    let child = depth.checked_add(1).ok_or(DocError::Invalid)?;
    match value {
        Value::Map(entries) => entries.iter().try_for_each(|(k, v)| {
            if k.as_text().is_none() {
                return Err(DocError::Type);
            }
            check_config_values(v, child)
        }),
        Value::Array(items) => items.iter().try_for_each(|v| check_config_values(v, child)),
        _ => Ok(()),
    }
}

fn text(value: &Value) -> Result<String, DocError> {
    value.as_text().map(String::from).ok_or(DocError::Type)
}

fn non_empty(s: String) -> Result<String, DocError> {
    if s.is_empty() {
        Err(DocError::Invalid)
    } else {
        Ok(s)
    }
}

fn uint(value: &Value) -> Result<u64, DocError> {
    let i = value.as_int().ok_or(DocError::Type)?;
    u64::try_from(i).map_err(|_| DocError::Invalid)
}

fn array(value: &Value) -> Result<&[Value], DocError> {
    value.as_array().ok_or(DocError::Type)
}

fn fixed<const N: usize>(value: &Value) -> Result<[u8; N], DocError> {
    let bytes = value.as_bytes().ok_or(DocError::Type)?;
    <[u8; N]>::try_from(bytes).map_err(|_| DocError::Invalid)
}

fn string_map(value: &Value) -> Result<BTreeMap<String, String>, DocError> {
    let Value::Map(entries) = value else {
        return Err(DocError::Type);
    };
    entries
        .iter()
        .map(|(k, v)| Ok((text(k)?, text(v)?)))
        .collect()
}

/// A map being consumed field by field; [`Obj::finish`] rejects fields nobody asked for.
struct Obj<'a> {
    entries: &'a [(Value, Value)],
    used: Vec<bool>,
}

impl<'a> Obj<'a> {
    fn new(value: &'a Value) -> Result<Self, DocError> {
        let Value::Map(entries) = value else {
            return Err(DocError::Type);
        };
        Ok(Obj {
            entries,
            used: alloc::vec![false; entries.len()],
        })
    }

    fn opt(&mut self, key: &str) -> Option<&'a Value> {
        let entries = self.entries;
        for ((k, v), used) in entries.iter().zip(self.used.iter_mut()) {
            if k.as_text() == Some(key) {
                *used = true;
                return Some(v);
            }
        }
        None
    }

    fn req(&mut self, key: &str) -> Result<&'a Value, DocError> {
        self.opt(key).ok_or(DocError::Missing)
    }

    fn finish(self) -> Result<(), DocError> {
        if self.used.iter().all(|u| *u) {
            Ok(())
        } else {
            Err(DocError::UnknownField)
        }
    }
}
