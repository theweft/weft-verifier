// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! Public keys, key identifiers and signature verification.
//!
//! Only verification lives here. Signing happens outside the trusted core (TPM, HSM, tooling).

use alloc::vec::Vec;

use sha2::{Digest, Sha256};

/// Signature algorithms the verifier accepts. Anything else is rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Algorithm {
    /// Ed25519 (COSE `EdDSA`, id -8), verified with strict rules (no malleability).
    Ed25519,
    /// ECDSA with P-256 and SHA-256 (COSE `ES256`, id -7). Requires the `p256` feature.
    #[cfg(feature = "p256")]
    EcdsaP256,
}

impl Algorithm {
    /// The COSE algorithm identifier (IANA registry).
    pub const fn cose_id(self) -> i64 {
        match self {
            Algorithm::Ed25519 => -8,
            #[cfg(feature = "p256")]
            Algorithm::EcdsaP256 => -7,
        }
    }

    /// Maps a COSE algorithm identifier to a supported algorithm.
    pub const fn from_cose_id(id: i64) -> Option<Algorithm> {
        match id {
            -8 => Some(Algorithm::Ed25519),
            #[cfg(feature = "p256")]
            -7 => Some(Algorithm::EcdsaP256),
            _ => None,
        }
    }
}

/// Key identifier: the first 16 bytes of SHA-256 over a domain tag, the algorithm and the key.
///
/// Key ids are always *computed* from the key, never taken from a document, so a document
/// cannot claim another key's identity.
pub type KeyId = [u8; 16];

/// A public key with its algorithm.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey {
    /// The signature algorithm this key is used with.
    pub alg: Algorithm,
    /// Raw key bytes: 32 bytes for Ed25519, SEC1 encoding for P-256.
    pub bytes: Vec<u8>,
}

impl PublicKey {
    /// Computes this key's [`KeyId`].
    ///
    /// @relation(VER-007, scope=function)
    pub fn key_id(&self) -> KeyId {
        let mut hasher = Sha256::new();
        hasher.update(b"weft-key-id-v1");
        hasher.update(self.alg.cose_id().to_be_bytes());
        hasher.update(&self.bytes);
        let digest = hasher.finalize();
        let mut id = [0u8; 16];
        for (dst, src) in id.iter_mut().zip(digest.iter()) {
            *dst = *src;
        }
        id
    }

    /// Verifies `signature` over `message`. Returns `false` for any malformed key or signature.
    ///
    /// @relation(VER-006, scope=function)
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        match self.alg {
            Algorithm::Ed25519 => verify_ed25519(&self.bytes, message, signature),
            #[cfg(feature = "p256")]
            Algorithm::EcdsaP256 => verify_p256(&self.bytes, message, signature),
        }
    }
}

/// @relation(VER-006, scope=function)
fn verify_ed25519(key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(key) = <&[u8; 32]>::try_from(key) else {
        return false;
    };
    let Ok(signature) = <&[u8; 64]>::try_from(signature) else {
        return false;
    };
    let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(key) else {
        return false;
    };
    let signature = ed25519_dalek::Signature::from_bytes(signature);
    key.verify_strict(message, &signature).is_ok()
}

#[cfg(feature = "p256")]
fn verify_p256(key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use p256::ecdsa::signature::Verifier;
    let Ok(key) = p256::ecdsa::VerifyingKey::from_sec1_bytes(key) else {
        return false;
    };
    // COSE carries ECDSA signatures as raw r || s (RFC 9053 §2.1), not DER.
    let Ok(signature) = p256::ecdsa::Signature::from_slice(signature) else {
        return false;
    };
    key.verify(message, &signature).is_ok()
}

/// SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    for (dst, src) in out.iter_mut().zip(digest.iter()) {
        *dst = *src;
    }
    out
}
