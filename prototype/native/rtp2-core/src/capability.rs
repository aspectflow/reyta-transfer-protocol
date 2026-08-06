// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//! Capabilities and provider authorization (§15).
//!
//! A capability authorizes some operations on some objects for a bounded
//! time. It never carries key material: a provider honouring one still sees
//! only ciphertext.
//!
//! Three things the spec leaves open, decided here:
//!
//! 1. §15.3 writes `token = RTP-CBOR(body || tag)`, but CBOR has no
//!    concatenation and the tag covers the body's exact bytes. So the token is
//!    `{0: bstr(body), 1: bstr(tag)}` and the inner byte string is MACed.
//! 2. `CapabilityBody` has no CDDL, so the field numbering below is ours.
//! 3. §15.2 names operations but gives no encoding; the bits below are ours.

use crate::{
    cbor::{CborError, MapWriter, Reader, Writer},
    crypto,
};

/// Tag domain. Not in the spec: keeps a provider capability key from being
/// confused with any other HMAC in the protocol.
const TAG_DOMAIN: &[u8] = b"RTP2-CAPABILITY-TAG-v1";

/// §15.2 operations, as a bit set.
pub const OP_READ_MANIFEST: u64 = 1 << 0;
pub const OP_READ_CHUNKS: u64 = 1 << 1;
pub const OP_READ_PROOFS: u64 = 1 << 2;
pub const OP_READ_PREVIEW: u64 = 1 << 3;
pub const OP_UPLOAD_CHUNKS: u64 = 1 << 4;
pub const OP_DELETE_OBJECT: u64 = 1 << 5;

/// Every bit this revision defines. Unknown ones are rejected, so an older
/// verifier cannot grant an operation it does not model.
pub const OP_ALL: u64 = OP_READ_MANIFEST
    | OP_READ_CHUNKS
    | OP_READ_PROOFS
    | OP_READ_PREVIEW
    | OP_UPLOAD_CHUNKS
    | OP_DELETE_OBJECT;

/// The read-only set a downloading peer needs.
pub const OP_DOWNLOAD: u64 = OP_READ_MANIFEST | OP_READ_CHUNKS | OP_READ_PROOFS | OP_READ_PREVIEW;

pub const CAPABILITY_VERSION: u64 = 1;

/// §15.1: at least 256 bits of unpredictable entropy.
pub const NONCE_LEN: usize = 32;
/// Upper bound on objects named by one capability (bounded allocation).
pub const MAX_OBJECTS: u64 = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityError {
    Encoding,
    UnsupportedVersion,
    UnknownOperation,
    NoOperations,
    TooManyObjects,
    BadTag,
    NotYetValid,
    Expired,
    WrongProvider,
    WrongTransfer,
    WrongObject,
    OperationNotPermitted,
}

impl From<CborError> for CapabilityError {
    fn from(_: CborError) -> Self {
        CapabilityError::Encoding
    }
}

/// `CapabilityBody` (§15.3). Our field numbering: 0 version, 1 provider_id,
/// 2 transfer_id, 3 object_ids, 4 operations, 5 not_before, 6 expires_at,
/// 7 nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityBody {
    pub version: u64,
    pub provider_id: [u8; 32],
    pub transfer_id: [u8; 32],
    pub object_ids: Vec<[u8; 32]>,
    pub operations: u64,
    pub not_before: u64,
    pub expires_at: u64,
    pub nonce: [u8; NONCE_LEN],
}

impl CapabilityBody {
    /// Mints a body with a fresh CSPRNG nonce (§15.1).
    pub fn new(
        provider_id: [u8; 32],
        transfer_id: [u8; 32],
        object_ids: Vec<[u8; 32]>,
        operations: u64,
        not_before: u64,
        expires_at: u64,
    ) -> Result<Self, CapabilityError> {
        let body = Self {
            version: CAPABILITY_VERSION,
            provider_id,
            transfer_id,
            object_ids,
            operations,
            not_before,
            expires_at,
            nonce: crypto::os_random_array(),
        };
        body.validate()?;
        Ok(body)
    }

    fn validate(&self) -> Result<(), CapabilityError> {
        if self.version != CAPABILITY_VERSION {
            return Err(CapabilityError::UnsupportedVersion);
        }
        if self.operations == 0 {
            return Err(CapabilityError::NoOperations);
        }
        if self.operations & !OP_ALL != 0 {
            return Err(CapabilityError::UnknownOperation);
        }
        if self.object_ids.is_empty() {
            return Err(CapabilityError::WrongObject);
        }
        if self.object_ids.len() as u64 > MAX_OBJECTS {
            return Err(CapabilityError::TooManyObjects);
        }
        // An open-ended capability is not a capability (§15.1).
        if self.expires_at <= self.not_before {
            return Err(CapabilityError::Expired);
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        let mut m = MapWriter::begin(&mut w, 8);
        m.uint(0, self.version);
        m.bytes(1, &self.provider_id);
        m.bytes(2, &self.transfer_id);
        {
            let inner = m.nested(3);
            inner.array(self.object_ids.len() as u64);
            for id in &self.object_ids {
                inner.bytes(id);
            }
        }
        m.uint(4, self.operations);
        m.uint(5, self.not_before);
        m.uint(6, self.expires_at);
        m.bytes(7, &self.nonce);
        m.end();
        w.into_bytes()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CapabilityError> {
        let mut r = Reader::new(bytes)?;
        let mut m = r.map()?;
        m.expect_key(0)?;
        let version = m.reader.uint()?;
        m.expect_key(1)?;
        let provider_id = m.reader.bytes_exact::<32>()?;
        m.expect_key(2)?;
        let transfer_id = m.reader.bytes_exact::<32>()?;
        m.expect_key(3)?;
        let count = m.reader.array()?;
        if count > MAX_OBJECTS {
            return Err(CapabilityError::TooManyObjects);
        }
        let mut object_ids = Vec::with_capacity(count as usize);
        for _ in 0..count {
            object_ids.push(m.reader.bytes_exact::<32>()?);
        }
        m.reader.leave();
        m.expect_key(4)?;
        let operations = m.reader.uint()?;
        m.expect_key(5)?;
        let not_before = m.reader.uint()?;
        m.expect_key(6)?;
        let expires_at = m.reader.uint()?;
        m.expect_key(7)?;
        let nonce = m.reader.bytes_exact::<NONCE_LEN>()?;
        if m.next_key()?.is_some() {
            return Err(CapabilityError::Encoding);
        }
        r.finish()?;

        let body = Self {
            version,
            provider_id,
            transfer_id,
            object_ids,
            operations,
            not_before,
            expires_at,
            nonce,
        };
        body.validate()?;
        Ok(body)
    }
}

/// A minted token: the exact body bytes that were MACed, plus the tag.
/// Keeping the bytes rather than re-encoding means no decoder quirk can turn
/// into a tag mismatch, or a collision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityToken {
    body_bytes: Vec<u8>,
    tag: [u8; 48],
}

impl CapabilityToken {
    /// §15.3: tag = HMAC-SHA384(provider_capability_key, RTP-CBOR(body)).
    pub fn mint(body: &CapabilityBody, provider_capability_key: &[u8]) -> Self {
        let body_bytes = body.encode();
        let tag = tag_for(&body_bytes, provider_capability_key);
        Self { body_bytes, tag }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        let mut m = MapWriter::begin(&mut w, 2);
        m.bytes(0, &self.body_bytes);
        m.bytes(1, &self.tag);
        m.end();
        w.into_bytes()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CapabilityError> {
        let mut r = Reader::new(bytes)?;
        let mut m = r.map()?;
        m.expect_key(0)?;
        let body_bytes = m.reader.bytes()?.to_vec();
        m.expect_key(1)?;
        let tag = m.reader.bytes_exact::<48>()?;
        if m.next_key()?.is_some() {
            return Err(CapabilityError::Encoding);
        }
        r.finish()?;
        Ok(Self { body_bytes, tag })
    }

    /// Verifies the provider MAC and returns the authenticated body.
    /// §15.3: MAC comparison MUST be constant time.
    pub fn verify(
        &self,
        provider_capability_key: &[u8],
    ) -> Result<CapabilityBody, CapabilityError> {
        let expected = tag_for(&self.body_bytes, provider_capability_key);
        if !crypto::ct_eq(&self.tag, &expected) {
            return Err(CapabilityError::BadTag);
        }
        CapabilityBody::decode(&self.body_bytes)
    }
}

fn tag_for(body_bytes: &[u8], provider_capability_key: &[u8]) -> [u8; 48] {
    let mut message = Vec::with_capacity(TAG_DOMAIN.len() + body_bytes.len());
    message.extend_from_slice(TAG_DOMAIN);
    message.extend_from_slice(body_bytes);
    crypto::hmac_sha384(provider_capability_key, &message)
}

/// What a provider checks before serving: the MAC, then every scope §15.1
/// requires, being provider, transfer, object, operation and time.
pub fn authorize(
    token: &CapabilityToken,
    provider_capability_key: &[u8],
    provider_id: &[u8; 32],
    transfer_id: &[u8; 32],
    object_id: &[u8; 32],
    operation: u64,
    now: u64,
) -> Result<CapabilityBody, CapabilityError> {
    let body = token.verify(provider_capability_key)?;
    if !crypto::ct_eq(&body.provider_id, provider_id) {
        return Err(CapabilityError::WrongProvider);
    }
    if !crypto::ct_eq(&body.transfer_id, transfer_id) {
        return Err(CapabilityError::WrongTransfer);
    }
    if !body
        .object_ids
        .iter()
        .any(|id| crypto::ct_eq(id, object_id))
    {
        return Err(CapabilityError::WrongObject);
    }
    // One request, one operation, and it must be a bit we know.
    if operation == 0 || operation & !OP_ALL != 0 || operation.count_ones() != 1 {
        return Err(CapabilityError::UnknownOperation);
    }
    if body.operations & operation == 0 {
        return Err(CapabilityError::OperationNotPermitted);
    }
    if now < body.not_before {
        return Err(CapabilityError::NotYetValid);
    }
    if now >= body.expires_at {
        return Err(CapabilityError::Expired);
    }
    Ok(body)
}

/// §15.4 abuse controls. The spec requires ceilings without giving numbers;
/// these are ours.
#[derive(Clone, Copy, Debug)]
pub struct AbuseLimits {
    pub max_bytes_per_capability: u64,
    pub max_concurrent_streams: u32,
    pub max_requests_per_minute: u32,
    pub max_ranges_per_request: u32,
    pub max_proof_bytes: u32,
    pub max_connection_memory_bytes: u64,
}

impl Default for AbuseLimits {
    fn default() -> Self {
        Self {
            // Enough for a large file plus retries, far short of a mirror.
            max_bytes_per_capability: 8 * 1024 * 1024 * 1024,
            max_concurrent_streams: 8,
            max_requests_per_minute: 600,
            max_ranges_per_request: 64,
            // 64 siblings * 33 bytes, rounded up with framing slack.
            max_proof_bytes: 4096,
            max_connection_memory_bytes: 32 * 1024 * 1024,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body() -> CapabilityBody {
        CapabilityBody::new([1; 32], [2; 32], vec![[3; 32]], OP_DOWNLOAD, 100, 200).unwrap()
    }

    #[test]
    fn mint_and_authorize() {
        let key = b"provider-key";
        let token = CapabilityToken::mint(&body(), key);
        let encoded = token.encode();
        let decoded = CapabilityToken::decode(&encoded).unwrap();
        assert_eq!(decoded, token);

        assert!(
            authorize(
                &decoded,
                key,
                &[1; 32],
                &[2; 32],
                &[3; 32],
                OP_READ_CHUNKS,
                150
            )
            .is_ok()
        );
    }

    #[test]
    fn every_scope_dimension_is_enforced() {
        let key = b"provider-key";
        let token = CapabilityToken::mint(&body(), key);
        let ok = |t: &CapabilityToken| {
            authorize(t, key, &[1; 32], &[2; 32], &[3; 32], OP_READ_CHUNKS, 150)
        };
        assert!(ok(&token).is_ok());

        assert_eq!(
            authorize(
                &token,
                b"other-key",
                &[1; 32],
                &[2; 32],
                &[3; 32],
                OP_READ_CHUNKS,
                150
            ),
            Err(CapabilityError::BadTag)
        );
        assert_eq!(
            authorize(
                &token,
                key,
                &[9; 32],
                &[2; 32],
                &[3; 32],
                OP_READ_CHUNKS,
                150
            ),
            Err(CapabilityError::WrongProvider)
        );
        assert_eq!(
            authorize(
                &token,
                key,
                &[1; 32],
                &[9; 32],
                &[3; 32],
                OP_READ_CHUNKS,
                150
            ),
            Err(CapabilityError::WrongTransfer)
        );
        assert_eq!(
            authorize(
                &token,
                key,
                &[1; 32],
                &[2; 32],
                &[9; 32],
                OP_READ_CHUNKS,
                150
            ),
            Err(CapabilityError::WrongObject)
        );
        assert_eq!(
            authorize(
                &token,
                key,
                &[1; 32],
                &[2; 32],
                &[3; 32],
                OP_DELETE_OBJECT,
                150
            ),
            Err(CapabilityError::OperationNotPermitted)
        );
        assert_eq!(
            authorize(
                &token,
                key,
                &[1; 32],
                &[2; 32],
                &[3; 32],
                OP_READ_CHUNKS,
                99
            ),
            Err(CapabilityError::NotYetValid)
        );
        assert_eq!(
            authorize(
                &token,
                key,
                &[1; 32],
                &[2; 32],
                &[3; 32],
                OP_READ_CHUNKS,
                200
            ),
            Err(CapabilityError::Expired)
        );
    }

    #[test]
    fn tampered_token_is_rejected() {
        let key = b"provider-key";
        let token = CapabilityToken::mint(&body(), key);
        let encoded = token.encode();
        for pos in [4usize, 20, encoded.len() - 1] {
            let mut bad = encoded.clone();
            bad[pos] ^= 1;
            match CapabilityToken::decode(&bad) {
                Err(_) => {}
                Ok(t) => assert_eq!(t.verify(key).err(), Some(CapabilityError::BadTag)),
            }
        }
    }

    #[test]
    fn nonces_are_unique() {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        for _ in 0..1000 {
            assert!(seen.insert(body().nonce));
        }
    }

    #[test]
    fn invalid_bodies_are_refused_at_mint_time() {
        // No operations.
        assert_eq!(
            CapabilityBody::new([1; 32], [2; 32], vec![[3; 32]], 0, 0, 1).err(),
            Some(CapabilityError::NoOperations)
        );
        // Unknown operation bit.
        assert_eq!(
            CapabilityBody::new([1; 32], [2; 32], vec![[3; 32]], 1 << 40, 0, 1).err(),
            Some(CapabilityError::UnknownOperation)
        );
        // No objects.
        assert_eq!(
            CapabilityBody::new([1; 32], [2; 32], vec![], OP_DOWNLOAD, 0, 1).err(),
            Some(CapabilityError::WrongObject)
        );
        // Unbounded lifetime.
        assert_eq!(
            CapabilityBody::new([1; 32], [2; 32], vec![[3; 32]], OP_DOWNLOAD, 10, 10).err(),
            Some(CapabilityError::Expired)
        );
    }
}
