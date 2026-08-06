// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//! Manifest model (§13) and manifest commitment (§12.6).
//!
//! Field numbering follows the CDDL exactly.
//!
//! Three places the normative text is unsettled, pinned here:
//!
//! 1. §13.1 prose lists `object_count`; the CDDL has no such key, so the array
//!    length is the count and a redundant field is a critical unknown key.
//! 2. §12.6 hashes the public manifest "without commitment", but the CDDL has
//!    no commitment field, so that is just the ordinary encoding.
//! 3. §13.3 AAD ends with `recipient_device_id_or_scope_hash`, undefined in
//!    the spec. `RecipientScope::hash` is what this uses.

use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use zeroize::Zeroizing;

use crate::{
    cbor::{CborError, MapWriter, Reader, Writer},
    crypto::{self, PROTOCOL_MAJOR, SUITE_ID},
    object::ALLOWED_CHUNK_SIZES,
};

/// §12.6 manifest commitment domain.
const COMMITMENT_DOMAIN: &[u8] = b"RTP2-MANIFEST-COMMITMENT-v1\0";
/// §13.3 private-manifest AEAD associated data prefix.
const MANIFEST_AAD_DOMAIN: &[u8] = b"RTP2-MANIFEST-AAD-v1";
/// Prototype binding for the undefined `recipient_scope_hash` (see gap 3).
const SCOPE_DOMAIN: &[u8] = b"RTP2-RECIPIENT-SCOPE-v1";

/// Cap on objects per manifest, so decoding stays bounded (§13.4).
pub const MAX_OBJECTS: u64 = 1024;
/// Upper bound on any display/text field, in bytes.
pub const MAX_TEXT_LEN: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestError {
    Encoding,
    UnknownCriticalField,
    UnsupportedVersion,
    UnsupportedSuite,
    InvalidValue,
    TooManyObjects,
    TextTooLong,
    Crypto,
    CommitmentMismatch,
}

impl From<CborError> for ManifestError {
    fn from(_: CborError) -> Self {
        ManifestError::Encoding
    }
}

// ---------------------------------------------------------------------------
// Enumerations (rtp2.cddl)
// ---------------------------------------------------------------------------

/// `route-profile` (§1.3).
pub const ROUTE_FAST_DIRECT: u8 = 0;
pub const ROUTE_BALANCED: u8 = 1;
pub const ROUTE_PRIVATE_RELAY: u8 = 2;
pub const ROUTE_STEALTH_TRANSFER: u8 = 3;

/// `object-role`.
pub const ROLE_PRIMARY: u8 = 0;
pub const ROLE_THUMBNAIL: u8 = 1;
pub const ROLE_PREVIEW: u8 = 2;
pub const ROLE_STREAM_INDEX: u8 = 3;
pub const ROLE_DERIVATIVE: u8 = 4;
pub const ROLE_SIDECAR: u8 = 5;

/// `padding-policy` (§10.3).
pub const PADDING_NONE: u8 = 0;
pub const PADDING_LAST_CHUNK: u8 = 1;
pub const PADDING_POWER_OF_TWO: u8 = 2;
pub const PADDING_FIXED_BUCKET: u8 = 3;

/// `capability-scheme`: the CDDL fixes the only defined value.
pub const CAPABILITY_SCHEME: u64 = 1;

fn valid_route_profile(v: u64) -> bool {
    v <= ROUTE_STEALTH_TRANSFER as u64
}

fn valid_role(v: u64) -> bool {
    v <= ROLE_SIDECAR as u64
}

fn valid_padding(v: u64) -> bool {
    v <= PADDING_FIXED_BUCKET as u64
}

// ---------------------------------------------------------------------------
// Public manifest (§13.1)
// ---------------------------------------------------------------------------

/// `object-public`. Transfer mechanics only, nothing derived from the
/// plaintext (§13.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectPublic {
    pub object_id: [u8; 32],
    pub object_role: u8,
    pub ciphertext_root: [u8; 32],
    pub ciphertext_size: u64,
    pub chunk_ciphertext_size: u64,
    pub chunk_count: u64,
    pub padding_policy: u8,
}

impl ObjectPublic {
    fn encode(&self, w: &mut Writer) {
        let mut m = MapWriter::begin(w, 7);
        m.bytes(0, &self.object_id);
        m.uint(1, self.object_role as u64);
        m.bytes(2, &self.ciphertext_root);
        m.uint(3, self.ciphertext_size);
        m.uint(4, self.chunk_ciphertext_size);
        m.uint(5, self.chunk_count);
        m.uint(6, self.padding_policy as u64);
        m.end();
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ManifestError> {
        let mut m = r.map()?;
        m.expect_key(0)?;
        let object_id = m.reader.bytes_exact::<32>()?;
        m.expect_key(1)?;
        let object_role = m.reader.uint()?;
        m.expect_key(2)?;
        let ciphertext_root = m.reader.bytes_exact::<32>()?;
        m.expect_key(3)?;
        let ciphertext_size = m.reader.uint()?;
        m.expect_key(4)?;
        let chunk_ciphertext_size = m.reader.uint()?;
        m.expect_key(5)?;
        let chunk_count = m.reader.uint()?;
        m.expect_key(6)?;
        let padding_policy = m.reader.uint()?;
        // Key 7 is the noncritical extension map. Anything else unknown is
        // critical and must be rejected (§13.4).
        match m.next_key()? {
            None => {}
            Some(7) => {
                skip_extension_map(m.reader)?;
                if m.next_key()?.is_some() {
                    return Err(ManifestError::UnknownCriticalField);
                }
            }
            Some(_) => return Err(ManifestError::UnknownCriticalField),
        }

        if !valid_role(object_role) || !valid_padding(padding_policy) {
            return Err(ManifestError::InvalidValue);
        }
        Ok(Self {
            object_id,
            object_role: object_role as u8,
            ciphertext_root,
            ciphertext_size,
            chunk_ciphertext_size,
            chunk_count,
            padding_policy: padding_policy as u8,
        })
    }
}

/// Reads and drops the noncritical extension map. Only RTP-CBOR value shapes
/// are accepted, so an extension cannot smuggle a forbidden encoding in.
fn skip_extension_map(r: &mut Reader<'_>) -> Result<(), ManifestError> {
    let mut m = r.map()?;
    while m.next_key()?.is_some() {
        skip_value(m.reader)?;
    }
    Ok(())
}

fn skip_value(r: &mut Reader<'_>) -> Result<(), ManifestError> {
    // A streaming reader cannot try-and-rewind, so peek at the major type.
    match r.peek_major()? {
        0 => {
            r.uint()?;
        }
        2 => {
            r.bytes()?;
        }
        3 => {
            r.text()?;
        }
        4 => {
            let n = r.array()?;
            for _ in 0..n {
                skip_value(r)?;
            }
            r.leave();
        }
        5 => {
            let mut m = r.map()?;
            while m.next_key()?.is_some() {
                skip_value(m.reader)?;
            }
        }
        _ => return Err(ManifestError::Encoding),
    }
    Ok(())
}

/// `public-manifest`. A relay holding the ticket sees all of this, so §13.1's
/// prohibition list is structural: there is simply no field for a filename,
/// MIME type, digest, key or nonce seed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicManifest {
    pub protocol_minor: u64,
    pub suite_id: u16,
    pub transfer_id: [u8; 32],
    pub created_at: u64,
    pub expires_at: u64,
    pub route_profile: u8,
    pub objects: Vec<ObjectPublic>,
    pub private_manifest_ciphertext_hash: [u8; 32],
    pub capability_scheme: u64,
}

impl PublicManifest {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        let mut m = MapWriter::begin(&mut w, 10);
        m.uint(0, PROTOCOL_MAJOR as u64);
        m.uint(1, self.protocol_minor);
        m.uint(2, self.suite_id as u64);
        m.bytes(3, &self.transfer_id);
        m.uint(4, self.created_at);
        m.uint(5, self.expires_at);
        m.uint(6, self.route_profile as u64);
        {
            let inner = m.nested(7);
            inner.array(self.objects.len() as u64);
            for object in &self.objects {
                object.encode(inner);
            }
        }
        m.bytes(8, &self.private_manifest_ciphertext_hash);
        m.uint(9, self.capability_scheme);
        m.end();
        w.into_bytes()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ManifestError> {
        let mut r = Reader::new(bytes)?;
        let mut m = r.map()?;
        m.expect_key(0)?;
        if m.reader.uint()? != PROTOCOL_MAJOR as u64 {
            return Err(ManifestError::UnsupportedVersion);
        }
        m.expect_key(1)?;
        let protocol_minor = m.reader.uint()?;
        m.expect_key(2)?;
        let suite_id = m.reader.uint()?;
        if suite_id != SUITE_ID as u64 {
            return Err(ManifestError::UnsupportedSuite);
        }
        m.expect_key(3)?;
        let transfer_id = m.reader.bytes_exact::<32>()?;
        m.expect_key(4)?;
        let created_at = m.reader.uint()?;
        m.expect_key(5)?;
        let expires_at = m.reader.uint()?;
        m.expect_key(6)?;
        let route_profile = m.reader.uint()?;
        if !valid_route_profile(route_profile) {
            return Err(ManifestError::InvalidValue);
        }
        m.expect_key(7)?;
        let count = m.reader.array()?;
        if count > MAX_OBJECTS {
            return Err(ManifestError::TooManyObjects);
        }
        let mut objects = Vec::with_capacity(count as usize);
        for _ in 0..count {
            objects.push(ObjectPublic::decode(m.reader)?);
        }
        m.reader.leave();
        m.expect_key(8)?;
        let private_manifest_ciphertext_hash = m.reader.bytes_exact::<32>()?;
        m.expect_key(9)?;
        let capability_scheme = m.reader.uint()?;
        match m.next_key()? {
            None => {}
            Some(10) => {
                skip_extension_map(m.reader)?;
                if m.next_key()?.is_some() {
                    return Err(ManifestError::UnknownCriticalField);
                }
            }
            Some(_) => return Err(ManifestError::UnknownCriticalField),
        }
        r.finish()?;

        let manifest = Self {
            protocol_minor,
            suite_id: suite_id as u16,
            transfer_id,
            created_at,
            expires_at,
            route_profile: route_profile as u8,
            objects,
            private_manifest_ciphertext_hash,
            capability_scheme,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    /// Semantic checks that the CDDL cannot express.
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.objects.is_empty() {
            return Err(ManifestError::InvalidValue);
        }
        if self.expires_at <= self.created_at {
            return Err(ManifestError::InvalidValue);
        }
        if self.capability_scheme != CAPABILITY_SCHEME {
            return Err(ManifestError::InvalidValue);
        }
        // Exactly one PRIMARY object.
        if self
            .objects
            .iter()
            .filter(|o| o.object_role == ROLE_PRIMARY)
            .count()
            != 1
        {
            return Err(ManifestError::InvalidValue);
        }
        let mut seen = std::collections::HashSet::new();
        for object in &self.objects {
            if !seen.insert(object.object_id) {
                return Err(ManifestError::InvalidValue);
            }
            // Ciphertext chunk size is plaintext plus tag, and the plaintext
            // size has to be one §10.2 allows.
            let plaintext_chunk = object
                .chunk_ciphertext_size
                .checked_sub(crate::object::AEAD_TAG_LEN as u64)
                .ok_or(ManifestError::InvalidValue)?;
            if !ALLOWED_CHUNK_SIZES.contains(&(plaintext_chunk as u32)) {
                return Err(ManifestError::InvalidValue);
            }
            // chunk_count must be consistent with ciphertext_size.
            if object.chunk_count == 0 {
                if object.ciphertext_size != 0 {
                    return Err(ManifestError::InvalidValue);
                }
            } else {
                let max = object.chunk_count * object.chunk_ciphertext_size;
                let min =
                    max - object.chunk_ciphertext_size + 1 + crate::object::AEAD_TAG_LEN as u64;
                if object.ciphertext_size > max || object.ciphertext_size < min {
                    return Err(ManifestError::InvalidValue);
                }
            }
        }
        Ok(())
    }

    pub fn primary(&self) -> Option<&ObjectPublic> {
        self.objects.iter().find(|o| o.object_role == ROLE_PRIMARY)
    }

    /// §12.6 commitment, binding the public manifest and the private
    /// ciphertext together. The signed offer carries it.
    pub fn commitment(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(COMMITMENT_DOMAIN);
        h.update(&self.encode());
        h.update(&self.private_manifest_ciphertext_hash);
        *h.finalize().as_bytes()
    }
}

// ---------------------------------------------------------------------------
// Private manifest (§13.2)
// ---------------------------------------------------------------------------

/// `recipient-scope`. Its hash is what fills the §13.3 AAD component the
/// spec leaves undefined.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientScope {
    pub scope_type: u64,
    pub id: Vec<u8>,
}

impl RecipientScope {
    /// A single recipient device.
    pub const TYPE_DEVICE: u64 = 0;
    /// A named group / multi-device scope.
    pub const TYPE_GROUP: u64 = 1;

    pub fn device(device_id: &[u8; 32]) -> Self {
        Self {
            scope_type: Self::TYPE_DEVICE,
            id: device_id.to_vec(),
        }
    }

    fn encode(&self, w: &mut Writer) {
        let mut m = MapWriter::begin(w, 2);
        m.uint(0, self.scope_type);
        m.bytes(1, &self.id);
        m.end();
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ManifestError> {
        let mut m = r.map()?;
        m.expect_key(0)?;
        let scope_type = m.reader.uint()?;
        m.expect_key(1)?;
        let id = m.reader.bytes()?.to_vec();
        if m.next_key()?.is_some() {
            return Err(ManifestError::UnknownCriticalField);
        }
        if id.len() > MAX_TEXT_LEN {
            return Err(ManifestError::InvalidValue);
        }
        Ok(Self { scope_type, id })
    }

    /// `recipient_device_id_or_scope_hash` for the §13.3 AAD.
    pub fn hash(&self) -> [u8; 32] {
        let mut w = Writer::new();
        self.encode(&mut w);
        let mut h = blake3::Hasher::new();
        h.update(SCOPE_DOMAIN);
        h.update(&w.into_bytes());
        *h.finalize().as_bytes()
    }
}

/// `key-policy`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyPolicy {
    pub mode: u64,
    pub minimum_security_level: u64,
    pub pqc_required: bool,
}

/// `retention-policy`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub expires_at: u64,
    pub view_once: bool,
    pub allow_local_save: bool,
}

/// `object-private`. Only the mandatory triple so far; stream maps and format
/// metadata are optional and unpopulated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectPrivate {
    pub object_id: [u8; 32],
    pub object_role: u8,
    pub relationship_to_primary: u64,
}

impl ObjectPrivate {
    fn encode(&self, w: &mut Writer) {
        let mut m = MapWriter::begin(w, 3);
        m.bytes(0, &self.object_id);
        m.uint(1, self.object_role as u64);
        m.uint(2, self.relationship_to_primary);
        m.end();
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ManifestError> {
        let mut m = r.map()?;
        m.expect_key(0)?;
        let object_id = m.reader.bytes_exact::<32>()?;
        m.expect_key(1)?;
        let object_role = m.reader.uint()?;
        m.expect_key(2)?;
        let relationship_to_primary = m.reader.uint()?;
        // Optional keys 3/4/5 are noncritical per the CDDL.
        loop {
            match m.next_key()? {
                None => break,
                Some(3..=5) => skip_value(m.reader)?,
                Some(_) => return Err(ManifestError::UnknownCriticalField),
            }
        }
        if !valid_role(object_role) {
            return Err(ManifestError::InvalidValue);
        }
        Ok(Self {
            object_id,
            object_role: object_role as u8,
            relationship_to_primary,
        })
    }
}

/// `private-manifest`: everything the recipient needs and nobody else may see.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateManifest {
    pub sender_account_id: [u8; 32],
    pub sender_device_id: [u8; 32],
    pub recipient_scope: RecipientScope,
    pub display_name: String,
    pub original_filename: String,
    pub mime_type: String,
    pub logical_plaintext_size: u64,
    pub plaintext_digest: [u8; 32],
    pub created_at: u64,
    pub user_caption: Option<String>,
    pub objects: Vec<ObjectPrivate>,
    pub key_policy: KeyPolicy,
    pub retention_policy: RetentionPolicy,
}

impl PrivateManifest {
    pub fn encode(&self) -> Result<Vec<u8>, ManifestError> {
        for text in [&self.display_name, &self.original_filename, &self.mime_type] {
            if text.len() > MAX_TEXT_LEN {
                return Err(ManifestError::TextTooLong);
            }
        }
        if let Some(caption) = &self.user_caption
            && caption.len() > MAX_TEXT_LEN
        {
            return Err(ManifestError::TextTooLong);
        }
        if self.objects.len() as u64 > MAX_OBJECTS {
            return Err(ManifestError::TooManyObjects);
        }

        let entries = if self.user_caption.is_some() { 13 } else { 12 };
        let mut w = Writer::new();
        let mut m = MapWriter::begin(&mut w, entries);
        m.bytes(0, &self.sender_account_id);
        m.bytes(1, &self.sender_device_id);
        {
            let inner = m.nested(2);
            self.recipient_scope.encode(inner);
        }
        m.text(3, &self.display_name);
        m.text(4, &self.original_filename);
        m.text(5, &self.mime_type);
        m.uint(6, self.logical_plaintext_size);
        m.bytes(7, &self.plaintext_digest);
        m.uint(8, self.created_at);
        if let Some(caption) = &self.user_caption {
            m.text(9, caption);
        }
        {
            let inner = m.nested(10);
            inner.array(self.objects.len() as u64);
            for object in &self.objects {
                object.encode(inner);
            }
        }
        {
            let inner = m.nested(11);
            let mut km = MapWriter::begin(inner, 3);
            km.uint(0, self.key_policy.mode);
            km.uint(1, self.key_policy.minimum_security_level);
            km.boolean(2, self.key_policy.pqc_required);
            km.end();
        }
        {
            let inner = m.nested(12);
            let mut rm = MapWriter::begin(inner, 3);
            rm.uint(0, self.retention_policy.expires_at);
            rm.boolean(1, self.retention_policy.view_once);
            rm.boolean(2, self.retention_policy.allow_local_save);
            rm.end();
        }
        m.end();
        Ok(w.into_bytes())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ManifestError> {
        let mut r = Reader::new(bytes)?;
        let mut m = r.map()?;
        m.expect_key(0)?;
        let sender_account_id = m.reader.bytes_exact::<32>()?;
        m.expect_key(1)?;
        let sender_device_id = m.reader.bytes_exact::<32>()?;
        m.expect_key(2)?;
        let recipient_scope = RecipientScope::decode(m.reader)?;
        m.expect_key(3)?;
        let display_name = m.reader.text()?.to_owned();
        m.expect_key(4)?;
        let original_filename = m.reader.text()?.to_owned();
        m.expect_key(5)?;
        let mime_type = m.reader.text()?.to_owned();
        m.expect_key(6)?;
        let logical_plaintext_size = m.reader.uint()?;
        m.expect_key(7)?;
        let plaintext_digest = m.reader.bytes_exact::<32>()?;
        m.expect_key(8)?;
        let created_at = m.reader.uint()?;

        // Key 9 (user_caption) is optional; 10, 11, 12 are mandatory.
        let mut user_caption = None;
        let mut key = m.next_key()?.ok_or(ManifestError::Encoding)?;
        if key == 9 {
            user_caption = Some(m.reader.text()?.to_owned());
            key = m.next_key()?.ok_or(ManifestError::Encoding)?;
        }
        if key != 10 {
            return Err(ManifestError::Encoding);
        }
        let count = m.reader.array()?;
        if count > MAX_OBJECTS {
            return Err(ManifestError::TooManyObjects);
        }
        let mut objects = Vec::with_capacity(count as usize);
        for _ in 0..count {
            objects.push(ObjectPrivate::decode(m.reader)?);
        }
        m.reader.leave();

        m.expect_key(11)?;
        let key_policy = {
            let mut km = m.reader.map()?;
            km.expect_key(0)?;
            let mode = km.reader.uint()?;
            km.expect_key(1)?;
            let minimum_security_level = km.reader.uint()?;
            km.expect_key(2)?;
            let pqc_required = km.reader.boolean()?;
            if km.next_key()?.is_some() {
                return Err(ManifestError::UnknownCriticalField);
            }
            KeyPolicy {
                mode,
                minimum_security_level,
                pqc_required,
            }
        };
        m.expect_key(12)?;
        let retention_policy = {
            let mut rm = m.reader.map()?;
            rm.expect_key(0)?;
            let expires_at = rm.reader.uint()?;
            rm.expect_key(1)?;
            let view_once = rm.reader.boolean()?;
            rm.expect_key(2)?;
            let allow_local_save = rm.reader.boolean()?;
            if rm.next_key()?.is_some() {
                return Err(ManifestError::UnknownCriticalField);
            }
            RetentionPolicy {
                expires_at,
                view_once,
                allow_local_save,
            }
        };
        match m.next_key()? {
            None => {}
            Some(13) => {
                skip_extension_map(m.reader)?;
                if m.next_key()?.is_some() {
                    return Err(ManifestError::UnknownCriticalField);
                }
            }
            Some(_) => return Err(ManifestError::UnknownCriticalField),
        }
        r.finish()?;

        let manifest = Self {
            sender_account_id,
            sender_device_id,
            recipient_scope,
            display_name,
            original_filename,
            mime_type,
            logical_plaintext_size,
            plaintext_digest,
            created_at,
            user_caption,
            objects,
            key_policy,
            retention_policy,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.objects.is_empty() {
            return Err(ManifestError::InvalidValue);
        }
        if self
            .objects
            .iter()
            .filter(|o| o.object_role == ROLE_PRIMARY)
            .count()
            != 1
        {
            return Err(ManifestError::InvalidValue);
        }
        // This core runs PQC_REQUIRED, so a manifest permitting classical
        // only is refused rather than quietly accepted (§6.3).
        if !self.key_policy.pqc_required || self.key_policy.minimum_security_level == 0 {
            return Err(ManifestError::InvalidValue);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Manifest encryption (§13.3)
// ---------------------------------------------------------------------------

/// §13.3 AAD:
/// "RTP2-MANIFEST-AAD-v1" || transfer_id || object_id_of_primary || suite_id
/// || sender_device_id || recipient_device_id_or_scope_hash
pub fn manifest_aad(
    transfer_id: &[u8; 32],
    primary_object_id: &[u8; 32],
    sender_device_id: &[u8; 32],
    recipient_scope: &RecipientScope,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(MANIFEST_AAD_DOMAIN.len() + 32 * 4 + 2);
    aad.extend_from_slice(MANIFEST_AAD_DOMAIN);
    aad.extend_from_slice(transfer_id);
    aad.extend_from_slice(primary_object_id);
    aad.extend_from_slice(&SUITE_ID.to_be_bytes());
    aad.extend_from_slice(sender_device_id);
    aad.extend_from_slice(&recipient_scope.hash());
    aad
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedManifest {
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

impl SealedManifest {
    /// Bound into the public manifest and the §12.6 commitment. Covers the
    /// nonce too, so a nonce swap fails the commitment, not just the AEAD.
    pub fn ciphertext_hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(&self.nonce);
        h.update(&self.ciphertext);
        *h.finalize().as_bytes()
    }
}

/// §13.3: deterministic RTP-CBOR body, fresh random 24-byte nonce.
pub fn seal_private_manifest(
    manifest: &PrivateManifest,
    manifest_key: &[u8; 32],
    transfer_id: &[u8; 32],
    primary_object_id: &[u8; 32],
) -> Result<SealedManifest, ManifestError> {
    manifest.validate()?;
    let plaintext = Zeroizing::new(manifest.encode()?);
    let aad = manifest_aad(
        transfer_id,
        primary_object_id,
        &manifest.sender_device_id,
        &manifest.recipient_scope,
    );
    let cipher =
        XChaCha20Poly1305::new_from_slice(manifest_key).map_err(|_| ManifestError::Crypto)?;
    let nonce: [u8; 24] = crypto::os_random_array();
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_ref(),
                aad: &aad,
            },
        )
        .map_err(|_| ManifestError::Crypto)?;
    Ok(SealedManifest { nonce, ciphertext })
}

pub fn open_private_manifest(
    sealed: &SealedManifest,
    manifest_key: &[u8; 32],
    transfer_id: &[u8; 32],
    primary_object_id: &[u8; 32],
    sender_device_id: &[u8; 32],
    recipient_scope: &RecipientScope,
) -> Result<PrivateManifest, ManifestError> {
    let aad = manifest_aad(
        transfer_id,
        primary_object_id,
        sender_device_id,
        recipient_scope,
    );
    let cipher =
        XChaCha20Poly1305::new_from_slice(manifest_key).map_err(|_| ManifestError::Crypto)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&sealed.nonce),
                Payload {
                    msg: sealed.ciphertext.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|_| ManifestError::Crypto)?,
    );
    let manifest = PrivateManifest::decode(&plaintext)?;
    // The AAD binds these already. Re-checking just makes the error clear.
    if &manifest.sender_device_id != sender_device_id
        || &manifest.recipient_scope != recipient_scope
    {
        return Err(ManifestError::InvalidValue);
    }
    Ok(manifest)
}

/// Checks the public manifest really commits to this sealed private one, and
/// that the offer's commitment agrees (§12.6).
pub fn verify_commitment(
    public: &PublicManifest,
    sealed: &SealedManifest,
    expected_commitment: &[u8; 32],
) -> Result<(), ManifestError> {
    if !crypto::ct_eq(
        &public.private_manifest_ciphertext_hash,
        &sealed.ciphertext_hash(),
    ) {
        return Err(ManifestError::CommitmentMismatch);
    }
    if !crypto::ct_eq(&public.commitment(), expected_commitment) {
        return Err(ManifestError::CommitmentMismatch);
    }
    Ok(())
}
