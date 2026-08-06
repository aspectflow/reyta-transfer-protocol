// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//! Transfer identifiers and file key hierarchy (§9).
//!
//! Everything secret here stays in the core, zeroized on drop, and never
//! crosses the C ABI (§25.1).

use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    cbor::{CborError, MapWriter, Reader, Writer},
    crypto::{self, SUITE_ID},
};

/// §9.4 chunk-nonce context. Must stay unique among all derive_key contexts
/// in the project (INV-26).
const CHUNK_NONCE_CONTEXT: &str = "Reyta RTP2 2026-08-01 chunk nonce v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyError;

impl From<CborError> for KeyError {
    fn from(_: CborError) -> Self {
        KeyError
    }
}

/// Per-file secret material (§9.1). Fresh CSPRNG values for every file.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct FileSecrets {
    pub transfer_id: [u8; 32],
    pub object_id: [u8; 32],
    file_master_key: [u8; 32],
    file_nonce_seed: [u8; 32],
}

impl FileSecrets {
    pub fn generate() -> Self {
        Self {
            transfer_id: crypto::os_random_array(),
            object_id: crypto::os_random_array(),
            file_master_key: crypto::os_random_array(),
            file_nonce_seed: crypto::os_random_array(),
        }
    }

    fn from_parts(
        transfer_id: [u8; 32],
        object_id: [u8; 32],
        file_master_key: [u8; 32],
        file_nonce_seed: [u8; 32],
    ) -> Self {
        Self {
            transfer_id,
            object_id,
            file_master_key,
            file_nonce_seed,
        }
    }

    /// §9.2 file key hierarchy.
    pub fn key_schedule(&self) -> FileKeySchedule {
        let salt = crypto::sha384(&[b"RTP2-FILE-SALT-v1", &self.transfer_id, &self.object_id]);
        let file_prk = crypto::hkdf_extract(&salt, &self.file_master_key);
        let manifest_key: Zeroizing<[u8; 32]> =
            crypto::hkdf_expand(&file_prk, &[b"RTP2 private manifest key v1"]);
        let chunk_key_base: Zeroizing<[u8; 48]> =
            crypto::hkdf_expand(&file_prk, &[b"RTP2 chunk key base v1"]);
        FileKeySchedule {
            transfer_id: self.transfer_id,
            object_id: self.object_id,
            file_nonce_seed: self.file_nonce_seed,
            manifest_key: *manifest_key,
            chunk_key_base: *chunk_key_base,
        }
    }
}

/// Derived per-file schedule (§9.2–§9.4).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct FileKeySchedule {
    pub transfer_id: [u8; 32],
    pub object_id: [u8; 32],
    file_nonce_seed: [u8; 32],
    manifest_key: [u8; 32],
    chunk_key_base: [u8; 48],
}

impl FileKeySchedule {
    /// §9.2 private-manifest key. Goes straight to the manifest sealer.
    pub fn manifest_key(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.manifest_key)
    }

    /// §9.3 chunk key for index `i`.
    pub fn chunk_key(&self, index: u64) -> Zeroizing<[u8; 32]> {
        crypto::hkdf_expand(
            &self.chunk_key_base,
            &[b"RTP2-CHUNK-KEY-v1", &self.object_id, &index.to_be_bytes()],
        )
    }

    /// §9.4 deterministic chunk nonce for index `i`.
    pub fn chunk_nonce(&self, index: u64) -> [u8; 24] {
        let mut material =
            Vec::with_capacity(self.file_nonce_seed.len() + self.transfer_id.len() + 32 + 8);
        material.extend_from_slice(&self.file_nonce_seed);
        material.extend_from_slice(&self.transfer_id);
        material.extend_from_slice(&self.object_id);
        material.extend_from_slice(&index.to_be_bytes());
        let derived = blake3::derive_key(CHUNK_NONCE_CONTEXT, &material);
        material.zeroize();
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&derived[..24]);
        nonce
    }
}

// ---------------------------------------------------------------------------
// Key envelope (§9.5)
// ---------------------------------------------------------------------------

const ENVELOPE_AAD: &[u8] = b"RTP2-ENVELOPE-AAD-v1";

/// §9.5 says the envelope key is "derived from transfer_wrap_key" without
/// naming the derivation, so this pins one:
///   prk = HKDF-Extract-SHA384("RTP2-ENVELOPE-SALT-v1", transfer_wrap_key)
///   key = HKDF-Expand(prk, "RTP2 envelope key v1", 32)
fn envelope_key(transfer_wrap_key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let prk = crypto::hkdf_extract(b"RTP2-ENVELOPE-SALT-v1", transfer_wrap_key);
    crypto::hkdf_expand(&prk, &[b"RTP2 envelope key v1"])
}

pub struct SealedEnvelope {
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

/// Seals the file master key + nonce seed for one recipient device (§9.5).
pub fn seal_envelope(
    secrets: &FileSecrets,
    transfer_wrap_key: &[u8; 32],
    created_at: u64,
    expires_at: u64,
    sender_device_id: &[u8; 32],
    recipient_device_id: &[u8; 32],
) -> Result<SealedEnvelope, KeyError> {
    seal_envelope_with_suite(
        secrets,
        transfer_wrap_key,
        created_at,
        expires_at,
        sender_device_id,
        recipient_device_id,
        SUITE_ID,
    )
}

/// [`seal_envelope`] with an explicit suite id, so a conformance test can
/// build an envelope a receiver must refuse (§6.3).
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn seal_envelope_with_suite(
    secrets: &FileSecrets,
    transfer_wrap_key: &[u8; 32],
    created_at: u64,
    expires_at: u64,
    sender_device_id: &[u8; 32],
    recipient_device_id: &[u8; 32],
    suite_id: u16,
) -> Result<SealedEnvelope, KeyError> {
    let mut w = Writer::new();
    let mut m = MapWriter::begin(&mut w, 9);
    m.bytes(0, &secrets.transfer_id);
    m.bytes(1, &secrets.object_id);
    m.bytes(2, &secrets.file_master_key);
    m.bytes(3, &secrets.file_nonce_seed);
    m.uint(4, suite_id as u64);
    m.uint(5, created_at);
    m.uint(6, expires_at);
    m.bytes(7, sender_device_id);
    m.bytes(8, recipient_device_id);
    m.end();
    let mut plaintext = Zeroizing::new(w.into_bytes());

    let key = envelope_key(transfer_wrap_key);
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| KeyError)?;
    // Fresh 24-byte nonce per envelope (§9.5).
    let nonce: [u8; 24] = crypto::os_random_array();
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_ref(),
                aad: ENVELOPE_AAD,
            },
        )
        .map_err(|_| KeyError)?;
    plaintext.zeroize();
    Ok(SealedEnvelope { nonce, ciphertext })
}

pub struct OpenedEnvelope {
    pub secrets: FileSecrets,
    pub suite_id: u16,
    pub created_at: u64,
    pub expires_at: u64,
    pub sender_device_id: [u8; 32],
    pub recipient_device_id: [u8; 32],
}

/// Opens without checking `expires_at`. Anyone with a clock should use
/// [`open_envelope_at`] instead.
pub fn open_envelope(
    envelope: &SealedEnvelope,
    transfer_wrap_key: &[u8; 32],
) -> Result<OpenedEnvelope, KeyError> {
    let key = envelope_key(transfer_wrap_key);
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| KeyError)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&envelope.nonce),
                Payload {
                    msg: envelope.ciphertext.as_slice(),
                    aad: ENVELOPE_AAD,
                },
            )
            .map_err(|_| KeyError)?,
    );

    let mut r = Reader::new(&plaintext).map_err(|_| KeyError)?;
    let mut m = r.map()?;
    m.expect_key(0)?;
    let transfer_id = m.reader.bytes_exact::<32>()?;
    m.expect_key(1)?;
    let object_id = m.reader.bytes_exact::<32>()?;
    m.expect_key(2)?;
    let file_master_key = m.reader.bytes_exact::<32>()?;
    m.expect_key(3)?;
    let file_nonce_seed = m.reader.bytes_exact::<32>()?;
    m.expect_key(4)?;
    let suite_id = m.reader.uint()?;
    m.expect_key(5)?;
    let created_at = m.reader.uint()?;
    m.expect_key(6)?;
    let expires_at = m.reader.uint()?;
    m.expect_key(7)?;
    let sender_device_id = m.reader.bytes_exact::<32>()?;
    m.expect_key(8)?;
    let recipient_device_id = m.reader.bytes_exact::<32>()?;
    if m.next_key()?.is_some() {
        return Err(KeyError);
    }
    r.finish().map_err(|_| KeyError)?;

    if suite_id != SUITE_ID as u64 {
        return Err(KeyError);
    }

    Ok(OpenedEnvelope {
        secrets: FileSecrets::from_parts(transfer_id, object_id, file_master_key, file_nonce_seed),
        suite_id: suite_id as u16,
        created_at,
        expires_at,
        sender_device_id,
        recipient_device_id,
    })
}

/// Rejects an expired envelope, and one dated too far in the future (§9.5).
pub fn open_envelope_at(
    envelope: &SealedEnvelope,
    transfer_wrap_key: &[u8; 32],
    now: u64,
) -> Result<OpenedEnvelope, KeyError> {
    let opened = open_envelope(envelope, transfer_wrap_key)?;
    if now >= opened.expires_at {
        return Err(KeyError);
    }
    // Same skew window handshake timestamps get (§8.2.11).
    if opened.created_at > now.saturating_add(300) {
        return Err(KeyError);
    }
    Ok(opened)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_keys_and_nonces_are_index_bound() {
        let secrets = FileSecrets::generate();
        let ks = secrets.key_schedule();
        assert_ne!(ks.chunk_key(0).as_ref(), ks.chunk_key(1).as_ref());
        assert_ne!(ks.chunk_nonce(0), ks.chunk_nonce(1));
        // Deterministic per index, so a retransmission matches (§11.3).
        assert_eq!(ks.chunk_nonce(7), ks.chunk_nonce(7));
        assert_eq!(ks.chunk_key(7).as_ref(), ks.chunk_key(7).as_ref());
    }

    #[test]
    fn different_files_never_share_material() {
        let a = FileSecrets::generate().key_schedule();
        let b = FileSecrets::generate().key_schedule();
        assert_ne!(a.chunk_key(0).as_ref(), b.chunk_key(0).as_ref());
        assert_ne!(a.chunk_nonce(0), b.chunk_nonce(0));
    }

    #[test]
    fn envelope_roundtrip_and_tamper() {
        let secrets = FileSecrets::generate();
        let wrap = [7u8; 32];
        let sender = [1u8; 32];
        let recipient = [2u8; 32];
        let sealed = seal_envelope(&secrets, &wrap, 100, 200, &sender, &recipient).unwrap();
        let opened = open_envelope(&sealed, &wrap).unwrap();
        assert_eq!(opened.secrets.transfer_id, secrets.transfer_id);
        assert_eq!(opened.sender_device_id, sender);

        // Wrong wrap key must fail.
        assert!(open_envelope(&sealed, &[8u8; 32]).is_err());

        // Tampered ciphertext must fail.
        let mut bad = SealedEnvelope {
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext.clone(),
        };
        bad.ciphertext[0] ^= 1;
        assert!(open_envelope(&bad, &wrap).is_err());
    }
}
