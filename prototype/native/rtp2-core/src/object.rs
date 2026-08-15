// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//! Object preparation and chunk encryption (§10, §11).

use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};

use crate::{
    cbor::{MapWriter, Writer},
    crypto::{PROTOCOL_MAJOR, SUITE_ID},
    keys::FileKeySchedule,
};

/// §10.2 allowed plaintext chunk sizes.
pub const ALLOWED_CHUNK_SIZES: [u32; 7] = [
    64 * 1024,
    128 * 1024,
    256 * 1024, // recommended mobile default
    512 * 1024,
    1024 * 1024,
    2 * 1024 * 1024,
    4 * 1024 * 1024,
];

pub const AEAD_TAG_LEN: usize = 16;

/// Ceiling on chunks per object (§10.2). Authenticated is not honest: a peer
/// can sign any size it likes, and the receiver sizes its bitmap and range
/// tables from that number. 2^32 is 256 TiB at the smallest chunk size, well
/// past anything real and far from overflowing.
pub const MAX_CHUNK_COUNT: u64 = 1 << 32;

/// §10.3 padding policies. The prototype pipeline implements NONE.
pub const PADDING_NONE: u8 = 0;

/// Object roles.
pub const ROLE_PRIMARY: u8 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectError;

/// §10.5 ObjectContext. Breaks the circularity between chunk encryption and
/// the final ciphertext root.
#[derive(Clone, PartialEq, Eq)]
pub struct ObjectContext {
    pub transfer_id: [u8; 32],
    pub object_id: [u8; 32],
    pub logical_plaintext_size: u64,
    pub encoded_plaintext_size: u64,
    pub chunk_plaintext_size: u32,
    pub chunk_count: u64,
    pub padding_policy: u8,
    pub object_role: u8,
}

impl ObjectContext {
    pub fn for_file(
        transfer_id: [u8; 32],
        object_id: [u8; 32],
        file_size: u64,
        chunk_size: u32,
    ) -> Result<Self, ObjectError> {
        if !ALLOWED_CHUNK_SIZES.contains(&chunk_size) {
            return Err(ObjectError);
        }
        // Policy NONE: encoded == logical, and the last chunk may be short.
        let chunk_count = if file_size == 0 {
            0
        } else {
            file_size.div_ceil(chunk_size as u64)
        };
        // Refused here, where both sides build a context, rather than at
        // every use of the number.
        if chunk_count > MAX_CHUNK_COUNT {
            return Err(ObjectError);
        }
        Ok(Self {
            transfer_id,
            object_id,
            logical_plaintext_size: file_size,
            encoded_plaintext_size: file_size,
            chunk_plaintext_size: chunk_size,
            chunk_count,
            padding_policy: PADDING_NONE,
            object_role: ROLE_PRIMARY,
        })
    }

    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        let mut m = MapWriter::begin(&mut w, 10);
        m.uint(0, PROTOCOL_MAJOR as u64);
        m.uint(1, SUITE_ID as u64);
        m.bytes(2, &self.transfer_id);
        m.bytes(3, &self.object_id);
        m.uint(4, self.logical_plaintext_size);
        m.uint(5, self.encoded_plaintext_size);
        m.uint(6, self.chunk_plaintext_size as u64);
        m.uint(7, self.chunk_count);
        m.uint(8, self.padding_policy as u64);
        m.uint(9, self.object_role as u64);
        m.end();
        w.into_bytes()
    }

    /// §10.5 object_context_hash.
    pub fn context_hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"RTP2-OBJECT-CONTEXT-v1");
        h.update(&self.encode());
        *h.finalize().as_bytes()
    }

    /// Plaintext length of chunk `index` under padding policy NONE.
    /// Bytes on the wire for one whole chunk: the plaintext plus its AEAD tag.
    ///
    /// This lived as an expression in the sender and, inverted, as another in
    /// the receiver — the two had to agree forever with nothing making them.
    /// A disagreement is a transfer that negotiates a size the peer computes
    /// differently, so the relation belongs where the geometry is defined.
    pub fn chunk_ciphertext_size(&self) -> u64 {
        self.chunk_plaintext_size as u64 + AEAD_TAG_LEN as u64
    }

    /// Bytes on the wire for the whole object. Zero chunks carry nothing, not
    /// even tags.
    pub fn ciphertext_size(&self) -> u64 {
        if self.chunk_count == 0 {
            return 0;
        }
        self.encoded_plaintext_size + self.chunk_count * AEAD_TAG_LEN as u64
    }

    /// Bytes on the wire for the chunk at `index`, which is shorter than the
    /// rest when it is the last one.
    pub fn chunk_ciphertext_len(&self, index: u64) -> Result<usize, ObjectError> {
        Ok(self.chunk_len(index)? as usize + AEAD_TAG_LEN)
    }

    /// The inverse of [`chunk_ciphertext_size`], for a receiver that has been
    /// told a chunk size and has to recover the plaintext size behind it.
    ///
    /// Refuses anything a chunk of that size could not have produced: a value
    /// too small to hold a tag, or a plaintext size beyond `u32`.
    pub fn chunk_plaintext_size_from_ciphertext(ciphertext: u64) -> Result<u32, ObjectError> {
        ciphertext
            .checked_sub(AEAD_TAG_LEN as u64)
            .filter(|v| *v <= u32::MAX as u64)
            .map(|v| v as u32)
            .ok_or(ObjectError)
    }

    pub fn chunk_len(&self, index: u64) -> Result<u32, ObjectError> {
        if index >= self.chunk_count {
            return Err(ObjectError);
        }
        let start = index * self.chunk_plaintext_size as u64;
        let remaining = self.encoded_plaintext_size - start;
        Ok(remaining.min(self.chunk_plaintext_size as u64) as u32)
    }
}

/// §11.1 associated data. Fixed layout, 132 bytes.
pub fn chunk_aad(
    ctx: &ObjectContext,
    object_context_hash: &[u8; 32],
    chunk_index: u64,
    plaintext_offset: u64,
    actual_plaintext_len: u32,
    chunk_flags: u32,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(132);
    aad.extend_from_slice(b"RTP2CHNK");
    aad.extend_from_slice(&PROTOCOL_MAJOR.to_be_bytes());
    aad.extend_from_slice(&SUITE_ID.to_be_bytes());
    aad.extend_from_slice(&ctx.transfer_id);
    aad.extend_from_slice(&ctx.object_id);
    aad.extend_from_slice(object_context_hash);
    aad.extend_from_slice(&chunk_index.to_be_bytes());
    aad.extend_from_slice(&plaintext_offset.to_be_bytes());
    aad.extend_from_slice(&actual_plaintext_len.to_be_bytes());
    aad.extend_from_slice(&chunk_flags.to_be_bytes());
    aad
}

/// §11.2 chunk encryption. Deterministic for an immutable object (§11.3).
pub fn encrypt_chunk(
    schedule: &FileKeySchedule,
    ctx: &ObjectContext,
    object_context_hash: &[u8; 32],
    index: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, ObjectError> {
    let expected = ctx.chunk_len(index)?;
    if plaintext.len() != expected as usize {
        return Err(ObjectError);
    }
    let key = schedule.chunk_key(index);
    let nonce = schedule.chunk_nonce(index);
    let aad = chunk_aad(
        ctx,
        object_context_hash,
        index,
        index * ctx.chunk_plaintext_size as u64,
        expected,
        0,
    );
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| ObjectError)?;
    cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| ObjectError)
}

/// §11.4 steps 4–6: derive key/nonce, verify AEAD, validate decoded length.
pub fn decrypt_chunk(
    schedule: &FileKeySchedule,
    ctx: &ObjectContext,
    object_context_hash: &[u8; 32],
    index: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>, ObjectError> {
    let expected = ctx.chunk_len(index)?;
    if ciphertext.len() != expected as usize + AEAD_TAG_LEN {
        return Err(ObjectError);
    }
    let key = schedule.chunk_key(index);
    let nonce = schedule.chunk_nonce(index);
    let aad = chunk_aad(
        ctx,
        object_context_hash,
        index,
        index * ctx.chunk_plaintext_size as u64,
        expected,
        0,
    );
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| ObjectError)?;
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| ObjectError)?;
    if plaintext.len() != expected as usize {
        return Err(ObjectError);
    }
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sender writes a chunk size into the manifest and the receiver reads
    /// it back out. If the two operations are not inverses, the peers disagree
    /// about the object without either noticing.
    #[test]
    fn a_chunk_size_survives_the_round_trip() {
        for &plaintext in &ALLOWED_CHUNK_SIZES {
            let ctx = ObjectContext::for_file([0; 32], [1; 32], plaintext as u64 * 4, plaintext)
                .expect("an allowed chunk size");
            let on_the_wire = ctx.chunk_ciphertext_size();
            assert_eq!(
                ObjectContext::chunk_plaintext_size_from_ciphertext(on_the_wire),
                Ok(plaintext),
                "{plaintext} did not survive the round trip"
            );
        }
    }

    /// A size that could not have come from a chunk is refused rather than
    /// wrapped around into a plausible one.
    #[test]
    fn an_impossible_chunk_size_is_refused() {
        for bad in [
            0u64,
            1,
            AEAD_TAG_LEN as u64 - 1,
            u32::MAX as u64 + AEAD_TAG_LEN as u64 + 1,
        ] {
            assert_eq!(
                ObjectContext::chunk_plaintext_size_from_ciphertext(bad),
                Err(ObjectError),
                "{bad} should not describe any chunk"
            );
        }
    }

    /// An object with no chunks carries nothing — not even the tags that a
    /// naive multiplication would invent.
    #[test]
    fn an_empty_object_has_no_ciphertext() {
        let ctx = ObjectContext::for_file([0; 32], [1; 32], 0, 256 * 1024).unwrap();
        assert_eq!(ctx.chunk_count, 0);
        assert_eq!(ctx.ciphertext_size(), 0);
    }

    use crate::keys::FileSecrets;

    fn setup(file_size: u64, chunk_size: u32) -> (FileKeySchedule, ObjectContext, [u8; 32]) {
        let secrets = FileSecrets::generate();
        let ctx = ObjectContext::for_file(
            secrets.transfer_id,
            secrets.object_id,
            file_size,
            chunk_size,
        )
        .unwrap();
        let hash = ctx.context_hash();
        (secrets.key_schedule(), ctx, hash)
    }

    #[test]
    fn roundtrip_and_binding() {
        let (ks, ctx, h) = setup(200_000, 64 * 1024);
        assert_eq!(ctx.chunk_count, 4);
        let chunk0 = vec![0xabu8; 64 * 1024];
        let ct = encrypt_chunk(&ks, &ctx, &h, 0, &chunk0).unwrap();
        assert_eq!(decrypt_chunk(&ks, &ctx, &h, 0, &ct).unwrap(), chunk0);

        // A chunk valid at index 0 must not decrypt at index 1 (INV-40). Use
        // a larger file so both positions have equal ciphertext length.
        let (ks2, ctx2, h2) = setup(3 * 64 * 1024, 64 * 1024);
        let ct0 = encrypt_chunk(&ks2, &ctx2, &h2, 0, &chunk0).unwrap();
        assert!(decrypt_chunk(&ks2, &ctx2, &h2, 1, &ct0).is_err());

        // Tampered ciphertext fails.
        let mut bad = ct.clone();
        bad[10] ^= 1;
        assert!(decrypt_chunk(&ks, &ctx, &h, 0, &bad).is_err());

        // Wrong context hash fails (AAD binding).
        let mut wrong_h = h;
        wrong_h[0] ^= 1;
        assert!(decrypt_chunk(&ks, &ctx, &wrong_h, 0, &ct).is_err());
    }

    #[test]
    fn deterministic_retransmission() {
        let (ks, ctx, h) = setup(100_000, 64 * 1024);
        let data = vec![5u8; ctx.chunk_len(0).unwrap() as usize];
        let a = encrypt_chunk(&ks, &ctx, &h, 0, &data).unwrap();
        let b = encrypt_chunk(&ks, &ctx, &h, 0, &data).unwrap();
        assert_eq!(a, b, "§11.3: identical ciphertext on retransmission");
    }

    #[test]
    fn last_chunk_short() {
        let (ks, ctx, h) = setup(100_000, 64 * 1024);
        assert_eq!(ctx.chunk_count, 2);
        let last_len = ctx.chunk_len(1).unwrap() as usize;
        assert_eq!(last_len, 100_000 - 64 * 1024);
        let data = vec![9u8; last_len];
        let ct = encrypt_chunk(&ks, &ctx, &h, 1, &data).unwrap();
        assert_eq!(decrypt_chunk(&ks, &ctx, &h, 1, &ct).unwrap(), data);
        // Wrong-length plaintext rejected.
        assert!(encrypt_chunk(&ks, &ctx, &h, 1, &vec![9u8; last_len + 1]).is_err());
    }

    #[test]
    fn disallowed_chunk_size_rejected() {
        let secrets = FileSecrets::generate();
        // An absurd signed size is refused before anything is sized from it.
        assert!(
            ObjectContext::for_file(secrets.transfer_id, secrets.object_id, u64::MAX, 64 * 1024)
                .is_err(),
            "an object of u64::MAX bytes must be refused"
        );
        assert!(
            ObjectContext::for_file(secrets.transfer_id, secrets.object_id, 1000, 12345).is_err()
        );
    }
}
