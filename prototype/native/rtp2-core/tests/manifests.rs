// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//! Manifest conformance and adversarial tests (§12.6, §13).

use rtp2_core::manifest::*;
use rtp2_core::object::AEAD_TAG_LEN;

const TRANSFER_ID: [u8; 32] = [0x11; 32];
const PRIMARY_ID: [u8; 32] = [0x22; 32];
const SENDER_DEVICE: [u8; 32] = [0x33; 32];
const RECIPIENT_DEVICE: [u8; 32] = [0x44; 32];
const CHUNK_PLAIN: u64 = 256 * 1024;
const CHUNK_CIPHER: u64 = CHUNK_PLAIN + AEAD_TAG_LEN as u64;

fn sample_object(role: u8, object_id: [u8; 32], chunks: u64) -> ObjectPublic {
    ObjectPublic {
        object_id,
        object_role: role,
        ciphertext_root: [0xab; 32],
        ciphertext_size: chunks * CHUNK_CIPHER,
        chunk_ciphertext_size: CHUNK_CIPHER,
        chunk_count: chunks,
        padding_policy: PADDING_NONE,
    }
}

fn sample_public(private_hash: [u8; 32]) -> PublicManifest {
    PublicManifest {
        protocol_minor: 0,
        suite_id: 1,
        transfer_id: TRANSFER_ID,
        created_at: 1_000,
        expires_at: 2_000,
        route_profile: ROUTE_BALANCED,
        objects: vec![sample_object(ROLE_PRIMARY, PRIMARY_ID, 3)],
        private_manifest_ciphertext_hash: private_hash,
        capability_scheme: CAPABILITY_SCHEME,
    }
}

fn sample_private() -> PrivateManifest {
    PrivateManifest {
        sender_account_id: [0x55; 32],
        sender_device_id: SENDER_DEVICE,
        recipient_scope: RecipientScope::device(&RECIPIENT_DEVICE),
        display_name: "Quarterly report".into(),
        original_filename: "q3-report.pdf".into(),
        mime_type: "application/pdf".into(),
        logical_plaintext_size: 700_000,
        plaintext_digest: [0x66; 32],
        created_at: 1_000,
        user_caption: Some("as discussed".into()),
        objects: vec![ObjectPrivate {
            object_id: PRIMARY_ID,
            object_role: ROLE_PRIMARY,
            relationship_to_primary: 0,
        }],
        key_policy: KeyPolicy {
            mode: 0,
            minimum_security_level: 1,
            pqc_required: true,
        },
        retention_policy: RetentionPolicy {
            expires_at: 2_000,
            view_once: false,
            allow_local_save: true,
        },
    }
}

// ---------------------------------------------------------------------------
// Encoding round-trips and determinism
// ---------------------------------------------------------------------------

#[test]
fn public_manifest_roundtrip_is_deterministic() {
    let m = sample_public([0x77; 32]);
    let a = m.encode();
    let b = m.encode();
    assert_eq!(a, b, "encoding must be deterministic (§13.4)");

    let decoded = PublicManifest::decode(&a).unwrap();
    assert_eq!(decoded, m);
    assert_eq!(decoded.encode(), a, "decode∘encode must be the identity");
}

#[test]
fn private_manifest_roundtrip_with_and_without_caption() {
    for caption in [Some("hello".to_string()), None] {
        let mut m = sample_private();
        m.user_caption = caption.clone();
        let bytes = m.encode().unwrap();
        let decoded = PrivateManifest::decode(&bytes).unwrap();
        assert_eq!(decoded, m);
        assert_eq!(decoded.encode().unwrap(), bytes);
    }
}

#[test]
fn public_manifest_carries_no_plaintext_metadata() {
    // The encoded public manifest must not contain the filename, MIME type,
    // caption or plaintext digest that live in the private one.
    let private = sample_private();
    let public = sample_public([0x77; 32]);
    let encoded = public.encode();

    for forbidden in [
        private.original_filename.as_bytes(),
        private.mime_type.as_bytes(),
        private.display_name.as_bytes(),
        private.user_caption.as_ref().unwrap().as_bytes(),
        &private.plaintext_digest,
    ] {
        assert!(
            !encoded.windows(forbidden.len()).any(|w| w == forbidden),
            "public manifest leaks {:?}",
            String::from_utf8_lossy(forbidden)
        );
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

#[test]
fn public_manifest_rejects_invalid_shapes() {
    // No objects.
    let mut m = sample_public([0; 32]);
    m.objects.clear();
    assert!(m.validate().is_err());

    // Two primaries.
    let mut m = sample_public([0; 32]);
    m.objects.push(sample_object(ROLE_PRIMARY, [0x99; 32], 1));
    assert!(m.validate().is_err());

    // No primary at all.
    let mut m = sample_public([0; 32]);
    m.objects[0].object_role = ROLE_PREVIEW;
    assert!(m.validate().is_err());

    // Duplicate object ids.
    let mut m = sample_public([0; 32]);
    m.objects.push(sample_object(ROLE_PREVIEW, PRIMARY_ID, 1));
    assert!(m.validate().is_err());

    // expires_at <= created_at.
    let mut m = sample_public([0; 32]);
    m.expires_at = m.created_at;
    assert!(m.validate().is_err());

    // Chunk size outside §10.2.
    let mut m = sample_public([0; 32]);
    m.objects[0].chunk_ciphertext_size = 12345;
    assert!(m.validate().is_err());

    // ciphertext_size inconsistent with chunk_count.
    let mut m = sample_public([0; 32]);
    m.objects[0].ciphertext_size = 10 * CHUNK_CIPHER;
    assert!(m.validate().is_err());

    // Unknown capability scheme.
    let mut m = sample_public([0; 32]);
    m.capability_scheme = 2;
    assert!(m.validate().is_err());
}

#[test]
fn private_manifest_refuses_classical_only_policy() {
    // §2.5 / §6.3: this core runs PQC_REQUIRED.
    let mut m = sample_private();
    m.key_policy.pqc_required = false;
    assert!(m.validate().is_err());
    assert!(m.encode().is_err() || PrivateManifest::decode(&m.encode().unwrap()).is_err());

    let mut m = sample_private();
    m.key_policy.minimum_security_level = 0;
    assert!(m.validate().is_err());
}

#[test]
fn decoder_rejects_unknown_critical_fields() {
    use rtp2_core::cbor::{MapWriter, Writer};

    // An extra critical key 11 must be rejected. Only 10 is the noncritical
    // extension map.
    let m = sample_public([0x77; 32]);
    let valid = m.encode();
    assert!(PublicManifest::decode(&valid).is_ok());

    let mut w = Writer::new();
    let mut mw = MapWriter::begin(&mut w, 11);
    mw.uint(0, 2);
    mw.uint(1, 0);
    mw.uint(2, 1);
    mw.bytes(3, &TRANSFER_ID);
    mw.uint(4, 1000);
    mw.uint(5, 2000);
    mw.uint(6, 1);
    {
        let inner = mw.nested(7);
        inner.array(1);
        // Inline a minimal object-public.
        let mut om = MapWriter::begin(inner, 7);
        om.bytes(0, &PRIMARY_ID);
        om.uint(1, 0);
        om.bytes(2, &[0xab; 32]);
        om.uint(3, 3 * CHUNK_CIPHER);
        om.uint(4, CHUNK_CIPHER);
        om.uint(5, 3);
        om.uint(6, 0);
        om.end();
    }
    mw.bytes(8, &[0x77; 32]);
    mw.uint(9, 1);
    mw.uint(11, 999); // unknown critical field
    mw.end();

    assert_eq!(
        PublicManifest::decode(&w.into_bytes()),
        Err(ManifestError::UnknownCriticalField)
    );
}

#[test]
fn decoder_tolerates_noncritical_extensions() {
    use rtp2_core::cbor::{MapWriter, Writer};

    let mut w = Writer::new();
    let mut mw = MapWriter::begin(&mut w, 11);
    mw.uint(0, 2);
    mw.uint(1, 0);
    mw.uint(2, 1);
    mw.bytes(3, &TRANSFER_ID);
    mw.uint(4, 1000);
    mw.uint(5, 2000);
    mw.uint(6, 1);
    {
        let inner = mw.nested(7);
        inner.array(1);
        let mut om = MapWriter::begin(inner, 7);
        om.bytes(0, &PRIMARY_ID);
        om.uint(1, 0);
        om.bytes(2, &[0xab; 32]);
        om.uint(3, 3 * CHUNK_CIPHER);
        om.uint(4, CHUNK_CIPHER);
        om.uint(5, 3);
        om.uint(6, 0);
        om.end();
    }
    mw.bytes(8, &[0x77; 32]);
    mw.uint(9, 1);
    {
        // Key 10 is the noncritical extension map: ignored, but still part
        // of the encoded bytes and so of the commitment.
        let inner = mw.nested(10);
        let mut em = MapWriter::begin(inner, 2);
        em.uint(0, 42);
        em.text(1, "future field");
        em.end();
    }
    mw.end();

    let bytes = w.into_bytes();
    let decoded = PublicManifest::decode(&bytes).expect("noncritical extension must be tolerated");
    assert_eq!(decoded.objects.len(), 1);
    // The extension is not re-emitted, so re-encoding differs. The
    // commitment covers the received bytes, so callers have to keep them.
    assert_ne!(decoded.encode(), bytes);
}

#[test]
fn truncated_and_garbage_manifests_fail_cleanly() {
    let m = sample_public([0x77; 32]);
    let bytes = m.encode();
    for cut in (0..bytes.len()).step_by(7) {
        assert!(
            PublicManifest::decode(&bytes[..cut]).is_err(),
            "truncation at {cut} accepted"
        );
    }
    let priv_bytes = sample_private().encode().unwrap();
    for cut in (0..priv_bytes.len()).step_by(7) {
        assert!(PrivateManifest::decode(&priv_bytes[..cut]).is_err());
    }
    for garbage in [vec![], vec![0xff; 10], b"not cbor".to_vec()] {
        assert!(PublicManifest::decode(&garbage).is_err());
        assert!(PrivateManifest::decode(&garbage).is_err());
    }
}

// ---------------------------------------------------------------------------
// Encryption (§13.3)
// ---------------------------------------------------------------------------

#[test]
fn sealed_manifest_roundtrip() {
    let key = [0x88u8; 32];
    let private = sample_private();
    let sealed = seal_private_manifest(&private, &key, &TRANSFER_ID, &PRIMARY_ID).unwrap();

    let opened = open_private_manifest(
        &sealed,
        &key,
        &TRANSFER_ID,
        &PRIMARY_ID,
        &SENDER_DEVICE,
        &RecipientScope::device(&RECIPIENT_DEVICE),
    )
    .unwrap();
    assert_eq!(opened, private);
}

#[test]
fn sealed_manifest_is_bound_to_every_aad_component() {
    let key = [0x88u8; 32];
    let private = sample_private();
    let sealed = seal_private_manifest(&private, &key, &TRANSFER_ID, &PRIMARY_ID).unwrap();
    let scope = RecipientScope::device(&RECIPIENT_DEVICE);

    // Wrong key.
    assert!(
        open_private_manifest(
            &sealed,
            &[0x99; 32],
            &TRANSFER_ID,
            &PRIMARY_ID,
            &SENDER_DEVICE,
            &scope
        )
        .is_err()
    );
    // Wrong transfer id.
    assert!(
        open_private_manifest(
            &sealed,
            &key,
            &[0x00; 32],
            &PRIMARY_ID,
            &SENDER_DEVICE,
            &scope
        )
        .is_err()
    );
    // Wrong primary object id.
    assert!(
        open_private_manifest(
            &sealed,
            &key,
            &TRANSFER_ID,
            &[0x00; 32],
            &SENDER_DEVICE,
            &scope
        )
        .is_err()
    );
    // Wrong sender device.
    assert!(
        open_private_manifest(
            &sealed,
            &key,
            &TRANSFER_ID,
            &PRIMARY_ID,
            &[0x00; 32],
            &scope
        )
        .is_err()
    );
    // Wrong recipient scope.
    let other_scope = RecipientScope::device(&[0x00; 32]);
    assert!(
        open_private_manifest(
            &sealed,
            &key,
            &TRANSFER_ID,
            &PRIMARY_ID,
            &SENDER_DEVICE,
            &other_scope
        )
        .is_err()
    );
    // A different scope type with the same identifier must not collide.
    let group_scope = RecipientScope {
        scope_type: RecipientScope::TYPE_GROUP,
        id: RECIPIENT_DEVICE.to_vec(),
    };
    assert_ne!(scope.hash(), group_scope.hash());
    assert!(
        open_private_manifest(
            &sealed,
            &key,
            &TRANSFER_ID,
            &PRIMARY_ID,
            &SENDER_DEVICE,
            &group_scope
        )
        .is_err()
    );
}

#[test]
fn tampered_sealed_manifest_fails() {
    let key = [0x88u8; 32];
    let private = sample_private();
    let sealed = seal_private_manifest(&private, &key, &TRANSFER_ID, &PRIMARY_ID).unwrap();
    let scope = RecipientScope::device(&RECIPIENT_DEVICE);

    for pos in [0usize, 1, 17, sealed.ciphertext.len() - 1] {
        let mut bad = SealedManifest {
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext.clone(),
        };
        bad.ciphertext[pos] ^= 1;
        assert!(
            open_private_manifest(
                &bad,
                &key,
                &TRANSFER_ID,
                &PRIMARY_ID,
                &SENDER_DEVICE,
                &scope
            )
            .is_err(),
            "ciphertext byte {pos} flip accepted"
        );
    }
    // Nonce substitution.
    let mut bad = SealedManifest {
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext.clone(),
    };
    bad.nonce[0] ^= 1;
    assert!(
        open_private_manifest(
            &bad,
            &key,
            &TRANSFER_ID,
            &PRIMARY_ID,
            &SENDER_DEVICE,
            &scope
        )
        .is_err()
    );
}

#[test]
fn sealed_manifest_hash_covers_the_nonce() {
    // The hash has to cover the nonce as well as the ciphertext. Otherwise a
    // swapped nonce leaves the commitment intact and shows up only as an AEAD
    // error, indistinguishable from ordinary corruption.
    let key = [0x88u8; 32];
    let sealed = seal_private_manifest(&sample_private(), &key, &TRANSFER_ID, &PRIMARY_ID).unwrap();

    let mut nonce_swapped = SealedManifest {
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext.clone(),
    };
    nonce_swapped.nonce[0] ^= 1;
    assert_ne!(
        sealed.ciphertext_hash(),
        nonce_swapped.ciphertext_hash(),
        "ciphertext_hash ignores the nonce"
    );

    // And the commitment therefore rejects the swap.
    let public = sample_public(sealed.ciphertext_hash());
    let commitment = public.commitment();
    assert_eq!(
        verify_commitment(&public, &nonce_swapped, &commitment),
        Err(ManifestError::CommitmentMismatch)
    );
}

#[test]
fn sealing_uses_a_fresh_nonce_each_time() {
    let key = [0x88u8; 32];
    let private = sample_private();
    let a = seal_private_manifest(&private, &key, &TRANSFER_ID, &PRIMARY_ID).unwrap();
    let b = seal_private_manifest(&private, &key, &TRANSFER_ID, &PRIMARY_ID).unwrap();
    assert_ne!(a.nonce, b.nonce, "§13.3 requires a fresh random nonce");
    assert_ne!(a.ciphertext, b.ciphertext);
}

// ---------------------------------------------------------------------------
// Commitment (§12.6)
// ---------------------------------------------------------------------------

#[test]
fn commitment_binds_public_manifest_and_private_ciphertext() {
    let key = [0x88u8; 32];
    let private = sample_private();
    let sealed = seal_private_manifest(&private, &key, &TRANSFER_ID, &PRIMARY_ID).unwrap();
    let public = sample_public(sealed.ciphertext_hash());
    let commitment = public.commitment();

    verify_commitment(&public, &sealed, &commitment).unwrap();

    // A different private manifest must break the binding.
    let mut other_private = private.clone();
    other_private.original_filename = "other.pdf".into();
    let other_sealed =
        seal_private_manifest(&other_private, &key, &TRANSFER_ID, &PRIMARY_ID).unwrap();
    assert_eq!(
        verify_commitment(&public, &other_sealed, &commitment),
        Err(ManifestError::CommitmentMismatch)
    );

    // Any change to the public manifest changes the commitment.
    let mut mutated = public.clone();
    mutated.route_profile = ROUTE_PRIVATE_RELAY;
    assert_ne!(mutated.commitment(), commitment);
    assert_eq!(
        verify_commitment(&mutated, &sealed, &commitment),
        Err(ManifestError::CommitmentMismatch)
    );

    // A changed ciphertext root (substituted content) changes it too.
    let mut mutated = public.clone();
    mutated.objects[0].ciphertext_root[0] ^= 1;
    assert_ne!(mutated.commitment(), commitment);
}

#[test]
fn commitment_matches_spec_formula() {
    // §12.6: manifest_commitment = BLAKE3("RTP2-MANIFEST-COMMITMENT-v1\0"
    //   || RTP-CBOR(PublicManifest) || private_manifest_ciphertext_hash)
    let private_hash = [0x77u8; 32];
    let public = sample_public(private_hash);

    let mut h = blake3::Hasher::new();
    h.update(b"RTP2-MANIFEST-COMMITMENT-v1\0");
    h.update(&public.encode());
    h.update(&private_hash);
    assert_eq!(public.commitment(), *h.finalize().as_bytes());
}

#[test]
fn manifest_aad_matches_spec_layout() {
    // §13.3 AAD = domain || transfer_id || primary_object_id || suite_id
    //             || sender_device_id || recipient_scope_hash
    let scope = RecipientScope::device(&RECIPIENT_DEVICE);
    let aad = manifest_aad(&TRANSFER_ID, &PRIMARY_ID, &SENDER_DEVICE, &scope);

    let domain = b"RTP2-MANIFEST-AAD-v1";
    assert_eq!(&aad[..domain.len()], domain);
    let mut off = domain.len();
    assert_eq!(&aad[off..off + 32], &TRANSFER_ID);
    off += 32;
    assert_eq!(&aad[off..off + 32], &PRIMARY_ID);
    off += 32;
    assert_eq!(&aad[off..off + 2], &1u16.to_be_bytes());
    off += 2;
    assert_eq!(&aad[off..off + 32], &SENDER_DEVICE);
    off += 32;
    assert_eq!(&aad[off..off + 32], &scope.hash());
    assert_eq!(aad.len(), off + 32);
}
