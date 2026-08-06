// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//! TransferOffer, ticket and capability tests (§14, §15).

use rtp2_core::capability::*;
use rtp2_core::identity::DeviceIdentity;
use rtp2_core::keys::{self, FileSecrets};
use rtp2_core::manifest::{self, PublicManifest, RecipientScope, SealedManifest};
use rtp2_core::object::AEAD_TAG_LEN;
use rtp2_core::offer::{
    AuthMode, KeyEnvelopeEntry, OfferError, ProviderAddress, Ticket, TransferOffer,
    offer_binding_hash, offer_mac_message, offer_signing_hash, offer_signing_hash_spec,
};

const CHUNK_PLAIN: u64 = 256 * 1024;
const CHUNK_CIPHER: u64 = CHUNK_PLAIN + AEAD_TAG_LEN as u64;

struct Fixture {
    sender: DeviceIdentity,
    recipient: DeviceIdentity,
    public: PublicManifest,
    sealed: SealedManifest,
    envelopes: Vec<KeyEnvelopeEntry>,
    scope: RecipientScope,
    secrets: FileSecrets,
    wrap_key: [u8; 32],
}

fn fixture() -> Fixture {
    let sender = DeviceIdentity::generate();
    let recipient = DeviceIdentity::generate();
    let secrets = FileSecrets::generate();
    let schedule = secrets.key_schedule();
    let scope = RecipientScope::device(&recipient.device_id);

    let private = manifest::PrivateManifest {
        sender_account_id: sender.device_id,
        sender_device_id: sender.device_id,
        recipient_scope: scope.clone(),
        display_name: "report.pdf".into(),
        original_filename: "report.pdf".into(),
        mime_type: "application/pdf".into(),
        logical_plaintext_size: 3 * CHUNK_PLAIN,
        plaintext_digest: [0x66; 32],
        created_at: 1_000,
        user_caption: None,
        objects: vec![manifest::ObjectPrivate {
            object_id: secrets.object_id,
            object_role: manifest::ROLE_PRIMARY,
            relationship_to_primary: 0,
        }],
        key_policy: manifest::KeyPolicy {
            mode: 0,
            minimum_security_level: 1,
            pqc_required: true,
        },
        retention_policy: manifest::RetentionPolicy {
            expires_at: 2_000,
            view_once: false,
            allow_local_save: true,
        },
    };
    let sealed = manifest::seal_private_manifest(
        &private,
        &schedule.manifest_key(),
        &secrets.transfer_id,
        &secrets.object_id,
    )
    .unwrap();

    let public = PublicManifest {
        protocol_minor: 0,
        suite_id: 1,
        transfer_id: secrets.transfer_id,
        created_at: 1_000,
        expires_at: 2_000,
        route_profile: manifest::ROUTE_BALANCED,
        objects: vec![manifest::ObjectPublic {
            object_id: secrets.object_id,
            object_role: manifest::ROLE_PRIMARY,
            ciphertext_root: [0xab; 32],
            ciphertext_size: 3 * CHUNK_CIPHER,
            chunk_ciphertext_size: CHUNK_CIPHER,
            chunk_count: 3,
            padding_policy: manifest::PADDING_NONE,
        }],
        private_manifest_ciphertext_hash: sealed.ciphertext_hash(),
        capability_scheme: manifest::CAPABILITY_SCHEME,
    };

    let wrap_key = [0x42u8; 32];
    let env = keys::seal_envelope(
        &secrets,
        &wrap_key,
        1_000,
        2_000,
        &sender.device_id,
        &recipient.device_id,
    )
    .unwrap();
    let envelopes = vec![KeyEnvelopeEntry {
        recipient_device_id: recipient.device_id,
        nonce: env.nonce,
        ciphertext: env.ciphertext,
    }];

    Fixture {
        sender,
        recipient,
        public,
        sealed,
        envelopes,
        scope,
        secrets,
        wrap_key,
    }
}

fn make_offer(f: &Fixture) -> TransferOffer {
    TransferOffer::create(
        &f.sender,
        &f.public,
        f.sealed.clone(),
        f.envelopes.clone(),
        vec![ProviderAddress {
            kind: ProviderAddress::KIND_SENDER_DEVICE,
            address: b"endpoint-blob".to_vec(),
        }],
        f.scope.clone(),
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// Offer round-trip and authentication (§14.1, §14.2)
// ---------------------------------------------------------------------------

#[test]
fn offer_roundtrip_and_verify() {
    let f = fixture();
    let offer = make_offer(&f);
    let bytes = offer.encode();
    let decoded = TransferOffer::decode(&bytes).unwrap();

    let public = decoded.verify(&f.scope, 1_500).unwrap();
    assert_eq!(public.transfer_id, f.secrets.transfer_id);
    assert_eq!(decoded.sender_device.device_id, f.sender.device_id);

    // The envelope addressed to the recipient opens with the session wrap key.
    let entry = decoded.envelope_for(&f.recipient.device_id).unwrap();
    let opened = keys::open_envelope(
        &keys::SealedEnvelope {
            nonce: entry.nonce,
            ciphertext: entry.ciphertext.clone(),
        },
        &f.wrap_key,
    )
    .unwrap();
    assert_eq!(opened.secrets.transfer_id, f.secrets.transfer_id);

    // No envelope for an unrelated device.
    assert!(decoded.envelope_for(&[0x00; 32]).is_none());
}

#[test]
fn offer_signature_is_bound_to_commitment_and_scope() {
    let f = fixture();
    let offer = make_offer(&f);

    // The signature covers the scope hash, and verify() refuses an offer
    // addressed to someone else.
    let other_scope = RecipientScope::device(&[0x00; 32]);
    assert_eq!(
        offer.verify(&other_scope, 1_500).err(),
        Some(OfferError::ScopeMismatch)
    );

    // Splice in another offer's manifest: the commitment changes and the
    // signature stops matching.
    let f2 = fixture();
    let mut spliced = offer.clone();
    spliced.public_manifest_bytes = f2.public.encode();
    let err = spliced.verify(&f.scope, 1_500).unwrap_err();
    assert!(
        matches!(
            err,
            OfferError::CommitmentMismatch | OfferError::InvalidSignature | OfferError::Encoding
        ),
        "spliced manifest gave {err:?}"
    );

    // Substituted private manifest ciphertext: commitment binding breaks.
    let mut spliced = offer.clone();
    spliced.sealed_manifest = f2.sealed.clone();
    assert_eq!(
        spliced.verify(&f.scope, 1_500).err(),
        Some(OfferError::CommitmentMismatch)
    );
}

#[test]
fn offer_from_another_device_does_not_verify_as_sender() {
    // Re-signed with the attacker's keys, the offer verifies as the
    // attacker's device, never as the real sender.
    let f = fixture();
    let mallory = DeviceIdentity::generate();
    let forged = TransferOffer::create(
        &mallory,
        &f.public,
        f.sealed.clone(),
        f.envelopes.clone(),
        vec![],
        f.scope.clone(),
    )
    .unwrap();

    forged.verify(&f.scope, 1_500).unwrap();
    assert_eq!(forged.sender_device.device_id, mallory.device_id);
    assert_ne!(forged.sender_device.device_id, f.sender.device_id);
}

#[test]
fn tampered_offer_bytes_are_rejected() {
    let f = fixture();
    let offer = make_offer(&f);
    let bytes = offer.encode();

    let stride = (bytes.len() / 120).max(1);
    let mut checked = 0;
    for pos in (0..bytes.len()).step_by(stride) {
        let mut bad = bytes.clone();
        bad[pos] ^= 0x01;
        match TransferOffer::decode(&bad) {
            Err(_) => {}
            Ok(decoded) => {
                assert!(
                    decoded.verify(&f.scope, 1_500).is_err(),
                    "offer byte {pos} flip accepted"
                );
            }
        }
        checked += 1;
    }
    assert!(checked > 50, "sweep covered too few positions");
}

#[test]
fn bound_session_mode_is_refused_not_guessed() {
    // Bound Session needs a key no schedule derives, so the core refuses
    // rather than invent one.
    let f = fixture();
    let mut offer = make_offer(&f);
    offer.auth_mode = AuthMode::BoundSessionMac;

    // Refused before any signature work: the mode check runs first.
    assert_eq!(
        offer.verify(&f.scope, 1_500).err(),
        Some(OfferError::UnsupportedAuthMode)
    );

    // The same holds after a wire round trip.
    let decoded = TransferOffer::decode(&offer.encode()).unwrap();
    assert_eq!(decoded.auth_mode, AuthMode::BoundSessionMac);
    assert_eq!(
        decoded.verify(&f.scope, 1_500).err(),
        Some(OfferError::UnsupportedAuthMode)
    );
}

#[test]
fn expired_offer_is_refused() {
    let f = fixture();
    let offer = make_offer(&f);
    assert!(offer.verify(&f.scope, 1_999).is_ok());
    assert_eq!(
        offer.verify(&f.scope, 2_000).err(),
        Some(OfferError::Expired)
    );
    assert_eq!(
        offer.verify(&f.scope, 9_999).err(),
        Some(OfferError::Expired)
    );
}

#[test]
fn offer_signing_hash_matches_spec_formula() {
    // §14.2 as written: SHA384("RTP2-OFFER-SIGN-v1" || manifest_commitment
    //                          || recipient_scope)
    let f = fixture();
    let offer = make_offer(&f);
    let commitment = offer.manifest_commitment().unwrap();

    let spec_hash =
        rtp2_core::crypto::sha384(&[b"RTP2-OFFER-SIGN-v1", &commitment, &f.scope.hash()]);
    assert_eq!(offer_signing_hash_spec(&commitment, &f.scope), spec_hash);

    // This core signs that preimage plus the binding hash over what §14.2
    // leaves unauthenticated.
    let binding = offer_binding_hash(
        &offer.key_envelopes,
        &offer.providers,
        &offer.sender_device,
        offer.auth_mode,
    );
    let signed = rtp2_core::crypto::sha384(&[
        b"RTP2-OFFER-SIGN-v1",
        &commitment,
        &f.scope.hash(),
        &binding,
    ]);
    assert_eq!(offer_signing_hash(&commitment, &f.scope, &binding), signed);
    assert_ne!(signed, spec_hash, "the strengthening must be observable");

    // Different domains for signing and MAC (§14.2).
    let mac_message = offer_mac_message(&commitment, &f.scope);
    assert!(mac_message.starts_with(b"RTP2-OFFER-MAC-v1"));
    assert_ne!(&mac_message[..17], b"RTP2-OFFER-SIGN-v");
}

#[test]
fn provider_list_is_authenticated() {
    // The attack §14.2 leaves open: point providers[] at the attacker's own
    // infrastructure.
    let f = fixture();
    let offer = make_offer(&f);
    assert!(offer.verify(&f.scope, 1_500).is_ok());

    let mut rerouted = offer.clone();
    rerouted.providers = vec![ProviderAddress {
        kind: ProviderAddress::KIND_RELAY,
        address: b"attacker-relay".to_vec(),
    }];
    assert_eq!(
        rerouted.verify(&f.scope, 1_500).err(),
        Some(OfferError::InvalidSignature)
    );

    // Adding a provider is equally forbidden.
    let mut appended = offer.clone();
    appended.providers.push(ProviderAddress {
        kind: ProviderAddress::KIND_VAULT,
        address: b"attacker-vault".to_vec(),
    });
    assert_eq!(
        appended.verify(&f.scope, 1_500).err(),
        Some(OfferError::InvalidSignature)
    );

    // So is dropping every provider.
    let mut emptied = offer.clone();
    emptied.providers.clear();
    assert_eq!(
        emptied.verify(&f.scope, 1_500).err(),
        Some(OfferError::InvalidSignature)
    );
}

#[test]
fn key_envelope_list_is_authenticated() {
    let f = fixture();
    let offer = make_offer(&f);

    // Corrupt the envelope ciphertext.
    let mut corrupted = offer.clone();
    corrupted.key_envelopes[0].ciphertext[0] ^= 1;
    assert_eq!(
        corrupted.verify(&f.scope, 1_500).err(),
        Some(OfferError::InvalidSignature)
    );

    // Re-address the envelope to another device.
    let mut readdressed = offer.clone();
    readdressed.key_envelopes[0].recipient_device_id = [0x00; 32];
    assert_eq!(
        readdressed.verify(&f.scope, 1_500).err(),
        Some(OfferError::InvalidSignature)
    );

    // Add an envelope for an unauthorized device.
    let mut extra = offer.clone();
    extra.key_envelopes.push(KeyEnvelopeEntry {
        recipient_device_id: [0x99; 32],
        nonce: [0; 24],
        ciphertext: vec![0; 32],
    });
    assert_eq!(
        extra.verify(&f.scope, 1_500).err(),
        Some(OfferError::InvalidSignature)
    );
}

#[test]
fn offer_without_envelopes_is_refused() {
    let f = fixture();
    assert_eq!(
        TransferOffer::create(
            &f.sender,
            &f.public,
            f.sealed.clone(),
            vec![],
            vec![],
            f.scope.clone()
        )
        .err(),
        Some(OfferError::NoEnvelope)
    );
}

// ---------------------------------------------------------------------------
// Ticket (§14.3)
// ---------------------------------------------------------------------------

#[test]
fn ticket_never_carries_key_material() {
    // A ticket carries no file or manifest key. The struct has no field for
    // one; this checks the encoded bytes too.
    let f = fixture();
    let schedule = f.secrets.key_schedule();
    let manifest_key = schedule.manifest_key();

    let body = CapabilityBody::new(
        [0x77; 32],
        f.secrets.transfer_id,
        vec![f.secrets.object_id],
        OP_DOWNLOAD,
        1_000,
        2_000,
    )
    .unwrap();
    let token = CapabilityToken::mint(&body, b"provider-key");

    let ticket = Ticket {
        ticket_version: 1,
        transfer_id: f.secrets.transfer_id,
        manifest_commitment: f.public.commitment(),
        provider_addresses: vec![ProviderAddress {
            kind: ProviderAddress::KIND_RELAY,
            address: b"relay".to_vec(),
        }],
        capability_token: token.encode(),
        expires_at: 2_000,
        route_profile: manifest::ROUTE_PRIVATE_RELAY,
    };

    let uri = ticket.to_uri();
    let bytes = ticket.encode();
    let uri_bytes = uri.as_bytes();

    let contains = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
    let secret = manifest_key.as_slice();
    assert!(!contains(&bytes, secret), "ticket bytes leak a key");
    assert!(!contains(uri_bytes, secret), "ticket URI leaks a key");
    // The seed and master key never leave the core, but the ticket must not
    // carry the sealed envelope either.
    assert!(!contains(&bytes, &f.envelopes[0].ciphertext));

    assert_eq!(Ticket::from_uri(&uri).unwrap(), ticket);
}

#[test]
fn ticket_rejects_malformed_and_oversized_input() {
    assert!(Ticket::from_uri("rtp2:").is_err());
    assert!(Ticket::from_uri("rtp2:AAAA").is_err());
    assert!(Ticket::from_uri(&format!("rtp2:{}", "A".repeat(20_000))).is_err());
    assert!(Ticket::from_uri("nottp2:AAAA").is_err());

    // A ticket with no providers is useless and must not decode.
    let mut w = rtp2_core::cbor::Writer::new();
    {
        let mut m = rtp2_core::cbor::MapWriter::begin(&mut w, 7);
        m.uint(0, 1);
        m.bytes(1, &[1; 32]);
        m.bytes(2, &[2; 32]);
        {
            let inner = m.nested(3);
            inner.array(0);
        }
        m.bytes(4, &[]);
        m.uint(5, 100);
        m.uint(6, 0);
        m.end();
    }
    assert!(Ticket::decode(&w.into_bytes()).is_err());
}

// ---------------------------------------------------------------------------
// Capability + ticket together
// ---------------------------------------------------------------------------

#[test]
fn ticket_capability_authorizes_only_its_own_transfer() {
    let f = fixture();
    let other = fixture();
    let provider_key = b"provider-capability-key";
    let provider_id = [0x77u8; 32];

    let body = CapabilityBody::new(
        provider_id,
        f.secrets.transfer_id,
        vec![f.secrets.object_id],
        OP_DOWNLOAD,
        1_000,
        2_000,
    )
    .unwrap();
    let token = CapabilityToken::mint(&body, provider_key);
    let ticket = Ticket {
        ticket_version: 1,
        transfer_id: f.secrets.transfer_id,
        manifest_commitment: f.public.commitment(),
        provider_addresses: vec![ProviderAddress {
            kind: ProviderAddress::KIND_RELAY,
            address: b"relay".to_vec(),
        }],
        capability_token: token.encode(),
        expires_at: 2_000,
        route_profile: manifest::ROUTE_PRIVATE_RELAY,
    };

    // Provider side: parse the ticket, verify the capability it carries.
    let parsed = Ticket::from_uri(&ticket.to_uri()).unwrap();
    parsed.check_fresh(1_500).unwrap();
    let parsed_token = CapabilityToken::decode(&parsed.capability_token).unwrap();

    assert!(
        authorize(
            &parsed_token,
            provider_key,
            &provider_id,
            &f.secrets.transfer_id,
            &f.secrets.object_id,
            OP_READ_CHUNKS,
            1_500
        )
        .is_ok()
    );

    // The same token must not unlock a different transfer or object.
    assert_eq!(
        authorize(
            &parsed_token,
            provider_key,
            &provider_id,
            &other.secrets.transfer_id,
            &f.secrets.object_id,
            OP_READ_CHUNKS,
            1_500
        )
        .err(),
        Some(CapabilityError::WrongTransfer)
    );
    assert_eq!(
        authorize(
            &parsed_token,
            provider_key,
            &provider_id,
            &f.secrets.transfer_id,
            &other.secrets.object_id,
            OP_READ_CHUNKS,
            1_500
        )
        .err(),
        Some(CapabilityError::WrongObject)
    );
    // A download capability must not permit deletion or upload.
    for op in [OP_DELETE_OBJECT, OP_UPLOAD_CHUNKS] {
        assert_eq!(
            authorize(
                &parsed_token,
                provider_key,
                &provider_id,
                &f.secrets.transfer_id,
                &f.secrets.object_id,
                op,
                1_500
            )
            .err(),
            Some(CapabilityError::OperationNotPermitted)
        );
    }
}

#[test]
fn capability_token_survives_no_bit_flip() {
    let provider_key = b"provider-capability-key";
    let body = CapabilityBody::new([1; 32], [2; 32], vec![[3; 32]], OP_DOWNLOAD, 0, 100).unwrap();
    let encoded = CapabilityToken::mint(&body, provider_key).encode();

    for pos in 0..encoded.len() {
        let mut bad = encoded.clone();
        bad[pos] ^= 0x01;
        let accepted = CapabilityToken::decode(&bad)
            .ok()
            .and_then(|t| t.verify(provider_key).ok())
            .is_some();
        assert!(!accepted, "capability byte {pos} flip was accepted");
    }
}

#[test]
fn capability_tag_is_domain_separated_from_finished_macs() {
    // A different key in a different role. The tag domain has to make
    // cross-protocol MAC reuse impossible even if an operator reused key
    // material.
    let key = b"same-key-in-two-roles";
    let body = CapabilityBody::new([1; 32], [2; 32], vec![[3; 32]], OP_DOWNLOAD, 0, 100).unwrap();
    let body_bytes = body.encode();
    let token = CapabilityToken::mint(&body, key);

    // A raw HMAC over the body without the domain must not match the tag.
    let naive = rtp2_core::crypto::hmac_sha384(key, &body_bytes);
    let encoded = token.encode();
    assert!(
        !encoded.windows(48).any(|w| w == naive),
        "tag equals an undomained HMAC over the body"
    );
}
