// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//! TransferOffer and ticket (§14).
//!
//! The offer says "this device is offering exactly this content to exactly
//! this recipient scope": everything a recipient needs to decide, and nothing
//! a relay may read.
//!
//! Three open points, decided here:
//!
//! 1. Bound Session auth needs `offer_auth_key`, which no key schedule
//!    derives. The mode is defined for wire completeness and refused rather
//!    than guessed at.
//! 2. §14.2 hashes `manifest_commitment || recipient_scope` without saying how
//!    the scope is serialized. We reuse the 32-byte scope hash from the §13.3
//!    AAD, so a scope cannot mean two things.
//! 3. The offer carries the device public bundle this core authenticates
//!    against; account-chained certificates live elsewhere.
//!
//! # Offer binding
//!
//! Draft 0.1 signed only the commitment and scope, leaving the envelopes and
//! provider list unauthenticated: rewrite `providers[]` and the signature
//! still verified. §14.2 now requires `offer_binding` over those fields.
//! [`offer_signing_hash_spec`] keeps the old preimage so a test can show the
//! two differ.

use crate::{
    cbor::{CborError, MapWriter, Reader, Writer},
    crypto::{self, SUITE_ID},
    identity::{DeviceIdentity, DevicePublic, HybridSignature},
    manifest::{self, PublicManifest, RecipientScope, SealedManifest},
};

/// §14.2 domains.
const OFFER_SIGN_DOMAIN: &[u8] = b"RTP2-OFFER-SIGN-v1";
const OFFER_MAC_DOMAIN: &[u8] = b"RTP2-OFFER-MAC-v1";
/// Domain for the binding hash added over §14.2 (see the module docs).
const OFFER_BINDING_DOMAIN: &[u8] = b"RTP2-OFFER-BINDING-v1";
/// §14.3 ticket URI scheme.
pub const TICKET_SCHEME: &str = "rtp2:";
pub const TICKET_VERSION: u64 = 1;

/// Bounded sizes for decoding.
pub const MAX_ENVELOPES: u64 = 64;
pub const MAX_PROVIDERS: u64 = 32;
pub const MAX_PROVIDER_ADDR_LEN: usize = 512;
pub const MAX_TICKET_LEN: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfferError {
    Encoding,
    UnsupportedAuthMode,
    UnsupportedVersion,
    InvalidSignature,
    CommitmentMismatch,
    ScopeMismatch,
    Expired,
    TooManyEnvelopes,
    TooManyProviders,
    ValueTooLong,
    NoEnvelope,
}

impl From<CborError> for OfferError {
    fn from(_: CborError) -> Self {
        OfferError::Encoding
    }
}

impl From<manifest::ManifestError> for OfferError {
    fn from(e: manifest::ManifestError) -> Self {
        match e {
            manifest::ManifestError::CommitmentMismatch => OfferError::CommitmentMismatch,
            _ => OfferError::Encoding,
        }
    }
}

/// §14.1 `auth_mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    BoundSessionMac,
    StandaloneHybridSignature,
}

impl AuthMode {
    fn to_u64(self) -> u64 {
        match self {
            AuthMode::BoundSessionMac => 0,
            AuthMode::StandaloneHybridSignature => 1,
        }
    }

    fn from_u64(v: u64) -> Result<Self, OfferError> {
        match v {
            0 => Ok(AuthMode::BoundSessionMac),
            1 => Ok(AuthMode::StandaloneHybridSignature),
            _ => Err(OfferError::UnsupportedAuthMode),
        }
    }
}

/// One device's copy of the file key (§9.5). The offer carries one per
/// authorized device, and a recipient only tries its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyEnvelopeEntry {
    pub recipient_device_id: [u8; 32],
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

/// `provider-address` from the CDDL: an opaque address plus a kind tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderAddress {
    pub kind: u64,
    pub address: Vec<u8>,
}

impl ProviderAddress {
    /// The sending device itself.
    pub const KIND_SENDER_DEVICE: u64 = 0;
    /// A Reyta private relay.
    pub const KIND_RELAY: u64 = 1;
    /// Encrypted offline vault.
    pub const KIND_VAULT: u64 = 2;
}

/// The Draft 0.1 signing input, kept only so a test can show it is no longer
/// what gets signed.
#[doc(hidden)]
pub fn offer_signing_hash_spec(
    manifest_commitment: &[u8; 32],
    recipient_scope: &RecipientScope,
) -> [u8; 48] {
    crypto::sha384(&[
        OFFER_SIGN_DOMAIN,
        manifest_commitment,
        &recipient_scope.hash(),
    ])
}

/// Binds what §14.2 leaves out: envelopes, providers, sender bundle, auth
/// mode.
pub fn offer_binding_hash(
    key_envelopes: &[KeyEnvelopeEntry],
    providers: &[ProviderAddress],
    sender_device: &DevicePublic,
    auth_mode: AuthMode,
) -> [u8; 32] {
    let mut w = Writer::new();
    let mut m = MapWriter::begin(&mut w, 4);
    {
        let inner = m.nested(0);
        inner.array(key_envelopes.len() as u64);
        for env in key_envelopes {
            let mut em = MapWriter::begin(inner, 3);
            em.bytes(0, &env.recipient_device_id);
            em.bytes(1, &env.nonce);
            em.bytes(2, &env.ciphertext);
            em.end();
        }
    }
    {
        let inner = m.nested(1);
        inner.array(providers.len() as u64);
        for p in providers {
            let mut pm = MapWriter::begin(inner, 2);
            pm.uint(0, p.kind);
            pm.bytes(1, &p.address);
            pm.end();
        }
    }
    {
        let inner = m.nested(2);
        sender_device.encode(inner);
    }
    m.uint(3, auth_mode.to_u64());
    m.end();

    let mut h = blake3::Hasher::new();
    h.update(OFFER_BINDING_DOMAIN);
    h.update(&w.into_bytes());
    *h.finalize().as_bytes()
}

/// What actually gets signed: the §14.2 preimage plus
/// [`offer_binding_hash`], so every field in the offer is authenticated.
pub fn offer_signing_hash(
    manifest_commitment: &[u8; 32],
    recipient_scope: &RecipientScope,
    offer_binding: &[u8; 32],
) -> [u8; 48] {
    crypto::sha384(&[
        OFFER_SIGN_DOMAIN,
        manifest_commitment,
        &recipient_scope.hash(),
        offer_binding,
    ])
}

/// Bound Session MAC input. Here for completeness; the key it needs is
/// undefined.
pub fn offer_mac_message(
    manifest_commitment: &[u8; 32],
    recipient_scope: &RecipientScope,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(OFFER_MAC_DOMAIN.len() + manifest_commitment.len() + 32);
    message.extend_from_slice(OFFER_MAC_DOMAIN);
    message.extend_from_slice(manifest_commitment);
    message.extend_from_slice(&recipient_scope.hash());
    message
}

/// §14.1 TransferOffer.
///
/// Map keys: 0 public_manifest (bstr), 1 manifest_nonce, 2 manifest_ciphertext,
/// 3 key_envelopes, 4 providers, 5 sender_device (DevicePublic),
/// 6 recipient_scope, 7 auth_mode, 8 authentication (hybrid signature).
#[derive(Clone)]
pub struct TransferOffer {
    pub public_manifest_bytes: Vec<u8>,
    pub sealed_manifest: SealedManifest,
    pub key_envelopes: Vec<KeyEnvelopeEntry>,
    pub providers: Vec<ProviderAddress>,
    pub sender_device: DevicePublic,
    pub recipient_scope: RecipientScope,
    pub auth_mode: AuthMode,
    signature: HybridSignature,
}

impl TransferOffer {
    /// Builds and signs an offer in Standalone Mode (§14.2).
    pub fn create(
        identity: &DeviceIdentity,
        public: &PublicManifest,
        sealed_manifest: SealedManifest,
        key_envelopes: Vec<KeyEnvelopeEntry>,
        providers: Vec<ProviderAddress>,
        recipient_scope: RecipientScope,
    ) -> Result<Self, OfferError> {
        public.validate()?;
        if key_envelopes.is_empty() {
            return Err(OfferError::NoEnvelope);
        }
        if key_envelopes.len() as u64 > MAX_ENVELOPES {
            return Err(OfferError::TooManyEnvelopes);
        }
        if providers.len() as u64 > MAX_PROVIDERS {
            return Err(OfferError::TooManyProviders);
        }
        // The offer has to commit to the manifest pair it carries.
        manifest::verify_commitment(public, &sealed_manifest, &public.commitment())?;

        let sender_device = identity.public();
        let auth_mode = AuthMode::StandaloneHybridSignature;
        let binding = offer_binding_hash(&key_envelopes, &providers, &sender_device, auth_mode);
        let hash = offer_signing_hash(&public.commitment(), &recipient_scope, &binding);
        let signature = identity
            .hybrid_sign(&hash)
            .map_err(|_| OfferError::InvalidSignature)?;

        Ok(Self {
            public_manifest_bytes: public.encode(),
            sealed_manifest,
            key_envelopes,
            providers,
            sender_device,
            recipient_scope,
            auth_mode,
            signature,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        let mut m = MapWriter::begin(&mut w, 9);
        m.bytes(0, &self.public_manifest_bytes);
        m.bytes(1, &self.sealed_manifest.nonce);
        m.bytes(2, &self.sealed_manifest.ciphertext);
        {
            let inner = m.nested(3);
            inner.array(self.key_envelopes.len() as u64);
            for env in &self.key_envelopes {
                let mut em = MapWriter::begin(inner, 3);
                em.bytes(0, &env.recipient_device_id);
                em.bytes(1, &env.nonce);
                em.bytes(2, &env.ciphertext);
                em.end();
            }
        }
        {
            let inner = m.nested(4);
            inner.array(self.providers.len() as u64);
            for p in &self.providers {
                let mut pm = MapWriter::begin(inner, 2);
                pm.uint(0, p.kind);
                pm.bytes(1, &p.address);
                pm.end();
            }
        }
        {
            let inner = m.nested(5);
            self.sender_device.encode(inner);
        }
        {
            let inner = m.nested(6);
            encode_scope(inner, &self.recipient_scope);
        }
        m.uint(7, self.auth_mode.to_u64());
        {
            let inner = m.nested(8);
            self.signature.encode(inner);
        }
        m.end();
        w.into_bytes()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, OfferError> {
        let mut r = Reader::new(bytes)?;
        let mut m = r.map()?;
        m.expect_key(0)?;
        let public_manifest_bytes = m.reader.bytes()?.to_vec();
        m.expect_key(1)?;
        let nonce = m.reader.bytes_exact::<24>()?;
        m.expect_key(2)?;
        let ciphertext = m.reader.bytes()?.to_vec();
        m.expect_key(3)?;
        let count = m.reader.array()?;
        if count > MAX_ENVELOPES {
            return Err(OfferError::TooManyEnvelopes);
        }
        let mut key_envelopes = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let mut em = m.reader.map()?;
            em.expect_key(0)?;
            let recipient_device_id = em.reader.bytes_exact::<32>()?;
            em.expect_key(1)?;
            let env_nonce = em.reader.bytes_exact::<24>()?;
            em.expect_key(2)?;
            let env_ct = em.reader.bytes()?.to_vec();
            if em.next_key()?.is_some() {
                return Err(OfferError::Encoding);
            }
            key_envelopes.push(KeyEnvelopeEntry {
                recipient_device_id,
                nonce: env_nonce,
                ciphertext: env_ct,
            });
        }
        m.reader.leave();
        m.expect_key(4)?;
        let count = m.reader.array()?;
        if count > MAX_PROVIDERS {
            return Err(OfferError::TooManyProviders);
        }
        let mut providers = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let mut pm = m.reader.map()?;
            pm.expect_key(0)?;
            let kind = pm.reader.uint()?;
            pm.expect_key(1)?;
            let address = pm.reader.bytes()?.to_vec();
            if pm.next_key()?.is_some() {
                return Err(OfferError::Encoding);
            }
            if address.len() > MAX_PROVIDER_ADDR_LEN {
                return Err(OfferError::ValueTooLong);
            }
            providers.push(ProviderAddress { kind, address });
        }
        m.reader.leave();
        m.expect_key(5)?;
        let sender_device = DevicePublic::decode(m.reader)?;
        m.expect_key(6)?;
        let recipient_scope = decode_scope(m.reader)?;
        m.expect_key(7)?;
        let auth_mode = AuthMode::from_u64(m.reader.uint()?)?;
        m.expect_key(8)?;
        let signature = HybridSignature::decode(m.reader)?;
        if m.next_key()?.is_some() {
            return Err(OfferError::Encoding);
        }
        r.finish()?;

        if key_envelopes.is_empty() {
            return Err(OfferError::NoEnvelope);
        }

        Ok(Self {
            public_manifest_bytes,
            sealed_manifest: SealedManifest { nonce, ciphertext },
            key_envelopes,
            providers,
            sender_device,
            recipient_scope,
            auth_mode,
            signature,
        })
    }

    /// Full recipient-side check (§14.2): the hybrid signature, the
    /// commitment binding the manifests actually delivered, and the scope
    /// naming this device. Returns the validated public manifest.
    pub fn verify(
        &self,
        expected_scope: &RecipientScope,
        now: u64,
    ) -> Result<PublicManifest, OfferError> {
        // Bound Session Mode needs a key the spec never defines. Refuse
        // rather than invent a derivation.
        if self.auth_mode != AuthMode::StandaloneHybridSignature {
            return Err(OfferError::UnsupportedAuthMode);
        }
        if &self.recipient_scope != expected_scope {
            return Err(OfferError::ScopeMismatch);
        }

        let public = PublicManifest::decode(&self.public_manifest_bytes)?;
        if public.suite_id != SUITE_ID {
            return Err(OfferError::UnsupportedVersion);
        }
        let commitment = public.commitment();
        manifest::verify_commitment(&public, &self.sealed_manifest, &commitment)?;

        // The commitment covers the manifests; the binding hash covers the
        // envelopes, providers, sender bundle and auth mode.
        let binding = offer_binding_hash(
            &self.key_envelopes,
            &self.providers,
            &self.sender_device,
            self.auth_mode,
        );
        let hash = offer_signing_hash(&commitment, &self.recipient_scope, &binding);
        self.sender_device
            .hybrid_verify(&hash, &self.signature)
            .map_err(|_| OfferError::InvalidSignature)?;

        // An offer past its manifest's expiry is refused before any transfer
        // work starts.
        if now >= public.expires_at {
            return Err(OfferError::Expired);
        }
        Ok(public)
    }

    /// The envelope addressed to a specific device, if present.
    pub fn envelope_for(&self, device_id: &[u8; 32]) -> Option<&KeyEnvelopeEntry> {
        self.key_envelopes
            .iter()
            .find(|e| crypto::ct_eq(&e.recipient_device_id, device_id))
    }

    pub fn manifest_commitment(&self) -> Result<[u8; 32], OfferError> {
        Ok(PublicManifest::decode(&self.public_manifest_bytes)?.commitment())
    }
}

fn encode_scope(w: &mut Writer, scope: &RecipientScope) {
    let mut m = MapWriter::begin(w, 2);
    m.uint(0, scope.scope_type);
    m.bytes(1, &scope.id);
    m.end();
}

fn decode_scope(r: &mut Reader<'_>) -> Result<RecipientScope, OfferError> {
    let mut m = r.map()?;
    m.expect_key(0)?;
    let scope_type = m.reader.uint()?;
    m.expect_key(1)?;
    let id = m.reader.bytes()?.to_vec();
    if m.next_key()?.is_some() {
        return Err(OfferError::Encoding);
    }
    if id.len() > MAX_PROVIDER_ADDR_LEN {
        return Err(OfferError::ValueTooLong);
    }
    Ok(RecipientScope { scope_type, id })
}

// ---------------------------------------------------------------------------
// Ticket (§14.3)
// ---------------------------------------------------------------------------

/// §14.3 ticket. It cannot carry a file or manifest key: there is no field
/// for one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ticket {
    pub ticket_version: u64,
    pub transfer_id: [u8; 32],
    pub manifest_commitment: [u8; 32],
    pub provider_addresses: Vec<ProviderAddress>,
    pub capability_token: Vec<u8>,
    pub expires_at: u64,
    pub route_profile: u8,
}

impl Ticket {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        let mut m = MapWriter::begin(&mut w, 7);
        m.uint(0, self.ticket_version);
        m.bytes(1, &self.transfer_id);
        m.bytes(2, &self.manifest_commitment);
        {
            let inner = m.nested(3);
            inner.array(self.provider_addresses.len() as u64);
            for p in &self.provider_addresses {
                let mut pm = MapWriter::begin(inner, 2);
                pm.uint(0, p.kind);
                pm.bytes(1, &p.address);
                pm.end();
            }
        }
        m.bytes(4, &self.capability_token);
        m.uint(5, self.expires_at);
        m.uint(6, self.route_profile as u64);
        m.end();
        w.into_bytes()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, OfferError> {
        let mut r = Reader::new(bytes)?;
        let mut m = r.map()?;
        m.expect_key(0)?;
        let ticket_version = m.reader.uint()?;
        if ticket_version != TICKET_VERSION {
            return Err(OfferError::UnsupportedVersion);
        }
        m.expect_key(1)?;
        let transfer_id = m.reader.bytes_exact::<32>()?;
        m.expect_key(2)?;
        let manifest_commitment = m.reader.bytes_exact::<32>()?;
        m.expect_key(3)?;
        let count = m.reader.array()?;
        if count == 0 || count > MAX_PROVIDERS {
            return Err(OfferError::TooManyProviders);
        }
        let mut provider_addresses = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let mut pm = m.reader.map()?;
            pm.expect_key(0)?;
            let kind = pm.reader.uint()?;
            pm.expect_key(1)?;
            let address = pm.reader.bytes()?.to_vec();
            if pm.next_key()?.is_some() {
                return Err(OfferError::Encoding);
            }
            if address.len() > MAX_PROVIDER_ADDR_LEN {
                return Err(OfferError::ValueTooLong);
            }
            provider_addresses.push(ProviderAddress { kind, address });
        }
        m.reader.leave();
        m.expect_key(4)?;
        let capability_token = m.reader.bytes()?.to_vec();
        m.expect_key(5)?;
        let expires_at = m.reader.uint()?;
        m.expect_key(6)?;
        let route_profile = m.reader.uint()?;
        if route_profile > 3 {
            return Err(OfferError::Encoding);
        }
        if m.next_key()?.is_some() {
            return Err(OfferError::Encoding);
        }
        r.finish()?;

        Ok(Self {
            ticket_version,
            transfer_id,
            manifest_commitment,
            provider_addresses,
            capability_token,
            expires_at,
            route_profile: route_profile as u8,
        })
    }

    /// §14.3: `rtp2:<base64url-no-padding(RTP-CBOR(Ticket))>`
    pub fn to_uri(&self) -> String {
        format!("{TICKET_SCHEME}{}", base64url_encode(&self.encode()))
    }

    pub fn from_uri(uri: &str) -> Result<Self, OfferError> {
        if uri.len() > MAX_TICKET_LEN {
            return Err(OfferError::ValueTooLong);
        }
        let body = uri
            .strip_prefix(TICKET_SCHEME)
            .ok_or(OfferError::Encoding)?;
        let bytes = base64url_decode(body)?;
        Self::decode(&bytes)
    }

    /// A ticket is only usable while it is in date (§14.3).
    pub fn check_fresh(&self, now: u64) -> Result<(), OfferError> {
        if now >= self.expires_at {
            return Err(OfferError::Expired);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// base64url without padding (RFC 4648 §5)
// ---------------------------------------------------------------------------

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn base64url_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(B64_ALPHABET[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(B64_ALPHABET[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(B64_ALPHABET[n as usize & 63] as char);
        }
    }
    out
}

pub fn base64url_decode(text: &str) -> Result<Vec<u8>, OfferError> {
    fn value(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a') as u32 + 26),
            b'0'..=b'9' => Some((c - b'0') as u32 + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }

    let bytes = text.as_bytes();
    // Padding is not permitted, and a 1-character trailing group is
    // impossible in canonical base64.
    if bytes.len() % 4 == 1 {
        return Err(OfferError::Encoding);
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= value(c).ok_or(OfferError::Encoding)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
        // Reject non-canonical encodings: bits beyond the emitted bytes must
        // be zero, otherwise two different strings decode to the same value.
        let unused_bits = match chunk.len() {
            2 => 16,
            3 => 8,
            _ => 0,
        };
        if unused_bits > 0 && (n & ((1 << unused_bits) - 1)) != 0 {
            return Err(OfferError::Encoding);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_rfc4648_vectors() {
        // RFC 4648 §10 vectors, base64url without padding.
        for (input, expected) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64url_encode(input.as_bytes()), expected);
            assert_eq!(base64url_decode(expected).unwrap(), input.as_bytes());
        }
        // URL-safe alphabet: no '+' or '/' ever appears.
        let encoded = base64url_encode(&[0xfb, 0xff, 0xbf]);
        assert!(!encoded.contains('+') && !encoded.contains('/'));
        assert_eq!(base64url_decode(&encoded).unwrap(), vec![0xfb, 0xff, 0xbf]);
    }

    #[test]
    fn base64url_rejects_malformed_input() {
        assert!(
            base64url_decode("Zg==").is_err(),
            "padding must be rejected"
        );
        assert!(base64url_decode("Z").is_err(), "1-char group is impossible");
        assert!(base64url_decode("Zm9v!").is_err(), "invalid character");
        assert!(base64url_decode("Zm+v").is_err(), "standard alphabet");
        // Non-canonical trailing bits: "Zh" decodes the same byte as "Zg"
        // but has a dirty low bit.
        assert_eq!(base64url_decode("Zg").unwrap(), b"f");
        assert!(base64url_decode("Zh").is_err());
    }

    #[test]
    fn ticket_uri_roundtrip() {
        let ticket = Ticket {
            ticket_version: TICKET_VERSION,
            transfer_id: [1; 32],
            manifest_commitment: [2; 32],
            provider_addresses: vec![ProviderAddress {
                kind: ProviderAddress::KIND_RELAY,
                address: b"relay-address".to_vec(),
            }],
            capability_token: vec![9; 64],
            expires_at: 1234,
            route_profile: 1,
        };
        let uri = ticket.to_uri();
        assert!(uri.starts_with("rtp2:"));
        assert_eq!(Ticket::from_uri(&uri).unwrap(), ticket);
        assert!(Ticket::from_uri("https://example.com").is_err());
        assert!(Ticket::from_uri("rtp2:!!!").is_err());
    }

    #[test]
    fn ticket_expiry_is_enforced() {
        let ticket = Ticket {
            ticket_version: TICKET_VERSION,
            transfer_id: [1; 32],
            manifest_commitment: [2; 32],
            provider_addresses: vec![ProviderAddress {
                kind: 0,
                address: b"addr".to_vec(),
            }],
            capability_token: vec![],
            expires_at: 100,
            route_profile: 0,
        };
        assert!(ticket.check_fresh(99).is_ok());
        assert_eq!(ticket.check_fresh(100), Err(OfferError::Expired));
        assert_eq!(ticket.check_fresh(101), Err(OfferError::Expired));
    }
}
