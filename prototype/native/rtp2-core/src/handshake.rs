// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//! Standalone Mode hybrid handshake (§8.2).
//!
//! X25519 + ML-KEM-768 ephemeral agreement, SHA-384 transcript, hybrid
//! Ed25519 + ML-DSA-65 device signatures, HKDF-SHA-384 key schedule,
//! HMAC-SHA-384 finished confirmation.
//!
//! Messages are deterministic RTP-CBOR maps. The spec has no CDDL for them
//! yet, so the integer keys documented per message are the wire contract.

use std::collections::{HashSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    cbor::{CborError, MapWriter, Reader, Writer},
    crypto::{self, PROTOCOL_MAJOR, PROTOCOL_MINOR, SUITE_ID},
    identity::{DeviceIdentity, DevicePublic, HybridSignature},
    pqc::{self, MLKEM768_CIPHERTEXT_LEN, MLKEM768_PUBLIC_KEY_LEN, MlKemKeyPair},
};

const TH1_DOMAIN: &[u8] = b"RTP2-HS-TH1-v1";
const TH2_DOMAIN: &[u8] = b"RTP2-HS-TH2-v1";
const SALT_DOMAIN: &[u8] = b"RTP2-HYBRID-SALT-v1";

/// §8.2.11: acceptance window for the ClientHello timestamp, seconds.
const TIMESTAMP_WINDOW_SECS: u64 = 300;
/// Bounded replay-cache size (entries), keyed by initiator identity + nonce.
const REPLAY_CACHE_CAP: usize = 4096;

/// Coarse on purpose: the peer never learns the cryptographic cause (§8.2.4).
/// These variants are for local diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeError {
    Decode,
    UnsupportedVersion,
    UnsupportedSuite,
    PolicyViolation,
    InvalidKey,
    InvalidSignature,
    InvalidMac,
    Replay,
    EndpointMismatch,
    State,
}

impl From<CborError> for HandshakeError {
    fn from(_: CborError) -> Self {
        HandshakeError::Decode
    }
}

impl From<pqc::PqcError> for HandshakeError {
    fn from(_: pqc::PqcError) -> Self {
        HandshakeError::InvalidKey
    }
}

// ---------------------------------------------------------------------------
// Session output
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

/// Keys and peer identity produced by a completed handshake (§8.2.9).
pub struct SessionKeys {
    pub role: Role,
    /// Epoch 0 of the control-key chain, plus the transcript hash every
    /// epoch binds to.
    pub handshake_prk: Zeroizing<[u8; 48]>,
    pub th2: [u8; 48],
    pub control_key_c2s: Zeroizing<[u8; 32]>,
    pub control_key_s2c: Zeroizing<[u8; 32]>,
    pub transfer_wrap_key: Zeroizing<[u8; 32]>,
    pub session_resumption_secret: Zeroizing<[u8; 48]>,
    pub peer: DevicePublic,
    pub peer_endpoint_id: [u8; 32],
}

// ---------------------------------------------------------------------------
// Replay cache (§8.2.11)
// ---------------------------------------------------------------------------

/// Bounded replay cache keyed by initiator device id + hello nonce.
#[derive(Default)]
pub struct ReplayCache {
    seen: HashSet<[u8; 64]>,
    order: VecDeque<[u8; 64]>,
}

impl ReplayCache {
    pub fn check_and_insert(&mut self, device_id: &[u8; 32], nonce: &[u8; 32]) -> bool {
        let mut key = [0u8; 64];
        key[..32].copy_from_slice(device_id);
        key[32..].copy_from_slice(nonce);
        if self.seen.contains(&key) {
            return false;
        }
        if self.order.len() >= REPLAY_CACHE_CAP
            && let Some(old) = self.order.pop_front()
        {
            self.seen.remove(&old);
        }
        self.seen.insert(key);
        self.order.push_back(key);
        true
    }
}

// ---------------------------------------------------------------------------
// Message encoding
// ---------------------------------------------------------------------------

/// §8.2.2 handshake modes.
pub const MODE_STANDALONE: u64 = 0;
pub const MODE_BOUND_SESSION: u64 = 1;
pub const MODE_ASYNC_PREKEY: u64 = 2;
pub const MODE_RESUMPTION: u64 = 3;

/// ClientHello, `client-hello` in rtp2.cddl. Keys:
/// 0 protocol_major, 1 protocol_minor, 2 handshake_mode, 3 alpn,
/// 4 suites, 5 nonce_A, 6 eX25519_A, 7 eMLKEM_PK_A,
/// 8 policy {0 pqc_required (bool), 1 minimum_security_level},
/// 9 cert_A, 10 endpoint_A, 11 timestamp.
///
/// Version, mode and ALPN are ordinary fields, so they land inside TH1/TH2
/// with no extra machinery. That is what makes downgrade resistance work.
struct ClientHello {
    protocol_minor: u64,
    handshake_mode: u64,
    alpn: Vec<u8>,
    suites: Vec<u16>,
    nonce: [u8; 32],
    ex_pk: [u8; 32],
    kem_pk: [u8; MLKEM768_PUBLIC_KEY_LEN],
    pqc_required: bool,
    minimum_security_level: u64,
    cert: DevicePublic,
    endpoint_id: [u8; 32],
    timestamp: u64,
}

impl ClientHello {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        let mut m = MapWriter::begin(&mut w, 12);
        m.uint(0, PROTOCOL_MAJOR as u64);
        m.uint(1, self.protocol_minor);
        m.uint(2, self.handshake_mode);
        m.bytes(3, &self.alpn);
        {
            let inner = m.nested(4);
            inner.array(self.suites.len() as u64);
            for s in &self.suites {
                inner.uint(*s as u64);
            }
        }
        m.bytes(5, &self.nonce);
        m.bytes(6, &self.ex_pk);
        m.bytes(7, &self.kem_pk);
        {
            let inner = m.nested(8);
            let mut pm = MapWriter::begin(inner, 2);
            pm.boolean(0, self.pqc_required);
            pm.uint(1, self.minimum_security_level);
            pm.end();
        }
        {
            let inner = m.nested(9);
            self.cert.encode(inner);
        }
        m.bytes(10, &self.endpoint_id);
        m.uint(11, self.timestamp);
        m.end();
        w.into_bytes()
    }

    fn decode(bytes: &[u8]) -> Result<Self, HandshakeError> {
        let mut r = Reader::new(bytes)?;
        let mut m = r.map()?;
        m.expect_key(0)?;
        let major = m.reader.uint()?;
        if major != PROTOCOL_MAJOR as u64 {
            return Err(HandshakeError::UnsupportedVersion);
        }
        m.expect_key(1)?;
        let protocol_minor = m.reader.uint()?;
        m.expect_key(2)?;
        let handshake_mode = m.reader.uint()?;
        m.expect_key(3)?;
        let alpn = m.reader.bytes()?.to_vec();
        if alpn.len() > 64 {
            return Err(HandshakeError::Decode);
        }
        m.expect_key(4)?;
        let n = m.reader.array()?;
        if n == 0 || n > 32 {
            return Err(HandshakeError::Decode);
        }
        let mut suites = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let s = m.reader.uint()?;
            if s > u16::MAX as u64 {
                return Err(HandshakeError::Decode);
            }
            suites.push(s as u16);
        }
        m.reader.leave();
        m.expect_key(5)?;
        let nonce = m.reader.bytes_exact::<32>()?;
        m.expect_key(6)?;
        let ex_pk = m.reader.bytes_exact::<32>()?;
        m.expect_key(7)?;
        let kem_pk = m.reader.bytes_exact::<MLKEM768_PUBLIC_KEY_LEN>()?;
        m.expect_key(8)?;
        let (pqc_required, minimum_security_level) = {
            let mut pm = m.reader.map()?;
            pm.expect_key(0)?;
            let req = pm.reader.boolean()?;
            pm.expect_key(1)?;
            let level = pm.reader.uint()?;
            if pm.next_key()?.is_some() {
                return Err(HandshakeError::Decode);
            }
            (req, level)
        };
        m.expect_key(9)?;
        let cert = DevicePublic::decode(m.reader)?;
        m.expect_key(10)?;
        let endpoint_id = m.reader.bytes_exact::<32>()?;
        m.expect_key(11)?;
        let timestamp = m.reader.uint()?;
        if m.next_key()?.is_some() {
            return Err(HandshakeError::Decode);
        }
        r.finish()?;
        Ok(Self {
            protocol_minor,
            handshake_mode,
            alpn,
            suites,
            nonce,
            ex_pk,
            kem_pk,
            pqc_required,
            minimum_security_level,
            cert,
            endpoint_id,
            timestamp,
        })
    }
}

/// ServerHello, `server-hello` in rtp2.cddl. Keys:
/// 0 selected_major, 1 selected_minor, 2 handshake_mode, 3 alpn,
/// 4 selected_suite, 5 nonce_B, 6 eX25519_B, 7 eMLKEM_PK_B,
/// 8 mlkem_ct_to_a, 9 cert_B, 10 endpoint_B, 11 hybrid_signature_B.
struct ServerHello {
    selected_minor: u64,
    handshake_mode: u64,
    alpn: Vec<u8>,
    selected_suite: u16,
    nonce: [u8; 32],
    ex_pk: [u8; 32],
    kem_pk: [u8; MLKEM768_PUBLIC_KEY_LEN],
    ct_to_a: [u8; MLKEM768_CIPHERTEXT_LEN],
    cert: DevicePublic,
    endpoint_id: [u8; 32],
    signature: Option<HybridSignature>,
}

impl ServerHello {
    /// Signatures are omitted from the message being hashed at the point the
    /// signature is computed (§8.2.5).
    fn encode(&self, with_signature: bool) -> Vec<u8> {
        let entries = if with_signature { 12 } else { 11 };
        let mut w = Writer::new();
        let mut m = MapWriter::begin(&mut w, entries);
        m.uint(0, PROTOCOL_MAJOR as u64);
        m.uint(1, self.selected_minor);
        m.uint(2, self.handshake_mode);
        m.bytes(3, &self.alpn);
        m.uint(4, self.selected_suite as u64);
        m.bytes(5, &self.nonce);
        m.bytes(6, &self.ex_pk);
        m.bytes(7, &self.kem_pk);
        m.bytes(8, &self.ct_to_a);
        {
            let inner = m.nested(9);
            self.cert.encode(inner);
        }
        m.bytes(10, &self.endpoint_id);
        if with_signature {
            let sig = self.signature.as_ref().expect("signature present");
            let inner = m.nested(11);
            sig.encode(inner);
        }
        m.end();
        w.into_bytes()
    }

    fn decode(bytes: &[u8]) -> Result<Self, HandshakeError> {
        let mut r = Reader::new(bytes)?;
        let mut m = r.map()?;
        m.expect_key(0)?;
        if m.reader.uint()? != PROTOCOL_MAJOR as u64 {
            return Err(HandshakeError::UnsupportedVersion);
        }
        m.expect_key(1)?;
        let selected_minor = m.reader.uint()?;
        m.expect_key(2)?;
        let handshake_mode = m.reader.uint()?;
        m.expect_key(3)?;
        let alpn = m.reader.bytes()?.to_vec();
        if alpn.len() > 64 {
            return Err(HandshakeError::Decode);
        }
        m.expect_key(4)?;
        let selected = m.reader.uint()?;
        if selected > u16::MAX as u64 {
            return Err(HandshakeError::Decode);
        }
        m.expect_key(5)?;
        let nonce = m.reader.bytes_exact::<32>()?;
        m.expect_key(6)?;
        let ex_pk = m.reader.bytes_exact::<32>()?;
        m.expect_key(7)?;
        let kem_pk = m.reader.bytes_exact::<MLKEM768_PUBLIC_KEY_LEN>()?;
        m.expect_key(8)?;
        let ct_to_a = m.reader.bytes_exact::<MLKEM768_CIPHERTEXT_LEN>()?;
        m.expect_key(9)?;
        let cert = DevicePublic::decode(m.reader)?;
        m.expect_key(10)?;
        let endpoint_id = m.reader.bytes_exact::<32>()?;
        m.expect_key(11)?;
        let signature = HybridSignature::decode(m.reader)?;
        if m.next_key()?.is_some() {
            return Err(HandshakeError::Decode);
        }
        r.finish()?;
        Ok(Self {
            selected_minor,
            handshake_mode,
            alpn,
            selected_suite: selected as u16,
            nonce,
            ex_pk,
            kem_pk,
            ct_to_a,
            cert,
            endpoint_id,
            signature: Some(signature),
        })
    }
}

/// ClientFinish map keys:
/// 0 mlkem_ct_to_b (b1088), 1 hybrid_signature_A, 2 finished_mac_A (b48).
struct ClientFinish {
    ct_to_b: [u8; MLKEM768_CIPHERTEXT_LEN],
    signature: Option<HybridSignature>,
    finished_mac: Option<[u8; 48]>,
}

impl ClientFinish {
    fn encode_bare(ct_to_b: &[u8; MLKEM768_CIPHERTEXT_LEN]) -> Vec<u8> {
        let mut w = Writer::new();
        let mut m = MapWriter::begin(&mut w, 1);
        m.bytes(0, ct_to_b);
        m.end();
        w.into_bytes()
    }

    fn encode_full(&self) -> Vec<u8> {
        let mut w = Writer::new();
        let mut m = MapWriter::begin(&mut w, 3);
        m.bytes(0, &self.ct_to_b);
        {
            let inner = m.nested(1);
            self.signature.as_ref().expect("signature").encode(inner);
        }
        m.bytes(2, self.finished_mac.as_ref().expect("mac"));
        m.end();
        w.into_bytes()
    }

    fn decode(bytes: &[u8]) -> Result<Self, HandshakeError> {
        let mut r = Reader::new(bytes)?;
        let mut m = r.map()?;
        m.expect_key(0)?;
        let ct_to_b = m.reader.bytes_exact::<MLKEM768_CIPHERTEXT_LEN>()?;
        m.expect_key(1)?;
        let signature = HybridSignature::decode(m.reader)?;
        m.expect_key(2)?;
        let finished_mac = m.reader.bytes_exact::<48>()?;
        if m.next_key()?.is_some() {
            return Err(HandshakeError::Decode);
        }
        r.finish()?;
        Ok(Self {
            ct_to_b,
            signature: Some(signature),
            finished_mac: Some(finished_mac),
        })
    }
}

/// ServerFinish map keys: 0 finished_mac_B (b48).
fn encode_server_finish(mac: &[u8; 48]) -> Vec<u8> {
    let mut w = Writer::new();
    let mut m = MapWriter::begin(&mut w, 1);
    m.bytes(0, mac);
    m.end();
    w.into_bytes()
}

fn decode_server_finish(bytes: &[u8]) -> Result<[u8; 48], HandshakeError> {
    let mut r = Reader::new(bytes)?;
    let mut m = r.map()?;
    m.expect_key(0)?;
    let mac = m.reader.bytes_exact::<48>()?;
    if m.next_key()?.is_some() {
        return Err(HandshakeError::Decode);
    }
    r.finish()?;
    Ok(mac)
}

// ---------------------------------------------------------------------------
// Key schedule (§8.2.8–§8.2.10)
// ---------------------------------------------------------------------------

#[derive(Zeroize, ZeroizeOnDrop)]
struct DerivedKeys {
    /// Root of the §17.1.2 epoch chain.
    handshake_prk: [u8; 48],
    client_finished_key: [u8; 48],
    server_finished_key: [u8; 48],
    control_key_c2s: [u8; 32],
    control_key_s2c: [u8; 32],
    transfer_wrap_key: [u8; 32],
    session_resumption_secret: [u8; 48],
}

/// Hybrid combiner and derived keys. Every input is length-prefixed, so no
/// two distinct shared-secret triples give the same IKM.
fn derive_keys(
    ch: &[u8],
    sh_wo_sig: &[u8],
    cf_bare: &[u8],
    th2: &[u8; 48],
    ss_x: &[u8; 32],
    ss_pq_a: &[u8; 32],
    ss_pq_b: &[u8; 32],
) -> DerivedKeys {
    let salt = crypto::sha384(&[SALT_DOMAIN, ch, sh_wo_sig, cf_bare]);

    let mut ikm = Zeroizing::new(Vec::with_capacity(3 * (2 + 32)));
    for ss in [ss_x, ss_pq_a, ss_pq_b] {
        ikm.extend_from_slice(&(ss.len() as u16).to_be_bytes());
        ikm.extend_from_slice(ss.as_slice());
    }
    let prk = crypto::hkdf_extract(&salt, &ikm);

    DerivedKeys {
        handshake_prk: *prk,
        client_finished_key: *crypto::hkdf_expand::<48>(&prk, &[b"RTP2 client finished v1", th2]),
        server_finished_key: *crypto::hkdf_expand::<48>(&prk, &[b"RTP2 server finished v1", th2]),
        control_key_c2s: *crypto::hkdf_expand::<32>(&prk, &[b"RTP2 control c2s v1", th2]),
        control_key_s2c: *crypto::hkdf_expand::<32>(&prk, &[b"RTP2 control s2c v1", th2]),
        transfer_wrap_key: *crypto::hkdf_expand::<32>(&prk, &[b"RTP2 transfer wrap v1", th2]),
        session_resumption_secret: *crypto::hkdf_expand::<48>(&prk, &[b"RTP2 resumption v1", th2]),
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// §8.2.7: the all-zero X25519 shared secret MUST be rejected.
fn x25519_agree(secret: EphemeralSecret, peer: &[u8; 32]) -> Result<[u8; 32], HandshakeError> {
    let shared = secret.diffie_hellman(&XPublicKey::from(*peer));
    let bytes = *shared.as_bytes();
    if bytes == [0u8; 32] {
        return Err(HandshakeError::InvalidKey);
    }
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// Initiator
// ---------------------------------------------------------------------------

pub struct Initiator<'a> {
    identity: &'a DeviceIdentity,
    state: InitiatorState,
}

#[allow(clippy::large_enum_variant)] // handshake states hold ML-KEM keys by value
enum InitiatorState {
    AwaitServerHello {
        ex_secret: EphemeralSecret,
        kem: MlKemKeyPair,
        ch_bytes: Vec<u8>,
        expected_peer_endpoint: [u8; 32],
    },
    AwaitServerFinish {
        keys: DerivedKeys,
        th2: [u8; 48],
        finished_mac_a: [u8; 48],
        peer: DevicePublic,
        peer_endpoint_id: [u8; 32],
    },
    Done,
    Failed,
}

impl<'a> Initiator<'a> {
    /// Builds the ClientHello. `expected_peer_endpoint` is the Endpoint ID
    /// being dialed, which must match what the peer authenticates as (§7.4).
    pub fn start(
        identity: &'a DeviceIdentity,
        local_endpoint_id: [u8; 32],
        expected_peer_endpoint: [u8; 32],
    ) -> (Self, Vec<u8>) {
        let ex_secret = EphemeralSecret::random_from_rng(rand_core::OsRng);
        let ex_pk = XPublicKey::from(&ex_secret).to_bytes();
        let kem = MlKemKeyPair::generate();
        let hello = ClientHello {
            protocol_minor: PROTOCOL_MINOR as u64,
            handshake_mode: MODE_STANDALONE,
            alpn: crypto::ALPN.to_vec(),
            suites: vec![SUITE_ID],
            nonce: crypto::os_random_array(),
            ex_pk,
            kem_pk: *kem.public_bytes(),
            pqc_required: true,
            minimum_security_level: 1,
            cert: identity.public(),
            endpoint_id: local_endpoint_id,
            timestamp: now_unix(),
        };
        let ch_bytes = hello.encode();
        (
            Self {
                identity,
                state: InitiatorState::AwaitServerHello {
                    ex_secret,
                    kem,
                    ch_bytes: ch_bytes.clone(),
                    expected_peer_endpoint,
                },
            },
            ch_bytes,
        )
    }

    /// Processes ServerHello, returns the ClientFinish to send.
    pub fn on_server_hello(&mut self, sh_bytes: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        let state = std::mem::replace(&mut self.state, InitiatorState::Failed);
        let InitiatorState::AwaitServerHello {
            ex_secret,
            kem,
            ch_bytes,
            expected_peer_endpoint,
        } = state
        else {
            return Err(HandshakeError::State);
        };

        let sh = ServerHello::decode(sh_bytes)?;
        // Version, mode and ALPN must be exactly what we offered. All three
        // are in TH1, so a mismatch means the peer answered a different
        // negotiation than the one we opened.
        if sh.selected_minor != PROTOCOL_MINOR as u64 {
            return Err(HandshakeError::UnsupportedVersion);
        }
        if sh.handshake_mode != MODE_STANDALONE || sh.alpn != crypto::ALPN {
            return Err(HandshakeError::PolicyViolation);
        }
        // §6.3: only the mandatory suite; no silent downgrade path exists.
        if sh.selected_suite != SUITE_ID {
            return Err(HandshakeError::UnsupportedSuite);
        }
        // The endpoint we dialed has to be the one the peer authenticates
        // as (§7.4).
        if sh.endpoint_id != expected_peer_endpoint {
            return Err(HandshakeError::EndpointMismatch);
        }

        // §8.2.5: responder signs TH1.
        let sh_wo_sig = sh.encode(false);
        let th1 = crypto::sha384(&[TH1_DOMAIN, &ch_bytes, &sh_wo_sig]);
        let signature = sh.signature.as_ref().ok_or(HandshakeError::Decode)?;
        sh.cert
            .hybrid_verify(&th1, signature)
            .map_err(|_| HandshakeError::InvalidSignature)?;

        // §8.2.7 shared secrets.
        let ss_x = Zeroizing::new(x25519_agree(ex_secret, &sh.ex_pk)?);
        let ss_pq_a = Zeroizing::new(kem.decapsulate(&sh.ct_to_a)?);
        let (ct_to_b_vec, ss_pq_b_raw) = pqc::mlkem_encapsulate(&sh.kem_pk)?;
        let ss_pq_b = Zeroizing::new(ss_pq_b_raw);
        let ct_to_b: [u8; MLKEM768_CIPHERTEXT_LEN] = ct_to_b_vec
            .try_into()
            .map_err(|_| HandshakeError::InvalidKey)?;

        // §8.2.5: initiator signs TH2 over the full ServerHello.
        let sh_full = sh.encode(true);
        let cf_bare = ClientFinish::encode_bare(&ct_to_b);
        let th2 = crypto::sha384(&[TH2_DOMAIN, &ch_bytes, &sh_full, &cf_bare]);

        let keys = derive_keys(
            &ch_bytes, &sh_wo_sig, &cf_bare, &th2, &ss_x, &ss_pq_a, &ss_pq_b,
        );

        let signature = self
            .identity
            .hybrid_sign(&th2)
            .map_err(|_| HandshakeError::InvalidSignature)?;
        let finished_mac_a: [u8; 48] = crypto::hmac_sha384(&keys.client_finished_key, &th2);

        let cf = ClientFinish {
            ct_to_b,
            signature: Some(signature),
            finished_mac: Some(finished_mac_a),
        };
        let cf_bytes = cf.encode_full();

        self.state = InitiatorState::AwaitServerFinish {
            keys,
            th2,
            finished_mac_a,
            peer: sh.cert,
            peer_endpoint_id: sh.endpoint_id,
        };
        Ok(cf_bytes)
    }

    /// Verifies ServerFinish and yields the session keys.
    pub fn on_server_finish(&mut self, sf_bytes: &[u8]) -> Result<SessionKeys, HandshakeError> {
        let state = std::mem::replace(&mut self.state, InitiatorState::Failed);
        let InitiatorState::AwaitServerFinish {
            keys,
            th2,
            finished_mac_a,
            peer,
            peer_endpoint_id,
        } = state
        else {
            return Err(HandshakeError::State);
        };

        let mac_b = decode_server_finish(sf_bytes)?;
        // §8.2.10: finished_mac_B = HMAC(server_finished_key, SHA384(TH2 || mac_A)).
        let expected = crypto::hmac_sha384(
            &keys.server_finished_key,
            &crypto::sha384(&[&th2, &finished_mac_a]),
        );
        if !crypto::ct_eq(&mac_b, &expected) {
            return Err(HandshakeError::InvalidMac);
        }

        self.state = InitiatorState::Done;
        Ok(SessionKeys {
            role: Role::Initiator,
            handshake_prk: Zeroizing::new(keys.handshake_prk),
            th2,
            control_key_c2s: Zeroizing::new(keys.control_key_c2s),
            control_key_s2c: Zeroizing::new(keys.control_key_s2c),
            transfer_wrap_key: Zeroizing::new(keys.transfer_wrap_key),
            session_resumption_secret: Zeroizing::new(keys.session_resumption_secret),
            peer,
            peer_endpoint_id,
        })
    }
}

// ---------------------------------------------------------------------------
// Responder
// ---------------------------------------------------------------------------

pub struct Responder<'a> {
    identity: &'a DeviceIdentity,
    local_endpoint_id: [u8; 32],
    state: ResponderState,
}

#[allow(clippy::large_enum_variant)] // handshake states hold ML-KEM keys by value
enum ResponderState {
    AwaitClientHello,
    AwaitClientFinish {
        ex_secret: EphemeralSecret,
        kem: MlKemKeyPair,
        ss_pq_a: Zeroizing<[u8; 32]>,
        ch_bytes: Vec<u8>,
        sh_wo_sig: Vec<u8>,
        sh_full: Vec<u8>,
        client_ex_pk: [u8; 32],
        client_cert: DevicePublic,
        client_endpoint_id: [u8; 32],
    },
    Done,
    Failed,
}

impl<'a> Responder<'a> {
    pub fn new(identity: &'a DeviceIdentity, local_endpoint_id: [u8; 32]) -> Self {
        Self {
            identity,
            local_endpoint_id,
            state: ResponderState::AwaitClientHello,
        }
    }

    /// Processes ClientHello, returns the ServerHello to send.
    ///
    /// `observed_peer_endpoint` is the Endpoint ID authenticated by the Iroh
    /// connection; §7.4 requires the hello's claim to match it.
    pub fn on_client_hello(
        &mut self,
        ch_bytes: &[u8],
        observed_peer_endpoint: &[u8; 32],
        replay: &mut ReplayCache,
    ) -> Result<Vec<u8>, HandshakeError> {
        let state = std::mem::replace(&mut self.state, ResponderState::Failed);
        let ResponderState::AwaitClientHello = state else {
            return Err(HandshakeError::State);
        };

        let ch = ClientHello::decode(ch_bytes)?;
        // The ALPN inside the hello must match what the transport
        // negotiated, and only Standalone Mode is served here.
        if ch.alpn != crypto::ALPN {
            return Err(HandshakeError::PolicyViolation);
        }
        if ch.handshake_mode != MODE_STANDALONE {
            return Err(HandshakeError::PolicyViolation);
        }
        // A responder MUST NOT select a minor above the initiator's offer.
        let selected_minor = ch.protocol_minor.min(PROTOCOL_MINOR as u64);
        if !ch.suites.contains(&SUITE_ID) {
            return Err(HandshakeError::UnsupportedSuite);
        }
        // This core runs PQC_REQUIRED, so a peer that does not is refused
        // rather than quietly downgraded.
        if !ch.pqc_required || ch.minimum_security_level < 1 {
            return Err(HandshakeError::PolicyViolation);
        }
        if &ch.endpoint_id != observed_peer_endpoint {
            return Err(HandshakeError::EndpointMismatch);
        }
        // §8.2.11 replay protection.
        let now = now_unix();
        if ch.timestamp.abs_diff(now) > TIMESTAMP_WINDOW_SECS {
            return Err(HandshakeError::Replay);
        }
        if !replay.check_and_insert(&ch.cert.device_id, &ch.nonce) {
            return Err(HandshakeError::Replay);
        }

        let ex_secret = EphemeralSecret::random_from_rng(rand_core::OsRng);
        let ex_pk = XPublicKey::from(&ex_secret).to_bytes();
        let kem = MlKemKeyPair::generate();
        let (ct_to_a_vec, ss_pq_a_raw) = pqc::mlkem_encapsulate(&ch.kem_pk)?;
        let ss_pq_a = Zeroizing::new(ss_pq_a_raw);
        let ct_to_a: [u8; MLKEM768_CIPHERTEXT_LEN] = ct_to_a_vec
            .try_into()
            .map_err(|_| HandshakeError::InvalidKey)?;

        let mut sh = ServerHello {
            selected_minor,
            handshake_mode: MODE_STANDALONE,
            alpn: crypto::ALPN.to_vec(),
            selected_suite: SUITE_ID,
            nonce: crypto::os_random_array(),
            ex_pk,
            kem_pk: *kem.public_bytes(),
            ct_to_a,
            cert: self.identity.public(),
            endpoint_id: self.local_endpoint_id,
            signature: None,
        };

        // §8.2.5: responder signs TH1.
        let sh_wo_sig = sh.encode(false);
        let th1 = crypto::sha384(&[TH1_DOMAIN, ch_bytes, &sh_wo_sig]);
        let signature = self
            .identity
            .hybrid_sign(&th1)
            .map_err(|_| HandshakeError::InvalidSignature)?;
        sh.signature = Some(signature);
        let sh_full = sh.encode(true);

        self.state = ResponderState::AwaitClientFinish {
            ex_secret,
            kem,
            ss_pq_a,
            ch_bytes: ch_bytes.to_vec(),
            sh_wo_sig,
            sh_full: sh_full.clone(),
            client_ex_pk: ch.ex_pk,
            client_cert: ch.cert,
            client_endpoint_id: ch.endpoint_id,
        };
        Ok(sh_full)
    }

    /// Processes ClientFinish, returns (ServerFinish, SessionKeys).
    pub fn on_client_finish(
        &mut self,
        cf_bytes: &[u8],
    ) -> Result<(Vec<u8>, SessionKeys), HandshakeError> {
        let state = std::mem::replace(&mut self.state, ResponderState::Failed);
        let ResponderState::AwaitClientFinish {
            ex_secret,
            kem,
            ss_pq_a,
            ch_bytes,
            sh_wo_sig,
            sh_full,
            client_ex_pk,
            client_cert,
            client_endpoint_id,
        } = state
        else {
            return Err(HandshakeError::State);
        };

        let cf = ClientFinish::decode(cf_bytes)?;
        let cf_bare = ClientFinish::encode_bare(&cf.ct_to_b);
        let th2 = crypto::sha384(&[TH2_DOMAIN, &ch_bytes, &sh_full, &cf_bare]);

        // §8.2.6, both device signatures over TH2 must verify.
        let signature = cf.signature.as_ref().ok_or(HandshakeError::Decode)?;
        client_cert
            .hybrid_verify(&th2, signature)
            .map_err(|_| HandshakeError::InvalidSignature)?;

        // §8.2.7 shared secrets.
        let ss_x = Zeroizing::new(x25519_agree(ex_secret, &client_ex_pk)?);
        let ss_pq_b = Zeroizing::new(kem.decapsulate(&cf.ct_to_b)?);

        let keys = derive_keys(
            &ch_bytes, &sh_wo_sig, &cf_bare, &th2, &ss_x, &ss_pq_a, &ss_pq_b,
        );

        // §8.2.10: verify finished_mac_A before accepting anything further.
        let mac_a = cf.finished_mac.ok_or(HandshakeError::Decode)?;
        let expected_a = crypto::hmac_sha384(&keys.client_finished_key, &th2);
        if !crypto::ct_eq(&mac_a, &expected_a) {
            return Err(HandshakeError::InvalidMac);
        }

        let mac_b =
            crypto::hmac_sha384(&keys.server_finished_key, &crypto::sha384(&[&th2, &mac_a]));
        let sf_bytes = encode_server_finish(&mac_b);

        let session = SessionKeys {
            role: Role::Responder,
            handshake_prk: Zeroizing::new(keys.handshake_prk),
            th2,
            control_key_c2s: Zeroizing::new(keys.control_key_c2s),
            control_key_s2c: Zeroizing::new(keys.control_key_s2c),
            transfer_wrap_key: Zeroizing::new(keys.transfer_wrap_key),
            session_resumption_secret: Zeroizing::new(keys.session_resumption_secret),
            peer: client_cert,
            peer_endpoint_id: client_endpoint_id,
        };
        self.state = ResponderState::Done;
        Ok((sf_bytes, session))
    }
}

// ---------------------------------------------------------------------------
// Session resumption (§8.4)
// ---------------------------------------------------------------------------

const RESUME_TH_DOMAIN: &[u8] = b"RTP2-RESUME-TH-v1";

/// §8.4: `resumption_id = first_16_bytes(HKDF-Expand(secret, "RTP2 resumption id v1", 16))`
pub fn resumption_id(session_resumption_secret: &[u8; 48]) -> [u8; 16] {
    *crypto::hkdf_expand::<16>(session_resumption_secret, &[b"RTP2 resumption id v1"])
}

/// Keys for a resumed session. No ML-KEM or ML-DSA work is redone; freshness
/// comes from both sides' nonces.
pub struct ResumedSession {
    pub handshake_prk: Zeroizing<[u8; 48]>,
    pub th_r: [u8; 48],
    pub control_key_c2s: Zeroizing<[u8; 32]>,
    pub control_key_s2c: Zeroizing<[u8; 32]>,
    pub transfer_wrap_key: Zeroizing<[u8; 32]>,
    pub session_resumption_secret: Zeroizing<[u8; 48]>,
}

/// `resumption-hello` in rtp2.cddl. Keys 0..8.
pub struct ResumptionHello {
    pub protocol_minor: u64,
    pub alpn: Vec<u8>,
    pub suite_id: u16,
    pub resumption_id: [u8; 16],
    pub nonce: [u8; 32],
    pub timestamp: u64,
    pub endpoint_id: [u8; 32],
}

impl ResumptionHello {
    pub fn new(session_resumption_secret: &[u8; 48], endpoint_id: [u8; 32]) -> Self {
        Self {
            protocol_minor: PROTOCOL_MINOR as u64,
            alpn: crypto::ALPN.to_vec(),
            suite_id: SUITE_ID,
            resumption_id: resumption_id(session_resumption_secret),
            nonce: crypto::os_random_array(),
            timestamp: now_unix(),
            endpoint_id,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        let mut m = MapWriter::begin(&mut w, 9);
        m.uint(0, PROTOCOL_MAJOR as u64);
        m.uint(1, self.protocol_minor);
        m.uint(2, MODE_RESUMPTION);
        m.bytes(3, &self.alpn);
        m.uint(4, self.suite_id as u64);
        m.bytes(5, &self.resumption_id);
        m.bytes(6, &self.nonce);
        m.uint(7, self.timestamp);
        m.bytes(8, &self.endpoint_id);
        m.end();
        w.into_bytes()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, HandshakeError> {
        let mut r = Reader::new(bytes)?;
        let mut m = r.map()?;
        m.expect_key(0)?;
        if m.reader.uint()? != PROTOCOL_MAJOR as u64 {
            return Err(HandshakeError::UnsupportedVersion);
        }
        m.expect_key(1)?;
        let protocol_minor = m.reader.uint()?;
        m.expect_key(2)?;
        if m.reader.uint()? != MODE_RESUMPTION {
            return Err(HandshakeError::PolicyViolation);
        }
        m.expect_key(3)?;
        let alpn = m.reader.bytes()?.to_vec();
        if alpn != crypto::ALPN {
            return Err(HandshakeError::PolicyViolation);
        }
        m.expect_key(4)?;
        let suite_id = m.reader.uint()?;
        if suite_id != SUITE_ID as u64 {
            return Err(HandshakeError::UnsupportedSuite);
        }
        m.expect_key(5)?;
        let resumption_id = m.reader.bytes_exact::<16>()?;
        m.expect_key(6)?;
        let nonce = m.reader.bytes_exact::<32>()?;
        m.expect_key(7)?;
        let timestamp = m.reader.uint()?;
        m.expect_key(8)?;
        let endpoint_id = m.reader.bytes_exact::<32>()?;
        if m.next_key()?.is_some() {
            return Err(HandshakeError::Decode);
        }
        r.finish()?;
        Ok(Self {
            protocol_minor,
            alpn,
            suite_id: suite_id as u16,
            resumption_id,
            nonce,
            timestamp,
            endpoint_id,
        })
    }
}

/// `resumption-accept` in rtp2.cddl. Keys 0..2.
pub struct ResumptionAccept {
    pub nonce: [u8; 32],
    pub endpoint_id: [u8; 32],
    pub timestamp: u64,
}

impl ResumptionAccept {
    pub fn new(endpoint_id: [u8; 32]) -> Self {
        Self {
            nonce: crypto::os_random_array(),
            endpoint_id,
            timestamp: now_unix(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        let mut m = MapWriter::begin(&mut w, 3);
        m.bytes(0, &self.nonce);
        m.bytes(1, &self.endpoint_id);
        m.uint(2, self.timestamp);
        m.end();
        w.into_bytes()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, HandshakeError> {
        let mut r = Reader::new(bytes)?;
        let mut m = r.map()?;
        m.expect_key(0)?;
        let nonce = m.reader.bytes_exact::<32>()?;
        m.expect_key(1)?;
        let endpoint_id = m.reader.bytes_exact::<32>()?;
        m.expect_key(2)?;
        let timestamp = m.reader.uint()?;
        if m.next_key()?.is_some() {
            return Err(HandshakeError::Decode);
        }
        r.finish()?;
        Ok(Self {
            nonce,
            endpoint_id,
            timestamp,
        })
    }
}

/// §8.4 key schedule. Both sides run this over the same two messages.
pub fn resumption_keys(
    session_resumption_secret: &[u8; 48],
    hello_bytes: &[u8],
    accept_bytes: &[u8],
) -> ResumedSession {
    let th_r = crypto::sha384(&[RESUME_TH_DOMAIN, hello_bytes, accept_bytes]);
    let prk = crypto::hkdf_extract(&th_r, session_resumption_secret);

    ResumedSession {
        control_key_c2s: crypto::hkdf_expand::<32>(&prk, &[b"RTP2 control c2s v1", &th_r]),
        control_key_s2c: crypto::hkdf_expand::<32>(&prk, &[b"RTP2 control s2c v1", &th_r]),
        transfer_wrap_key: crypto::hkdf_expand::<32>(&prk, &[b"RTP2 transfer wrap v1", &th_r]),
        // A resumed session derives its own next secret, so a chain of them
        // never reuses one.
        session_resumption_secret: crypto::hkdf_expand::<48>(&prk, &[b"RTP2 resumption v1", &th_r]),
        handshake_prk: prk,
        th_r,
    }
}

/// §8.4 confirmation, the resumption analogue of §8.2.10.
pub fn resumption_finished_mac(session_resumption_secret: &[u8; 48], th_r: &[u8; 48]) -> [u8; 48] {
    let prk = crypto::hkdf_extract(th_r, session_resumption_secret);
    let key = crypto::hkdf_expand::<48>(&prk, &[b"RTP2 resumption finished v1", th_r]);
    crypto::hmac_sha384(key.as_ref(), th_r)
}

// ---------------------------------------------------------------------------
// Conformance surface
// ---------------------------------------------------------------------------

/// Lets conformance tests recompute the transcript and key schedule
/// independently and compare. Not part of the C ABI.
#[doc(hidden)]
pub mod conformance {
    use super::*;

    pub const TH1_DOMAIN_BYTES: &[u8] = TH1_DOMAIN;
    pub const TH2_DOMAIN_BYTES: &[u8] = TH2_DOMAIN;
    pub const SALT_DOMAIN_BYTES: &[u8] = SALT_DOMAIN;

    /// Re-encodes a ServerHello without its signature, as TH1 needs.
    pub fn server_hello_without_signature(bytes: &[u8]) -> Option<Vec<u8>> {
        ServerHello::decode(bytes).ok().map(|sh| sh.encode(false))
    }

    /// Extracts the responder's hybrid signature from a ServerHello.
    pub fn server_hello_signature(bytes: &[u8]) -> Option<HybridSignature> {
        ServerHello::decode(bytes).ok().and_then(|sh| sh.signature)
    }

    /// Re-encodes a ClientFinish without signature or finished MAC, as TH2
    /// needs.
    pub fn client_finish_bare(bytes: &[u8]) -> Option<Vec<u8>> {
        ClientFinish::decode(bytes)
            .ok()
            .map(|cf| ClientFinish::encode_bare(&cf.ct_to_b))
    }

    /// Extracts the initiator's hybrid signature from a ClientFinish.
    pub fn client_finish_signature(bytes: &[u8]) -> Option<HybridSignature> {
        ClientFinish::decode(bytes).ok().and_then(|cf| cf.signature)
    }

    /// Extracts finished_mac_A from a ClientFinish.
    pub fn client_finish_mac(bytes: &[u8]) -> Option<[u8; 48]> {
        ClientFinish::decode(bytes)
            .ok()
            .and_then(|cf| cf.finished_mac)
    }

    /// Extracts finished_mac_B from a ServerFinish.
    pub fn server_finish_mac(bytes: &[u8]) -> Option<[u8; 48]> {
        decode_server_finish(bytes).ok()
    }

    /// The six derived keys of §8.2.9, in declaration order:
    /// client_finished, server_finished, control_c2s, control_s2c,
    /// transfer_wrap, session_resumption.
    #[allow(clippy::type_complexity)]
    pub fn derived_keys(
        ch: &[u8],
        sh_wo_sig: &[u8],
        cf_bare: &[u8],
        th2: &[u8; 48],
        ss_x: &[u8; 32],
        ss_pq_a: &[u8; 32],
        ss_pq_b: &[u8; 32],
    ) -> ([u8; 48], [u8; 48], [u8; 32], [u8; 32], [u8; 32], [u8; 48]) {
        let k = derive_keys(ch, sh_wo_sig, cf_bare, th2, ss_x, ss_pq_a, ss_pq_b);
        (
            k.client_finished_key,
            k.server_finished_key,
            k.control_key_c2s,
            k.control_key_s2c,
            k.transfer_wrap_key,
            k.session_resumption_secret,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_handshake() -> (SessionKeys, SessionKeys) {
        let id_a = DeviceIdentity::generate();
        let id_b = DeviceIdentity::generate();
        let ep_a = [0xaa; 32];
        let ep_b = [0xbb; 32];
        let mut replay = ReplayCache::default();

        let (mut initiator, ch) = Initiator::start(&id_a, ep_a, ep_b);
        let mut responder = Responder::new(&id_b, ep_b);
        let sh = responder.on_client_hello(&ch, &ep_a, &mut replay).unwrap();
        let cf = initiator.on_server_hello(&sh).unwrap();
        let (sf, keys_b) = responder.on_client_finish(&cf).unwrap();
        let keys_a = initiator.on_server_finish(&sf).unwrap();
        (keys_a, keys_b)
    }

    #[test]
    fn completes_and_keys_match() {
        let (a, b) = run_handshake();
        assert_eq!(a.control_key_c2s.as_ref(), b.control_key_c2s.as_ref());
        assert_eq!(a.control_key_s2c.as_ref(), b.control_key_s2c.as_ref());
        assert_eq!(a.transfer_wrap_key.as_ref(), b.transfer_wrap_key.as_ref());
        assert_ne!(a.control_key_c2s.as_ref(), a.control_key_s2c.as_ref());
    }

    #[test]
    fn replayed_hello_is_rejected() {
        let id_a = DeviceIdentity::generate();
        let id_b = DeviceIdentity::generate();
        let ep_a = [0xaa; 32];
        let ep_b = [0xbb; 32];
        let mut replay = ReplayCache::default();

        let (_initiator, ch) = Initiator::start(&id_a, ep_a, ep_b);
        let mut r1 = Responder::new(&id_b, ep_b);
        r1.on_client_hello(&ch, &ep_a, &mut replay).unwrap();
        let mut r2 = Responder::new(&id_b, ep_b);
        assert_eq!(
            r2.on_client_hello(&ch, &ep_a, &mut replay).unwrap_err(),
            HandshakeError::Replay
        );
    }

    #[test]
    fn tampered_server_hello_fails_signature() {
        let id_a = DeviceIdentity::generate();
        let id_b = DeviceIdentity::generate();
        let ep_a = [0xaa; 32];
        let ep_b = [0xbb; 32];
        let mut replay = ReplayCache::default();

        let (mut initiator, ch) = Initiator::start(&id_a, ep_a, ep_b);
        let mut responder = Responder::new(&id_b, ep_b);
        let sh = responder.on_client_hello(&ch, &ep_a, &mut replay).unwrap();

        // Swap the KEM ciphertext. The signature over TH1 must catch it.
        let mut decoded = ServerHello::decode(&sh).unwrap();
        decoded.ct_to_a[0] ^= 1;
        let forged = decoded.encode(true);
        assert!(initiator.on_server_hello(&forged).is_err());
    }

    #[test]
    fn endpoint_mismatch_fails() {
        let id_a = DeviceIdentity::generate();
        let id_b = DeviceIdentity::generate();
        let mut replay = ReplayCache::default();
        let (_i, ch) = Initiator::start(&id_a, [0xaa; 32], [0xbb; 32]);
        let mut responder = Responder::new(&id_b, [0xbb; 32]);
        // Observed endpoint differs from the hello's claim (§7.4).
        assert_eq!(
            responder
                .on_client_hello(&ch, &[0xcc; 32], &mut replay)
                .unwrap_err(),
            HandshakeError::EndpointMismatch
        );
    }

    #[test]
    fn wrong_finished_mac_fails() {
        let id_a = DeviceIdentity::generate();
        let id_b = DeviceIdentity::generate();
        let ep_a = [0xaa; 32];
        let ep_b = [0xbb; 32];
        let mut replay = ReplayCache::default();

        let (mut initiator, ch) = Initiator::start(&id_a, ep_a, ep_b);
        let mut responder = Responder::new(&id_b, ep_b);
        let sh = responder.on_client_hello(&ch, &ep_a, &mut replay).unwrap();
        let _cf = initiator.on_server_hello(&sh).unwrap();
        // Forge a ServerFinish with a wrong MAC. SessionKeys has no Debug on
        // purpose, so match rather than unwrap_err.
        let forged = encode_server_finish(&[0u8; 48]);
        match initiator.on_server_finish(&forged) {
            Err(HandshakeError::InvalidMac) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("forged finished MAC accepted"),
        }
    }

    #[test]
    fn resumption_derives_matching_keys_on_both_sides() {
        // Same schedule, same two messages, so a resumed session agrees on
        // keys with no signature exchange.
        let secret = [0x3cu8; 48];
        let hello = ResumptionHello::new(&secret, [0xaa; 32]);
        let accept = ResumptionAccept::new([0xbb; 32]);
        let hb = hello.encode();
        let ab = accept.encode();

        let initiator = resumption_keys(&secret, &hb, &ab);
        let responder = resumption_keys(&secret, &hb, &ab);
        assert_eq!(
            initiator.control_key_c2s.as_ref(),
            responder.control_key_c2s.as_ref()
        );
        assert_eq!(
            initiator.transfer_wrap_key.as_ref(),
            responder.transfer_wrap_key.as_ref()
        );
        assert_ne!(
            initiator.control_key_c2s.as_ref(),
            initiator.control_key_s2c.as_ref()
        );

        // Both confirm with the same MAC over the same transcript.
        assert_eq!(
            resumption_finished_mac(&secret, &initiator.th_r),
            resumption_finished_mac(&secret, &responder.th_r)
        );
    }

    #[test]
    fn every_resumption_is_freshly_keyed() {
        // Resumption must derive fresh traffic keys, and fresh nonces on
        // both sides are what guarantee that.
        let secret = [0x3cu8; 48];
        let first = {
            let h = ResumptionHello::new(&secret, [0xaa; 32]).encode();
            let a = ResumptionAccept::new([0xbb; 32]).encode();
            resumption_keys(&secret, &h, &a)
        };
        let second = {
            let h = ResumptionHello::new(&secret, [0xaa; 32]).encode();
            let a = ResumptionAccept::new([0xbb; 32]).encode();
            resumption_keys(&secret, &h, &a)
        };
        assert_ne!(first.th_r, second.th_r);
        assert_ne!(
            first.control_key_c2s.as_ref(),
            second.control_key_c2s.as_ref()
        );
        assert_ne!(
            first.transfer_wrap_key.as_ref(),
            second.transfer_wrap_key.as_ref()
        );
        // The next secret differs from the one consumed, so a chain never
        // reuses one.
        assert_ne!(first.session_resumption_secret.as_ref(), &secret);
        assert_ne!(
            first.session_resumption_secret.as_ref(),
            second.session_resumption_secret.as_ref()
        );
    }

    #[test]
    fn resumption_keys_are_bound_to_both_messages() {
        let secret = [0x3cu8; 48];
        let hello = ResumptionHello::new(&secret, [0xaa; 32]).encode();
        let accept = ResumptionAccept::new([0xbb; 32]).encode();
        let base = resumption_keys(&secret, &hello, &accept);

        let mut tampered_hello = hello.clone();
        tampered_hello[10] ^= 1;
        assert_ne!(
            base.control_key_c2s.as_ref(),
            resumption_keys(&secret, &tampered_hello, &accept)
                .control_key_c2s
                .as_ref()
        );

        let mut tampered_accept = accept.clone();
        tampered_accept[5] ^= 1;
        assert_ne!(
            base.control_key_c2s.as_ref(),
            resumption_keys(&secret, &hello, &tampered_accept)
                .control_key_c2s
                .as_ref()
        );

        // A different stored secret gives different keys, which is what
        // makes the id lookup mean anything.
        let mut other_secret = secret;
        other_secret[0] ^= 1;
        assert_ne!(
            base.control_key_c2s.as_ref(),
            resumption_keys(&other_secret, &hello, &accept)
                .control_key_c2s
                .as_ref()
        );
    }

    #[test]
    fn resumption_messages_round_trip_and_reject_wrong_mode() {
        let secret = [0x77u8; 48];
        let hello = ResumptionHello::new(&secret, [0x11; 32]);
        let bytes = hello.encode();
        let decoded = ResumptionHello::decode(&bytes).unwrap();
        assert_eq!(decoded.resumption_id, resumption_id(&secret));
        assert_eq!(decoded.endpoint_id, [0x11; 32]);

        // §8.2.2 prefix: major, minor, mode=RESUMPTION(3).
        assert_eq!(&bytes[1..7], &[0x00, 0x02, 0x01, 0x00, 0x02, 0x03]);

        // A hello naming Standalone is not a resumption hello.
        let mut wrong_mode = bytes.clone();
        wrong_mode[6] = 0x00;
        match ResumptionHello::decode(&wrong_mode) {
            Err(e) => assert_eq!(e, HandshakeError::PolicyViolation),
            Ok(_) => panic!("a Standalone-mode hello decoded as a resumption hello"),
        }

        let accept = ResumptionAccept::new([0x22; 32]);
        let ab = accept.encode();
        assert_eq!(
            ResumptionAccept::decode(&ab).unwrap().endpoint_id,
            [0x22; 32]
        );

        // Garbage and truncation fail cleanly.
        for cut in 0..bytes.len().min(40) {
            assert!(ResumptionHello::decode(&bytes[..cut]).is_err());
        }
    }

    #[test]
    fn resumption_id_is_derived_not_the_secret() {
        // The id travels in the clear, so it must not reveal the secret.
        let secret = [0x9au8; 48];
        let id = resumption_id(&secret);
        assert!(
            !secret.windows(16).any(|w| w == id),
            "the resumption id must not be a slice of the secret"
        );
        let mut other = secret;
        other[47] ^= 1;
        assert_ne!(id, resumption_id(&other));
    }

    #[test]
    fn non_pqc_hello_is_refused() {
        // A hello with pqc_required = 0 must be refused, not continued
        // classical-only (INV-04).
        let id_a = DeviceIdentity::generate();
        let id_b = DeviceIdentity::generate();
        let ep_a = [0xaa; 32];
        let ep_b = [0xbb; 32];
        let mut replay = ReplayCache::default();

        let (_i, ch_bytes) = Initiator::start(&id_a, ep_a, ep_b);
        let mut ch = ClientHello::decode(&ch_bytes).unwrap();
        ch.pqc_required = false;
        let downgraded = ch.encode();
        let mut responder = Responder::new(&id_b, ep_b);
        assert_eq!(
            responder
                .on_client_hello(&downgraded, &ep_a, &mut replay)
                .unwrap_err(),
            HandshakeError::PolicyViolation
        );
    }
}
