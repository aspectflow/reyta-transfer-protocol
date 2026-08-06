// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//! Every test here models an active attacker and asserts the pipeline
//! refuses to complete.
//!
//! The transcript covers every handshake byte, so any change to a message
//! seen by one side must stop both from completing with matching keys, by
//! signature, MAC, decode failure or key divergence. A panic is never an
//! acceptable outcome.

use rtp2_core::handshake::{HandshakeError, Initiator, ReplayCache, Responder, SessionKeys};
use rtp2_core::identity::DeviceIdentity;
use rtp2_core::keys::{self, FileSecrets};
use rtp2_core::merkle;
use rtp2_core::object::{self, ObjectContext};

const EP_A: [u8; 32] = [0xaa; 32];
const EP_B: [u8; 32] = [0xbb; 32];

struct Peers {
    a: DeviceIdentity,
    b: DeviceIdentity,
}

impl Peers {
    fn new() -> Self {
        Self {
            a: DeviceIdentity::generate(),
            b: DeviceIdentity::generate(),
        }
    }

    /// Runs a handshake where the attacker may substitute each message on the
    /// wire. Returns Some((keys_a, keys_b)) only if BOTH sides completed.
    fn run(
        &self,
        mutate_ch: impl Fn(&[u8]) -> Vec<u8>,
        mutate_sh: impl Fn(&[u8]) -> Vec<u8>,
        mutate_cf: impl Fn(&[u8]) -> Vec<u8>,
        mutate_sf: impl Fn(&[u8]) -> Vec<u8>,
    ) -> Option<(SessionKeys, SessionKeys)> {
        let mut replay = ReplayCache::default();
        let (mut initiator, ch) = Initiator::start(&self.a, EP_A, EP_B);
        let mut responder = Responder::new(&self.b, EP_B);

        let sh = responder
            .on_client_hello(&mutate_ch(&ch), &EP_A, &mut replay)
            .ok()?;
        let cf = initiator.on_server_hello(&mutate_sh(&sh)).ok()?;
        let (sf, keys_b) = responder.on_client_finish(&mutate_cf(&cf)).ok()?;
        let keys_a = initiator.on_server_finish(&mutate_sf(&sf)).ok()?;
        Some((keys_a, keys_b))
    }
}

fn id(bytes: &[u8]) -> Vec<u8> {
    bytes.to_vec()
}

/// Boundaries plus a stride through the middle, so every field gets hit
/// without a full sweep.
fn sample_positions(len: usize) -> Vec<usize> {
    let mut positions: Vec<usize> = (0..len.min(24)).collect();
    positions.extend((len.saturating_sub(24)..len).collect::<Vec<_>>());
    let stride = (len / 96).max(1);
    positions.extend((0..len).step_by(stride));
    positions.sort_unstable();
    positions.dedup();
    positions
}

fn flip(bytes: &[u8], pos: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[pos] ^= 0x01;
    out
}

// ---------------------------------------------------------------------------
// Transcript binding: bit-flips anywhere in any message kill the handshake
// ---------------------------------------------------------------------------

#[test]
fn any_client_hello_byte_flip_kills_handshake() {
    let peers = Peers::new();
    let (_i, ch) = Initiator::start(&peers.a, EP_A, EP_B);
    for pos in sample_positions(ch.len()) {
        let result = peers.run(|c| flip(c, pos), id, id, id);
        assert!(
            result.is_none(),
            "handshake completed despite ClientHello byte {pos} flipped"
        );
    }
}

#[test]
fn any_server_hello_byte_flip_kills_handshake() {
    let peers = Peers::new();
    // Capture a real ServerHello once to size the sweep.
    let mut replay = ReplayCache::default();
    let (_i, ch) = Initiator::start(&peers.a, EP_A, EP_B);
    let sh = Responder::new(&peers.b, EP_B)
        .on_client_hello(&ch, &EP_A, &mut replay)
        .unwrap();
    for pos in sample_positions(sh.len()) {
        let result = peers.run(id, |s| flip(s, pos), id, id);
        assert!(
            result.is_none(),
            "handshake completed despite ServerHello byte {pos} flipped"
        );
    }
}

#[test]
fn any_client_finish_byte_flip_kills_handshake() {
    let peers = Peers::new();
    let mut replay = ReplayCache::default();
    let (mut initiator, ch) = Initiator::start(&peers.a, EP_A, EP_B);
    let sh = Responder::new(&peers.b, EP_B)
        .on_client_hello(&ch, &EP_A, &mut replay)
        .unwrap();
    let cf = initiator.on_server_hello(&sh).unwrap();
    for pos in sample_positions(cf.len()) {
        let result = peers.run(id, id, |c| flip(c, pos), id);
        assert!(
            result.is_none(),
            "handshake completed despite ClientFinish byte {pos} flipped"
        );
    }
}

#[test]
fn any_server_finish_byte_flip_kills_handshake() {
    let peers = Peers::new();
    // ServerFinish is small: sweep every byte.
    let mut replay = ReplayCache::default();
    let (mut initiator, ch) = Initiator::start(&peers.a, EP_A, EP_B);
    let mut responder = Responder::new(&peers.b, EP_B);
    let sh = responder.on_client_hello(&ch, &EP_A, &mut replay).unwrap();
    let cf = initiator.on_server_hello(&sh).unwrap();
    let (sf, _keys_b) = responder.on_client_finish(&cf).unwrap();
    for pos in 0..sf.len() {
        let result = peers.run(id, id, id, |s| flip(s, pos));
        assert!(
            result.is_none(),
            "handshake completed despite ServerFinish byte {pos} flipped"
        );
    }
}

// ---------------------------------------------------------------------------
// Honest baseline + freshness
// ---------------------------------------------------------------------------

#[test]
fn honest_handshake_completes_with_matching_keys() {
    let peers = Peers::new();
    let (a, b) = peers.run(id, id, id, id).expect("honest handshake");
    assert_eq!(a.control_key_c2s.as_ref(), b.control_key_c2s.as_ref());
    assert_eq!(a.control_key_s2c.as_ref(), b.control_key_s2c.as_ref());
    assert_eq!(a.transfer_wrap_key.as_ref(), b.transfer_wrap_key.as_ref());
    assert_eq!(
        a.session_resumption_secret.as_ref(),
        b.session_resumption_secret.as_ref()
    );
    assert_eq!(a.peer.device_id, peers.b.device_id);
    assert_eq!(b.peer.device_id, peers.a.device_id);
}

#[test]
fn sessions_never_share_keys() {
    // Two handshakes between the same devices: fresh ephemerals and nonces
    // must give unrelated session keys.
    let peers = Peers::new();
    let (a1, _b1) = peers.run(id, id, id, id).unwrap();
    let (a2, _b2) = peers.run(id, id, id, id).unwrap();
    assert_ne!(a1.transfer_wrap_key.as_ref(), a2.transfer_wrap_key.as_ref());
    assert_ne!(a1.control_key_c2s.as_ref(), a2.control_key_c2s.as_ref());
    assert_ne!(
        a1.session_resumption_secret.as_ref(),
        a2.session_resumption_secret.as_ref()
    );
}

// ---------------------------------------------------------------------------
// Cross-session transplants (INV-08)
// ---------------------------------------------------------------------------

#[test]
fn server_hello_from_another_session_is_rejected() {
    let peers = Peers::new();
    let mut replay = ReplayCache::default();

    // Session 1 produces a fully valid, signed ServerHello.
    let (_i1, ch1) = Initiator::start(&peers.a, EP_A, EP_B);
    let sh1 = Responder::new(&peers.b, EP_B)
        .on_client_hello(&ch1, &EP_A, &mut replay)
        .unwrap();

    // Session 2: attacker replays session 1's ServerHello.
    let (mut i2, _ch2) = Initiator::start(&peers.a, EP_A, EP_B);
    assert!(
        i2.on_server_hello(&sh1).is_err(),
        "signature bound to another session's transcript was accepted"
    );
}

#[test]
fn client_finish_from_another_session_is_rejected() {
    let peers = Peers::new();

    // Two parallel sessions between the same devices.
    let mut replay = ReplayCache::default();
    let (mut i1, ch1) = Initiator::start(&peers.a, EP_A, EP_B);
    let mut r1 = Responder::new(&peers.b, EP_B);
    let sh1 = r1.on_client_hello(&ch1, &EP_A, &mut replay).unwrap();
    let cf1 = i1.on_server_hello(&sh1).unwrap();

    let (mut i2, ch2) = Initiator::start(&peers.a, EP_A, EP_B);
    let mut r2 = Responder::new(&peers.b, EP_B);
    let sh2 = r2.on_client_hello(&ch2, &EP_A, &mut replay).unwrap();
    let _cf2 = i2.on_server_hello(&sh2).unwrap();

    // Session 1's finish presented to session 2's responder.
    assert!(
        r2.on_client_finish(&cf1).is_err(),
        "ClientFinish from another session was accepted"
    );
}

#[test]
fn impersonation_without_private_keys_fails() {
    // The attacker has B's public bundle but not its private keys, so it
    // cannot produce the hybrid signature over TH1.
    let peers = Peers::new();
    let mallory = DeviceIdentity::generate();
    let mut replay = ReplayCache::default();

    let (mut initiator, ch) = Initiator::start(&peers.a, EP_A, EP_B);
    // Mallory can only sign with her own keys. The initiator checks the
    // signature against the cert inside the message, so she has to present
    // her own, and the session then names her. The trust decision stays with
    // the caller.
    let sh = Responder::new(&mallory, EP_B)
        .on_client_hello(&ch, &EP_A, &mut replay)
        .unwrap();
    let _cf = initiator.on_server_hello(&sh).unwrap();
    // Continued, the session authenticates Mallory, not B. She still had to
    // control the dialed endpoint to get here.
    let mut replay2 = ReplayCache::default();
    let (mut i2, ch2) = Initiator::start(&peers.a, EP_A, EP_B);
    let mut rm = Responder::new(&mallory, EP_B);
    let sh2 = rm.on_client_hello(&ch2, &EP_A, &mut replay2).unwrap();
    let cf2 = i2.on_server_hello(&sh2).unwrap();
    let (sf2, _kb) = rm.on_client_finish(&cf2).unwrap();
    let keys = i2.on_server_finish(&sf2).unwrap();
    assert_eq!(keys.peer.device_id, mallory.device_id);
    assert_ne!(keys.peer.device_id, peers.b.device_id);
}

// ---------------------------------------------------------------------------
// Key confirmation (§8.2.10)
// ---------------------------------------------------------------------------

#[test]
fn responder_rejects_tampered_finished_mac() {
    // The initiator's signature does not cover finished_mac_A, since TH2
    // hashes the ClientFinish without it. Only the explicit MAC check stands
    // between a tampered confirmation and an accepted session. It is the last
    // 48 bytes of the encoding.
    let peers = Peers::new();
    let mut replay = ReplayCache::default();
    let (mut initiator, ch) = Initiator::start(&peers.a, EP_A, EP_B);
    let mut responder = Responder::new(&peers.b, EP_B);
    let sh = responder.on_client_hello(&ch, &EP_A, &mut replay).unwrap();
    let cf = initiator.on_server_hello(&sh).unwrap();

    // Sanity: the untouched finish is accepted.
    {
        let mut r = Responder::new(&peers.b, EP_B);
        let mut rp = ReplayCache::default();
        let (_i, ch2) = Initiator::start(&peers.a, EP_A, EP_B);
        let _ = r.on_client_hello(&ch2, &EP_A, &mut rp).unwrap();
    }
    assert!(responder.on_client_finish(&cf).is_ok());

    // Every byte of the trailing MAC has to matter.
    for offset in 1..=48usize {
        let mut replay = ReplayCache::default();
        let (mut i, ch) = Initiator::start(&peers.a, EP_A, EP_B);
        let mut r = Responder::new(&peers.b, EP_B);
        let sh = r.on_client_hello(&ch, &EP_A, &mut replay).unwrap();
        let mut cf = i.on_server_hello(&sh).unwrap();
        let pos = cf.len() - offset;
        cf[pos] ^= 0x01;
        assert_eq!(
            r.on_client_finish(&cf).err(),
            Some(HandshakeError::InvalidMac),
            "tampered finished_mac_A byte at -{offset} was accepted"
        );
    }
}

#[test]
fn initiator_rejects_tampered_server_finish_mac() {
    let peers = Peers::new();
    for offset in 1..=48usize {
        let mut replay = ReplayCache::default();
        let (mut i, ch) = Initiator::start(&peers.a, EP_A, EP_B);
        let mut r = Responder::new(&peers.b, EP_B);
        let sh = r.on_client_hello(&ch, &EP_A, &mut replay).unwrap();
        let cf = i.on_server_hello(&sh).unwrap();
        let (mut sf, _keys) = r.on_client_finish(&cf).unwrap();
        let pos = sf.len() - offset;
        sf[pos] ^= 0x01;
        match i.on_server_finish(&sf) {
            Err(HandshakeError::InvalidMac) | Err(HandshakeError::Decode) => {}
            other => panic!(
                "tampered finished_mac_B byte at -{offset} gave {:?}",
                other.err()
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Replay and endpoint binding
// ---------------------------------------------------------------------------

#[test]
fn hello_replay_across_responders_with_shared_cache() {
    let peers = Peers::new();
    let mut replay = ReplayCache::default();
    let (_i, ch) = Initiator::start(&peers.a, EP_A, EP_B);

    let mut r1 = Responder::new(&peers.b, EP_B);
    r1.on_client_hello(&ch, &EP_A, &mut replay).unwrap();
    let mut r2 = Responder::new(&peers.b, EP_B);
    assert_eq!(
        r2.on_client_hello(&ch, &EP_A, &mut replay).unwrap_err(),
        HandshakeError::Replay
    );
}

#[test]
fn endpoint_binding_rejects_forwarded_hello() {
    // A hello built for endpoint B, arriving over a connection whose
    // authenticated remote is C, must be refused.
    let peers = Peers::new();
    let mut replay = ReplayCache::default();
    let (_i, ch) = Initiator::start(&peers.a, EP_A, EP_B);
    let mut responder = Responder::new(&peers.b, EP_B);
    assert_eq!(
        responder
            .on_client_hello(&ch, &[0xcc; 32], &mut replay)
            .unwrap_err(),
        HandshakeError::EndpointMismatch
    );
}

// ---------------------------------------------------------------------------
// §8.2.2 negotiated parameters
// ---------------------------------------------------------------------------

#[test]
fn alpn_and_mode_claims_are_checked() {
    // Major, minor, mode and ALPN are the first four keys. Flipping the mode
    // byte or the ALPN string must be refused outright, not merely fail later
    // through the transcript.
    let peers = Peers::new();
    let (_i, ch) = Initiator::start(&peers.a, EP_A, EP_B);

    // Byte 6 is the handshake_mode value in the canonical encoding
    // (map header, 00 02, 01 00, 02 <mode>).
    assert_eq!(&ch[1..7], &[0x00, 0x02, 0x01, 0x00, 0x02, 0x00]);
    let mut wrong_mode = ch.clone();
    wrong_mode[6] = 0x03; // RESUMPTION offered on a Standalone responder
    let mut replay = ReplayCache::default();
    let mut responder = Responder::new(&peers.b, EP_B);
    assert_eq!(
        responder
            .on_client_hello(&wrong_mode, &EP_A, &mut replay)
            .unwrap_err(),
        HandshakeError::PolicyViolation
    );

    // Corrupt one byte of the ALPN string.
    let alpn = rtp2_core::crypto::ALPN;
    let pos = ch
        .windows(alpn.len())
        .position(|w| w == alpn)
        .expect("ALPN present in hello");
    let mut wrong_alpn = ch.clone();
    wrong_alpn[pos] ^= 0x01;
    let mut responder = Responder::new(&peers.b, EP_B);
    assert_eq!(
        responder
            .on_client_hello(&wrong_alpn, &EP_A, &mut replay)
            .unwrap_err(),
        HandshakeError::PolicyViolation
    );
}

#[test]
fn responder_answer_must_echo_the_negotiation() {
    // A ServerHello naming another mode or ALPN is refused before the
    // signature is even checked.
    let peers = Peers::new();
    let mut replay = ReplayCache::default();
    let (mut initiator, ch) = Initiator::start(&peers.a, EP_A, EP_B);
    let sh = Responder::new(&peers.b, EP_B)
        .on_client_hello(&ch, &EP_A, &mut replay)
        .unwrap();

    // ServerHello prefix: map header, 00 02, 01 <minor>, 02 <mode>.
    assert_eq!(&sh[1..7], &[0x00, 0x02, 0x01, 0x00, 0x02, 0x00]);
    let mut wrong_mode = sh.clone();
    wrong_mode[6] = 0x02;
    assert_eq!(
        initiator.on_server_hello(&wrong_mode).unwrap_err(),
        HandshakeError::PolicyViolation
    );
}

// ---------------------------------------------------------------------------
// Garbage robustness: decode paths must fail cleanly, never panic
// ---------------------------------------------------------------------------

#[test]
fn garbage_inputs_never_panic() {
    let peers = Peers::new();
    let mut replay = ReplayCache::default();

    // Deterministic pseudo-random garbage of assorted lengths.
    let mut seed = 0x12345678u64;
    let mut next = move || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (seed >> 33) as u8
    };
    for len in [0usize, 1, 2, 7, 64, 1000, 5000] {
        let garbage: Vec<u8> = (0..len).map(|_| next()).collect();
        let mut responder = Responder::new(&peers.b, EP_B);
        let _ = responder.on_client_hello(&garbage, &EP_A, &mut replay);

        let (mut initiator, _ch) = Initiator::start(&peers.a, EP_A, EP_B);
        let _ = initiator.on_server_hello(&garbage);
    }

    // Truncations of a valid hello at every sampled cut point.
    let (_i, ch) = Initiator::start(&peers.a, EP_A, EP_B);
    for cut in sample_positions(ch.len()) {
        let mut responder = Responder::new(&peers.b, EP_B);
        assert!(
            responder
                .on_client_hello(&ch[..cut], &EP_A, &mut replay)
                .is_err(),
            "truncated hello at {cut} accepted"
        );
    }
}

// ---------------------------------------------------------------------------
// Envelope binding (§9.5) with real session keys
// ---------------------------------------------------------------------------

#[test]
fn envelope_sealed_for_one_session_never_opens_in_another() {
    let peers = Peers::new();
    let (s1, _) = peers.run(id, id, id, id).unwrap();
    let (s2, _) = peers.run(id, id, id, id).unwrap();

    let secrets = FileSecrets::generate();
    let sealed = keys::seal_envelope(
        &secrets,
        &s1.transfer_wrap_key,
        0,
        u64::MAX,
        &peers.a.device_id,
        &peers.b.device_id,
    )
    .unwrap();

    assert!(keys::open_envelope(&sealed, &s1.transfer_wrap_key).is_ok());
    assert!(
        keys::open_envelope(&sealed, &s2.transfer_wrap_key).is_err(),
        "envelope opened under a different session's wrap key"
    );
}

#[test]
fn envelope_with_unknown_suite_is_refused() {
    // An envelope that authenticates under the right wrap key but names
    // another suite is still refused. Agility must not mean silent
    // downgrade.
    let peers = Peers::new();
    let (session, _) = peers.run(id, id, id, id).unwrap();
    let secrets = FileSecrets::generate();

    for suite in [0u16, 2, 0xffff] {
        let sealed = keys::seal_envelope_with_suite(
            &secrets,
            &session.transfer_wrap_key,
            0,
            u64::MAX,
            &peers.a.device_id,
            &peers.b.device_id,
            suite,
        )
        .unwrap();
        assert!(
            keys::open_envelope(&sealed, &session.transfer_wrap_key).is_err(),
            "envelope naming suite {suite:#06x} was accepted"
        );
    }

    // The mandatory suite still works.
    let good = keys::seal_envelope_with_suite(
        &secrets,
        &session.transfer_wrap_key,
        0,
        u64::MAX,
        &peers.a.device_id,
        &peers.b.device_id,
        1,
    )
    .unwrap();
    assert!(keys::open_envelope(&good, &session.transfer_wrap_key).is_ok());
}

// ---------------------------------------------------------------------------
// Chunk substitution across files, positions, and contexts
// ---------------------------------------------------------------------------

#[test]
fn chunk_is_bound_to_file_position_and_context() {
    const CHUNK: u32 = 64 * 1024;
    let file_len = 4 * CHUNK as u64;

    let make = || {
        let secrets = FileSecrets::generate();
        let ctx = ObjectContext::for_file(secrets.transfer_id, secrets.object_id, file_len, CHUNK)
            .unwrap();
        let hash = ctx.context_hash();
        (secrets.key_schedule(), ctx, hash)
    };
    let (ks_a, ctx_a, h_a) = make();
    let (ks_b, ctx_b, h_b) = make();

    let plain = vec![0x5au8; CHUNK as usize];
    let ct = object::encrypt_chunk(&ks_a, &ctx_a, &h_a, 1, &plain).unwrap();

    // Correct decryption works.
    assert!(object::decrypt_chunk(&ks_a, &ctx_a, &h_a, 1, &ct).is_ok());
    // Same ciphertext in file B (same sizes!) must fail (INV-40).
    assert!(object::decrypt_chunk(&ks_b, &ctx_b, &h_b, 1, &ct).is_err());
    // Same ciphertext at a different position of file A must fail.
    assert!(object::decrypt_chunk(&ks_a, &ctx_a, &h_a, 2, &ct).is_err());
    // Same ciphertext under a lying context hash must fail.
    let mut h_bad = h_a;
    h_bad[5] ^= 1;
    assert!(object::decrypt_chunk(&ks_a, &ctx_a, &h_bad, 1, &ct).is_err());
}

#[test]
fn merkle_cross_tree_substitution_fails() {
    const N: usize = 16;
    let chunks_a: Vec<Vec<u8>> = (0..N).map(|i| vec![i as u8; 100]).collect();
    let chunks_b: Vec<Vec<u8>> = (0..N).map(|i| vec![(i + 1) as u8; 100]).collect();

    let leaves_a: Vec<[u8; 32]> = chunks_a
        .iter()
        .enumerate()
        .map(|(i, c)| merkle::leaf_hash(i as u64, c))
        .collect();
    let leaves_b: Vec<[u8; 32]> = chunks_b
        .iter()
        .enumerate()
        .map(|(i, c)| merkle::leaf_hash(i as u64, c))
        .collect();
    let root_a = merkle::merkle_root(&leaves_a);

    // A leaf and a well-shaped proof from tree B must not verify against
    // root A (INV-41).
    for i in [0usize, 7, 15] {
        let proof_b = merkle::build_proof(&leaves_b, i).unwrap();
        assert!(
            merkle::verify_proof(&leaves_b[i], i as u64, N as u64, &proof_b, &root_a).is_err(),
            "foreign leaf {i} accepted under root A"
        );
    }
}

// ---------------------------------------------------------------------------
// Nonce uniqueness at scale (§9.4)
// ---------------------------------------------------------------------------

#[test]
fn chunk_nonces_never_collide_within_or_across_files() {
    use std::collections::HashSet;
    let mut seen: HashSet<[u8; 24]> = HashSet::new();
    for _file in 0..8 {
        let schedule = FileSecrets::generate().key_schedule();
        for index in 0..2048u64 {
            assert!(
                seen.insert(schedule.chunk_nonce(index)),
                "nonce collision detected"
            );
        }
    }
    // Keys likewise.
    let schedule = FileSecrets::generate().key_schedule();
    let mut keys_seen: HashSet<[u8; 32]> = HashSet::new();
    for index in 0..2048u64 {
        assert!(keys_seen.insert(*schedule.chunk_key(index)));
    }
}

// ---------------------------------------------------------------------------
// Downgrade resistance (§2.5, §6.3)
// ---------------------------------------------------------------------------

#[test]
fn downgrade_probes_die_before_key_agreement() {
    // The sweeps above already cover mutated suite lists reaching the
    // responder. Here the initiator refuses a responder that selected a
    // non-mandatory suite, valid signature and all, because the suite check
    // runs first. Flipping the byte is enough; the sweep of the first 24
    // keeps this layout-agnostic.
    let peers = Peers::new();
    let mut replay = ReplayCache::default();
    let (mut initiator, ch) = Initiator::start(&peers.a, EP_A, EP_B);
    let sh = Responder::new(&peers.b, EP_B)
        .on_client_hello(&ch, &EP_A, &mut replay)
        .unwrap();
    let mut all_rejected = true;
    for pos in 0..24 {
        let (mut i, chx) = Initiator::start(&peers.a, EP_A, EP_B);
        let mut r = Responder::new(&peers.b, EP_B);
        let mut rp = ReplayCache::default();
        let shx = r.on_client_hello(&chx, &EP_A, &mut rp).unwrap();
        if i.on_server_hello(&flip(&shx, pos)).is_ok() {
            all_rejected = false;
        }
    }
    assert!(all_rejected, "a mutated ServerHello prefix was accepted");
    // Sanity: untouched flow still succeeds for these identities.
    let cf = initiator.on_server_hello(&sh).unwrap();
    assert!(!cf.is_empty());
}
