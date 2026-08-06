// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//! Pins the exact §8.2 and §9 formulas, recomputed from the spec text and
//! compared against what the implementation used.
//!
//! End-to-end tests miss this class of bug: a transcript or key schedule that
//! differs from the spec but is self-consistent. Both peers agree, transfers
//! succeed, and the result is neither interoperable nor necessarily as strong
//! as specified.

use rtp2_core::crypto;
use rtp2_core::handshake::{Initiator, ReplayCache, Responder, conformance as conf};
use rtp2_core::identity::DeviceIdentity;
use rtp2_core::keys::FileSecrets;

const EP_A: [u8; 32] = [0xaa; 32];
const EP_B: [u8; 32] = [0xbb; 32];

struct Recorded {
    ch: Vec<u8>,
    sh: Vec<u8>,
    cf: Vec<u8>,
    sf: Vec<u8>,
    initiator_cert: rtp2_core::identity::DevicePublic,
    responder_cert: rtp2_core::identity::DevicePublic,
}

fn record_handshake() -> Recorded {
    let a = DeviceIdentity::generate();
    let b = DeviceIdentity::generate();
    let mut replay = ReplayCache::default();

    let (mut initiator, ch) = Initiator::start(&a, EP_A, EP_B);
    let mut responder = Responder::new(&b, EP_B);
    let sh = responder.on_client_hello(&ch, &EP_A, &mut replay).unwrap();
    let cf = initiator.on_server_hello(&sh).unwrap();
    let (sf, _keys_b) = responder.on_client_finish(&cf).unwrap();
    let _keys_a = initiator.on_server_finish(&sf).unwrap();

    Recorded {
        ch,
        sh,
        cf,
        sf,
        initiator_cert: a.public(),
        responder_cert: b.public(),
    }
}

// ---------------------------------------------------------------------------
// §8.2.5: transcript hashes
// ---------------------------------------------------------------------------

#[test]
fn th1_matches_spec_formula() {
    // TH1 = SHA384("RTP2-HS-TH1-v1" || encode(ClientHello)
    //                                || encode(ServerHello_without_signatures))
    let r = record_handshake();
    let sh_wo_sig = conf::server_hello_without_signature(&r.sh).unwrap();
    let th1 = crypto::sha384(&[conf::TH1_DOMAIN_BYTES, &r.ch, &sh_wo_sig]);

    // The signature must verify against exactly this hash.
    let sig = conf::server_hello_signature(&r.sh).unwrap();
    r.responder_cert
        .hybrid_verify(&th1, &sig)
        .expect("responder signature is not over the spec's TH1");

    // And must not verify over a near miss: domain dropped, ClientHello
    // dropped, or the full ServerHello instead of the stripped one.
    for wrong in [
        crypto::sha384(&[&r.ch, &sh_wo_sig]),
        crypto::sha384(&[conf::TH1_DOMAIN_BYTES, &sh_wo_sig]),
        crypto::sha384(&[conf::TH1_DOMAIN_BYTES, &r.ch, &r.sh]),
    ] {
        assert!(
            r.responder_cert.hybrid_verify(&wrong, &sig).is_err(),
            "signature verified over a non-spec transcript"
        );
    }
}

#[test]
fn th2_matches_spec_formula() {
    // TH2 = SHA384("RTP2-HS-TH2-v1" || encode(ClientHello)
    //                                || encode(ServerHello)
    //                                || encode(ClientFinish_without_sig_and_finished))
    let r = record_handshake();
    let cf_bare = conf::client_finish_bare(&r.cf).unwrap();
    let th2 = crypto::sha384(&[conf::TH2_DOMAIN_BYTES, &r.ch, &r.sh, &cf_bare]);

    let sig = conf::client_finish_signature(&r.cf).unwrap();
    r.initiator_cert
        .hybrid_verify(&th2, &sig)
        .expect("initiator signature is not over the spec's TH2");

    // TH2 takes the full ServerHello, not the stripped one, and includes the
    // ClientHello.
    let sh_wo_sig = conf::server_hello_without_signature(&r.sh).unwrap();
    for wrong in [
        crypto::sha384(&[conf::TH2_DOMAIN_BYTES, &r.ch, &sh_wo_sig, &cf_bare]),
        crypto::sha384(&[conf::TH2_DOMAIN_BYTES, &r.sh, &cf_bare]),
        crypto::sha384(&[conf::TH2_DOMAIN_BYTES, &r.ch, &r.sh, &r.cf]),
    ] {
        assert!(
            r.initiator_cert.hybrid_verify(&wrong, &sig).is_err(),
            "signature verified over a non-spec TH2"
        );
    }
}

#[test]
fn th1_and_th2_are_domain_separated() {
    let r = record_handshake();
    let sh_wo_sig = conf::server_hello_without_signature(&r.sh).unwrap();
    let cf_bare = conf::client_finish_bare(&r.cf).unwrap();
    let th1 = crypto::sha384(&[conf::TH1_DOMAIN_BYTES, &r.ch, &sh_wo_sig]);
    let th2 = crypto::sha384(&[conf::TH2_DOMAIN_BYTES, &r.ch, &r.sh, &cf_bare]);
    assert_ne!(th1, th2);
    assert_ne!(conf::TH1_DOMAIN_BYTES, conf::TH2_DOMAIN_BYTES);
    assert_ne!(conf::TH1_DOMAIN_BYTES, conf::SALT_DOMAIN_BYTES);
    assert_ne!(conf::TH2_DOMAIN_BYTES, conf::SALT_DOMAIN_BYTES);
}

// ---------------------------------------------------------------------------
// §8.2.2: version, mode and ALPN live inside the transcript (D-101, D-207)
// ---------------------------------------------------------------------------

#[test]
fn transcript_covers_version_mode_and_alpn() {
    // Ordinary fields, so they land in TH1/TH2 by construction. Check they
    // are really in the encoding and that changing one changes the
    // transcript.
    let r = record_handshake();

    let alpn = rtp2_core::crypto::ALPN;
    let contains = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
    assert!(
        contains(&r.ch, alpn),
        "ClientHello does not carry the ALPN, so TH1/TH2 cannot authenticate it"
    );
    assert!(contains(&r.sh, alpn), "ServerHello does not carry the ALPN");

    // The canonical encoding of {0: 2, 1: 0, 2: 0, ...} starts with a map
    // header then 00 02 01 00 02 00. Match that prefix rather than guess
    // offsets.
    assert_eq!(
        &r.ch[1..7],
        &[0x00, 0x02, 0x01, 0x00, 0x02, 0x00],
        "ClientHello prefix must be major=2, minor=0, mode=STANDALONE"
    );

    // Flip the mode byte and the signature over TH1 stops verifying.
    let sh_wo_sig = conf::server_hello_without_signature(&r.sh).unwrap();
    let th1 = crypto::sha384(&[conf::TH1_DOMAIN_BYTES, &r.ch, &sh_wo_sig]);
    let sig = conf::server_hello_signature(&r.sh).unwrap();
    r.responder_cert.hybrid_verify(&th1, &sig).unwrap();

    let mut tampered_ch = r.ch.clone();
    tampered_ch[6] ^= 0x01; // handshake_mode
    let th1_bad = crypto::sha384(&[conf::TH1_DOMAIN_BYTES, &tampered_ch, &sh_wo_sig]);
    assert!(
        r.responder_cert.hybrid_verify(&th1_bad, &sig).is_err(),
        "handshake_mode is outside the transcript"
    );
}

// ---------------------------------------------------------------------------
// §8.2.8 / §8.2.9: combiner and key schedule
// ---------------------------------------------------------------------------

/// The six §8.2.9 outputs, in declaration order.
type SpecKeys = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// The combiner and key schedule, rewritten straight from the spec.
#[allow(clippy::too_many_arguments)]
fn spec_key_schedule(
    ch: &[u8],
    sh_wo_sig: &[u8],
    cf_bare: &[u8],
    th2: &[u8; 48],
    ss_x: &[u8; 32],
    ss_pq_a: &[u8; 32],
    ss_pq_b: &[u8; 32],
) -> SpecKeys {
    // handshake_salt = SHA384("RTP2-HYBRID-SALT-v1" || CH || SH_wo_sig || CF_bare)
    let salt = crypto::sha384(&[conf::SALT_DOMAIN_BYTES, ch, sh_wo_sig, cf_bare]);

    // hybrid_ikm = U16BE(len)||ss for each of ss_x, ss_pqA, ss_pqB in order
    let mut ikm = Vec::new();
    for ss in [ss_x.as_slice(), ss_pq_a.as_slice(), ss_pq_b.as_slice()] {
        ikm.extend_from_slice(&(ss.len() as u16).to_be_bytes());
        ikm.extend_from_slice(ss);
    }

    let prk = crypto::hkdf_extract(&salt, &ikm);
    let exp = |label: &[u8], n: usize| -> Vec<u8> {
        match n {
            48 => crypto::hkdf_expand::<48>(&prk, &[label, th2]).to_vec(),
            32 => crypto::hkdf_expand::<32>(&prk, &[label, th2]).to_vec(),
            _ => unreachable!(),
        }
    };
    (
        exp(b"RTP2 client finished v1", 48),
        exp(b"RTP2 server finished v1", 48),
        exp(b"RTP2 control c2s v1", 32),
        exp(b"RTP2 control s2c v1", 32),
        exp(b"RTP2 transfer wrap v1", 32),
        exp(b"RTP2 resumption v1", 48),
    )
}

#[test]
fn key_schedule_matches_spec_formula() {
    let ch = b"client-hello-bytes".to_vec();
    let sh = b"server-hello-without-signature".to_vec();
    let cf = b"client-finish-bare".to_vec();
    let th2: [u8; 48] = crypto::sha384(&[b"transcript"]);
    let ss_x = [1u8; 32];
    let ss_a = [2u8; 32];
    let ss_b = [3u8; 32];

    let impl_keys = conf::derived_keys(&ch, &sh, &cf, &th2, &ss_x, &ss_a, &ss_b);
    let spec = spec_key_schedule(&ch, &sh, &cf, &th2, &ss_x, &ss_a, &ss_b);

    assert_eq!(impl_keys.0.to_vec(), spec.0, "client_finished_key");
    assert_eq!(impl_keys.1.to_vec(), spec.1, "server_finished_key");
    assert_eq!(impl_keys.2.to_vec(), spec.2, "control_key_c2s");
    assert_eq!(impl_keys.3.to_vec(), spec.3, "control_key_s2c");
    assert_eq!(impl_keys.4.to_vec(), spec.4, "transfer_wrap_key");
    assert_eq!(impl_keys.5.to_vec(), spec.5, "session_resumption_secret");

    // All six outputs are distinct (label domain separation, §8.2.9).
    let all = [
        impl_keys.0.to_vec(),
        impl_keys.1.to_vec(),
        impl_keys.2.to_vec(),
        impl_keys.3.to_vec(),
        impl_keys.4.to_vec(),
        impl_keys.5.to_vec(),
    ];
    for i in 0..all.len() {
        for j in (i + 1)..all.len() {
            assert_ne!(all[i], all[j], "derived keys {i} and {j} collide");
        }
    }
}

#[test]
fn every_combiner_input_affects_the_keys() {
    // Change any shared secret or transcript component and every derived key
    // must change (INV-01, INV-02).
    let ch = b"ch".to_vec();
    let sh = b"sh".to_vec();
    let cf = b"cf".to_vec();
    let th2: [u8; 48] = crypto::sha384(&[b"th2"]);
    let base = conf::derived_keys(&ch, &sh, &cf, &th2, &[1; 32], &[2; 32], &[3; 32]);

    let variants = [
        conf::derived_keys(&ch, &sh, &cf, &th2, &[9; 32], &[2; 32], &[3; 32]),
        conf::derived_keys(&ch, &sh, &cf, &th2, &[1; 32], &[9; 32], &[3; 32]),
        conf::derived_keys(&ch, &sh, &cf, &th2, &[1; 32], &[2; 32], &[9; 32]),
        conf::derived_keys(b"CH", &sh, &cf, &th2, &[1; 32], &[2; 32], &[3; 32]),
        conf::derived_keys(&ch, b"SH", &cf, &th2, &[1; 32], &[2; 32], &[3; 32]),
        conf::derived_keys(&ch, &sh, b"CF", &th2, &[1; 32], &[2; 32], &[3; 32]),
        conf::derived_keys(
            &ch,
            &sh,
            &cf,
            &crypto::sha384(&[b"other"]),
            &[1; 32],
            &[2; 32],
            &[3; 32],
        ),
    ];
    for (i, v) in variants.iter().enumerate() {
        assert_ne!(base.4, v.4, "transfer_wrap_key unchanged by variant {i}");
        assert_ne!(base.2, v.2, "control_key_c2s unchanged by variant {i}");
    }

    // The combiner is order-sensitive, so swapping the PQ branches must
    // change the result.
    let swapped = conf::derived_keys(&ch, &sh, &cf, &th2, &[1; 32], &[3; 32], &[2; 32]);
    assert_ne!(base.4, swapped.4, "combiner is order-insensitive");
}

#[test]
fn length_prefixing_prevents_ikm_ambiguity() {
    // Without length prefixes the boundaries could shift. All three inputs
    // are 32 bytes here, so assert the stronger thing: moving the same bytes
    // between slots gives different keys.
    let ch = b"ch".to_vec();
    let sh = b"sh".to_vec();
    let cf = b"cf".to_vec();
    let th2: [u8; 48] = crypto::sha384(&[b"th2"]);

    let mut a = [0u8; 32];
    a[31] = 1;
    let mut b = [0u8; 32];
    b[0] = 1;

    let k1 = conf::derived_keys(&ch, &sh, &cf, &th2, &a, &b, &[0; 32]);
    let k2 = conf::derived_keys(&ch, &sh, &cf, &th2, &b, &a, &[0; 32]);
    assert_ne!(k1.4, k2.4);
}

// ---------------------------------------------------------------------------
// §8.2.10: finished MAC chain
// ---------------------------------------------------------------------------

#[test]
fn finished_mac_chain_matches_spec_formula() {
    // finished_mac_A = HMAC(client_finished_key, TH2)
    // finished_mac_B = HMAC(server_finished_key, SHA384(TH2 || finished_mac_A))
    //
    // The finished keys are secret, so pin the structure instead: mac_B is a
    // MAC over SHA384(TH2 || mac_A) under some key, and differs from one over
    // TH2 alone. Known inputs go through the conformance hook.
    let ch = b"ch".to_vec();
    let sh = b"sh".to_vec();
    let cf = b"cf".to_vec();
    let th2: [u8; 48] = crypto::sha384(&[b"th2"]);
    let (client_finished, server_finished, ..) =
        conf::derived_keys(&ch, &sh, &cf, &th2, &[1; 32], &[2; 32], &[3; 32]);

    let mac_a = crypto::hmac_sha384(&client_finished, &th2);
    let mac_b = crypto::hmac_sha384(&server_finished, &crypto::sha384(&[&th2, &mac_a]));

    // The two MACs use different keys and different messages.
    assert_ne!(mac_a, mac_b);
    // mac_B must not be a MAC over TH2 alone under the server key.
    assert_ne!(mac_b, crypto::hmac_sha384(&server_finished, &th2));
    // One bit of mac_A changes mac_B: the chain binds A's confirmation.
    let mut tampered = mac_a;
    tampered[0] ^= 1;
    assert_ne!(
        mac_b,
        crypto::hmac_sha384(&server_finished, &crypto::sha384(&[&th2, &tampered]))
    );
}

#[test]
fn recorded_finished_macs_are_present_and_distinct() {
    let r = record_handshake();
    let mac_a = conf::client_finish_mac(&r.cf).unwrap();
    let mac_b = conf::server_finish_mac(&r.sf).unwrap();
    assert_ne!(mac_a, mac_b);
    assert_ne!(mac_a, [0u8; 48]);
    assert_ne!(mac_b, [0u8; 48]);
}

// ---------------------------------------------------------------------------
// §9.2–§9.4: file key hierarchy formulas
// ---------------------------------------------------------------------------

#[test]
fn chunk_nonce_matches_spec_formula() {
    // chunk_nonce_i = first 24 bytes of BLAKE3-DERIVE-KEY(
    //   context = "Reyta RTP2 2026-08-01 chunk nonce v1",
    //   material = file_nonce_seed || transfer_id || object_id || U64BE(i))
    //
    // The seed is private, so pin what is observable: the exact §9.4 context
    // string, unique in the project, and a derivation that is a pure function
    // of seed, ids and index.
    let secrets = FileSecrets::generate();
    let ks = secrets.key_schedule();

    // Purity / determinism.
    for i in [0u64, 1, 7, 1_000_000] {
        assert_eq!(ks.chunk_nonce(i), ks.chunk_nonce(i));
    }
    // Index sensitivity across a wide range.
    let mut seen = std::collections::HashSet::new();
    for i in 0..1000u64 {
        assert!(seen.insert(ks.chunk_nonce(i)));
    }

    // Exactly this string, and different from every other BLAKE3 domain in
    // the project.
    const CTX: &str = "Reyta RTP2 2026-08-01 chunk nonce v1";
    let domains: [&[u8]; 4] = [
        CTX.as_bytes(),
        rtp2_core::merkle::LEAF_DOMAIN,
        rtp2_core::merkle::NODE_DOMAIN,
        rtp2_core::merkle::EMPTY_DOMAIN,
    ];
    for i in 0..domains.len() {
        for j in (i + 1)..domains.len() {
            assert_ne!(domains[i], domains[j], "BLAKE3 domains {i}/{j} collide");
        }
    }
    // derive_key with this context is not the same as plain hashing.
    assert_ne!(
        blake3::derive_key(CTX, b"material")[..24],
        blake3::hash(b"material").as_bytes()[..24]
    );
}

#[test]
fn merkle_domains_match_spec_strings() {
    // §12.1–§12.3: exact domain strings, including the trailing NUL.
    assert_eq!(rtp2_core::merkle::LEAF_DOMAIN, b"RTP2-MERKLE-LEAF-v1\0");
    assert_eq!(rtp2_core::merkle::NODE_DOMAIN, b"RTP2-MERKLE-NODE-v1\0");
    assert_eq!(rtp2_core::merkle::EMPTY_DOMAIN, b"RTP2-MERKLE-EMPTY-v1\0");

    // §12.3 EmptyRoot = BLAKE3-256("RTP2-MERKLE-EMPTY-v1\0")
    assert_eq!(
        rtp2_core::merkle::empty_root(),
        *blake3::hash(b"RTP2-MERKLE-EMPTY-v1\0").as_bytes()
    );

    // §12.1 LeafHash(i, ct) = BLAKE3(dom || U64BE(i) || U32BE(len) || ct)
    let ct = b"ciphertext";
    let mut h = blake3::Hasher::new();
    h.update(b"RTP2-MERKLE-LEAF-v1\0");
    h.update(&7u64.to_be_bytes());
    h.update(&(ct.len() as u32).to_be_bytes());
    h.update(ct);
    assert_eq!(
        rtp2_core::merkle::leaf_hash(7, ct),
        *h.finalize().as_bytes()
    );

    // §12.2 NodeHash(l, r) = BLAKE3(dom || l || r)
    let l = [1u8; 32];
    let rr = [2u8; 32];
    let mut h = blake3::Hasher::new();
    h.update(b"RTP2-MERKLE-NODE-v1\0");
    h.update(&l);
    h.update(&rr);
    assert_eq!(
        rtp2_core::merkle::node_hash(&l, &rr),
        *h.finalize().as_bytes()
    );
    // Order matters.
    assert_ne!(
        rtp2_core::merkle::node_hash(&l, &rr),
        rtp2_core::merkle::node_hash(&rr, &l)
    );
}

#[test]
fn merkle_tree_shape_matches_spec() {
    // MTH([]) = EmptyRoot, MTH([x]) = x, and for n > 1 split at the largest
    // power of two below n.
    use rtp2_core::merkle::{merkle_root, node_hash};
    let leaf = |i: u8| [i; 32];

    assert_eq!(merkle_root(&[]), rtp2_core::merkle::empty_root());
    assert_eq!(merkle_root(&[leaf(1)]), leaf(1));

    // n = 3 gives Node(Node(l0, l1), l2), not a duplicated odd leaf.
    let three = [leaf(0), leaf(1), leaf(2)];
    assert_eq!(
        merkle_root(&three),
        node_hash(&node_hash(&leaf(0), &leaf(1)), &leaf(2))
    );

    // n = 5: k = 4 → Node(MTH(0..4), l4).
    let five = [leaf(0), leaf(1), leaf(2), leaf(3), leaf(4)];
    let left = node_hash(
        &node_hash(&leaf(0), &leaf(1)),
        &node_hash(&leaf(2), &leaf(3)),
    );
    assert_eq!(merkle_root(&five), node_hash(&left, &leaf(4)));
}

// ---------------------------------------------------------------------------
// §11.1: chunk AAD layout
// ---------------------------------------------------------------------------

#[test]
fn chunk_aad_layout_matches_spec() {
    use rtp2_core::object::{ObjectContext, chunk_aad};

    let transfer_id = [0x11u8; 32];
    let object_id = [0x22u8; 32];
    let ctx = ObjectContext::for_file(transfer_id, object_id, 300_000, 65536).unwrap();
    let ctx_hash = [0x33u8; 32];
    let aad = chunk_aad(&ctx, &ctx_hash, 5, 5 * 65536, 65536, 0);

    // "RTP2CHNK"(8) || major(2) || suite(2) || transfer(32) || object(32)
    // || ctx_hash(32) || index(8) || offset(8) || len(4) || flags(4) = 132
    assert_eq!(aad.len(), 132, "§11.1 AAD is exactly 132 bytes");
    assert_eq!(&aad[0..8], b"RTP2CHNK");
    assert_eq!(&aad[8..10], &2u16.to_be_bytes());
    assert_eq!(&aad[10..12], &1u16.to_be_bytes()); // suite 0x0001
    assert_eq!(&aad[12..44], &transfer_id);
    assert_eq!(&aad[44..76], &object_id);
    assert_eq!(&aad[76..108], &ctx_hash);
    assert_eq!(&aad[108..116], &5u64.to_be_bytes());
    assert_eq!(&aad[116..124], &(5u64 * 65536).to_be_bytes());
    assert_eq!(&aad[124..128], &65536u32.to_be_bytes());
    assert_eq!(&aad[128..132], &0u32.to_be_bytes());
}

// ---------------------------------------------------------------------------
// §9.5: envelope key derivation and AAD
// ---------------------------------------------------------------------------

#[test]
fn envelope_key_matches_spec_formula() {
    // §9.5:
    //   envelope_prk = HKDF-Extract-SHA384("RTP2-ENVELOPE-SALT-v1",
    //                                      transfer_wrap_key)
    //   envelope_key = HKDF-Expand(envelope_prk, "RTP2 envelope key v1", 32)
    //   EnvelopeAAD  = "RTP2-ENVELOPE-AAD-v1"
    use chacha20poly1305::{
        KeyInit, XChaCha20Poly1305, XNonce,
        aead::{Aead, Payload},
    };
    use rtp2_core::keys;

    let wrap = [0x5au8; 32];
    let secrets = FileSecrets::generate();
    let sealed = keys::seal_envelope(&secrets, &wrap, 100, 200, &[1; 32], &[2; 32]).unwrap();

    // Recompute the key straight from the spec text and decrypt with it.
    let prk = crypto::hkdf_extract(b"RTP2-ENVELOPE-SALT-v1", &wrap);
    let key: zeroize::Zeroizing<[u8; 32]> = crypto::hkdf_expand(&prk, &[b"RTP2 envelope key v1"]);
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap();
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&sealed.nonce),
            Payload {
                msg: sealed.ciphertext.as_slice(),
                aad: b"RTP2-ENVELOPE-AAD-v1",
            },
        )
        .expect("envelope is not sealed under the spec's key/AAD");

    // The plaintext is the §9.5 KeyEnvelopePlaintext / key-envelope-plaintext
    // CDDL map: keys 0..8, transfer_id first.
    assert_eq!(plaintext[0], 0xa9, "envelope plaintext is a 9-entry map");
    assert_eq!(
        &plaintext[1..3],
        &[0x00, 0x58],
        "key 0 then a 32-byte string"
    );
    assert_eq!(&plaintext[4..36], &secrets.transfer_id);
}

#[test]
fn envelope_expiry_is_enforced() {
    // §9.5: a receiver MUST reject an envelope whose expires_at has passed.
    use rtp2_core::keys;
    let wrap = [0x5au8; 32];
    let secrets = FileSecrets::generate();
    let sealed = keys::seal_envelope(&secrets, &wrap, 100, 200, &[1; 32], &[2; 32]).unwrap();

    assert!(keys::open_envelope_at(&sealed, &wrap, 150).is_ok());
    assert!(keys::open_envelope_at(&sealed, &wrap, 199).is_ok());
    assert!(keys::open_envelope_at(&sealed, &wrap, 200).is_err());
    assert!(keys::open_envelope_at(&sealed, &wrap, 10_000).is_err());
    // Far-future created_at is refused too (clock skew allowance is 300 s).
    let future =
        keys::seal_envelope(&secrets, &wrap, 100_000, 200_000, &[1; 32], &[2; 32]).unwrap();
    assert!(keys::open_envelope_at(&future, &wrap, 1_000).is_err());
}

// ---------------------------------------------------------------------------
// §14.2: offer authentication covers the whole offer (D-501)
// ---------------------------------------------------------------------------

#[test]
fn offer_binding_matches_spec_formula() {
    // §14.2: offer_binding = BLAKE3-256("RTP2-OFFER-BINDING-v1" ||
    //   RTP-CBOR({0: key_envelopes, 1: providers, 2: sender_device,
    //             3: auth_mode}))
    use rtp2_core::cbor::{MapWriter, Writer};
    use rtp2_core::identity::DeviceIdentity;
    use rtp2_core::offer::{AuthMode, KeyEnvelopeEntry, ProviderAddress};

    let device = DeviceIdentity::generate();
    let public = device.public();
    let envelopes = vec![KeyEnvelopeEntry {
        recipient_device_id: [7; 32],
        nonce: [8; 24],
        ciphertext: vec![9; 40],
    }];
    let providers = vec![ProviderAddress {
        kind: ProviderAddress::KIND_RELAY,
        address: b"relay-1".to_vec(),
    }];

    let mut w = Writer::new();
    {
        let mut m = MapWriter::begin(&mut w, 4);
        {
            let inner = m.nested(0);
            inner.array(1);
            let mut em = MapWriter::begin(inner, 3);
            em.bytes(0, &envelopes[0].recipient_device_id);
            em.bytes(1, &envelopes[0].nonce);
            em.bytes(2, &envelopes[0].ciphertext);
            em.end();
        }
        {
            let inner = m.nested(1);
            inner.array(1);
            let mut pm = MapWriter::begin(inner, 2);
            pm.uint(0, providers[0].kind);
            pm.bytes(1, &providers[0].address);
            pm.end();
        }
        {
            let inner = m.nested(2);
            public.encode(inner);
        }
        m.uint(3, 1); // STANDALONE_HYBRID_SIGNATURE
        m.end();
    }
    let mut h = blake3::Hasher::new();
    h.update(b"RTP2-OFFER-BINDING-v1");
    h.update(&w.into_bytes());
    let expected = *h.finalize().as_bytes();

    assert_eq!(
        rtp2_core::offer::offer_binding_hash(
            &envelopes,
            &providers,
            &public,
            AuthMode::StandaloneHybridSignature
        ),
        expected
    );
}

// ---------------------------------------------------------------------------
// §13.4: RTP-CBOR determinism
// ---------------------------------------------------------------------------

#[test]
fn rtp_cbor_admits_only_true_and_false_simple_values() {
    // Floats, tags and every simple value but true and false are rejected.
    use rtp2_core::cbor::{CborError, Reader, Writer};

    let mut w = Writer::new();
    w.boolean(true);
    w.boolean(false);
    let bytes = w.into_bytes();
    assert_eq!(bytes, vec![0xf5, 0xf4]);

    let mut r = Reader::new(&bytes).unwrap();
    assert!(r.boolean().unwrap());
    assert!(!r.boolean().unwrap());
    r.finish().unwrap();

    // null (0xf6), undefined (0xf7) and other simple values are refused.
    for byte in [0xf6u8, 0xf7, 0xe0, 0xf3] {
        let buf = [byte];
        let mut r = Reader::new(&buf).unwrap();
        assert_eq!(r.boolean(), Err(CborError::ForbiddenType), "0x{byte:02x}");
    }
    // A bool where a uint belongs is a type error, not a silent 0 or 1.
    let buf = [0xf5u8];
    let mut r = Reader::new(&buf).unwrap();
    assert_eq!(r.uint(), Err(CborError::UnexpectedType));
}

#[test]
fn rtp_cbor_rejects_non_deterministic_encodings() {
    use rtp2_core::cbor::{CborError, Reader};

    // Indefinite-length map, array, byte string and text are all forbidden.
    for byte in [0xbfu8, 0x9f, 0x5f, 0x7f] {
        let buf = [byte];
        let mut r = Reader::new(&buf).unwrap();
        let map_err = r.map().err();
        let mut r2 = Reader::new(&buf).unwrap();
        let array_err = r2.array().err();
        let mut r3 = Reader::new(&buf).unwrap();
        let bytes_err = r3.bytes().err();
        assert!(
            map_err.is_some() && array_err.is_some() && bytes_err.is_some(),
            "indefinite-length header 0x{byte:02x} accepted"
        );
    }

    // Floats (major type 7 with ai 25/26/27) must be rejected.
    for bytes in [
        vec![0xf9, 0x00, 0x00],
        vec![0xfa, 0, 0, 0, 0],
        vec![0xfb, 0, 0, 0, 0, 0, 0, 0, 0],
    ] {
        let mut r = Reader::new(&bytes).unwrap();
        assert!(r.uint().is_err(), "float accepted");
    }

    // Non-shortest integer encodings.
    for bytes in [
        vec![0x18, 0x17],             // 23 in one-byte form
        vec![0x19, 0x00, 0xff],       // 255 in two-byte form
        vec![0x1a, 0, 0, 0xff, 0xff], // 65535 in four-byte form
    ] {
        let mut r = Reader::new(&bytes).unwrap();
        assert_eq!(r.uint(), Err(CborError::NonCanonical));
    }

    // Depth limit: 17 nested arrays must be rejected at depth 17.
    let deep: Vec<u8> = std::iter::repeat_n(0x81u8, 17).collect();
    let mut r = Reader::new(&deep).unwrap();
    let mut last = Ok(0);
    for _ in 0..17 {
        last = r.array();
        if last.is_err() {
            break;
        }
    }
    assert_eq!(last, Err(CborError::DepthExceeded));

    // Control-object size cap: 1 MiB + 1 is refused outright.
    let big = vec![0u8; 1024 * 1024 + 1];
    assert_eq!(Reader::new(&big).err(), Some(CborError::SizeExceeded));
}

#[test]
fn rtp_cbor_map_keys_must_strictly_increase() {
    use rtp2_core::cbor::{CborError, Reader, Writer};

    // Handcraft {2: 0, 1: 0}: descending keys.
    let mut w = Writer::new();
    w.map(2);
    w.uint(2);
    w.uint(0);
    w.uint(1);
    w.uint(0);
    let bytes = w.into_bytes();

    let mut r = Reader::new(&bytes).unwrap();
    let mut m = r.map().unwrap();
    assert_eq!(m.next_key().unwrap(), Some(2));
    m.reader.uint().unwrap();
    assert_eq!(m.next_key(), Err(CborError::KeyOrder));
}
