// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//! Known-answer tests for every primitive in the mandatory suite.
//!
//! Where the vectors come from: SHA-384 from FIPS 180-4, HMAC-SHA-384 from
//! RFC 4231, HKDF-SHA-384 computed independently, X25519 from RFC 7748,
//! Ed25519 from RFC 8032, BLAKE3 from the official empty-input vector.
//!
//! ML-KEM-768 and ML-DSA-65 have no fixed vectors here. Instead the portable
//! and SIMD paths run from identical randomness and must agree, which is two
//! independent implementations checking each other.

use rtp2_core::crypto;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// ---------------------------------------------------------------------------
// SHA-384
// ---------------------------------------------------------------------------

#[test]
fn sha384_known_answers() {
    assert_eq!(
        crypto::sha384(&[b"abc"]).to_vec(),
        hex(
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        )
    );
    assert_eq!(
        crypto::sha384(&[]).to_vec(),
        hex(
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        )
    );
    // Where the input is split must not change the digest.
    assert_eq!(crypto::sha384(&[b"ab", b"c"]), crypto::sha384(&[b"abc"]));
}

// ---------------------------------------------------------------------------
// HMAC-SHA-384 (RFC 4231)
// ---------------------------------------------------------------------------

#[test]
fn hmac_sha384_rfc4231() {
    // Test Case 1.
    assert_eq!(
        crypto::hmac_sha384(&[0x0b; 20], b"Hi There").to_vec(),
        hex(
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"
        )
    );
    // Test Case 2.
    assert_eq!(
        crypto::hmac_sha384(b"Jefe", b"what do ya want for nothing?").to_vec(),
        hex(
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"
        )
    );
}

// ---------------------------------------------------------------------------
// HKDF-SHA-384 (RFC 5869 shape, independently computed)
// ---------------------------------------------------------------------------

#[test]
fn hkdf_sha384_independent_vector() {
    let ikm = [0x0bu8; 22];
    let salt = hex("000102030405060708090a0b0c");
    let info = hex("f0f1f2f3f4f5f6f7f8f9");

    let prk = crypto::hkdf_extract(&salt, &ikm);
    assert_eq!(
        prk.to_vec(),
        hex(
            "704b39990779ce1dc548052c7dc39f303570dd13fb39f7acc564680bef80e8dec70ee9a7e1f3e293ef68eceb072a5ade"
        )
    );
    let okm: zeroize::Zeroizing<[u8; 42]> = crypto::hkdf_expand(&prk, &[&info]);
    assert_eq!(
        okm.to_vec(),
        hex("9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f748b6457763e4f0204fc5")
    );
}

// ---------------------------------------------------------------------------
// X25519 (RFC 7748 §6.1)
// ---------------------------------------------------------------------------

#[test]
fn x25519_rfc7748() {
    use x25519_dalek::{PublicKey, StaticSecret};

    let a_priv: [u8; 32] = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        .try_into()
        .unwrap();
    let b_priv: [u8; 32] = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        .try_into()
        .unwrap();

    let a = StaticSecret::from(a_priv);
    let b = StaticSecret::from(b_priv);
    assert_eq!(
        PublicKey::from(&a).as_bytes().to_vec(),
        hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    );
    assert_eq!(
        PublicKey::from(&b).as_bytes().to_vec(),
        hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    );

    let shared_ab = a.diffie_hellman(&PublicKey::from(&b));
    let shared_ba = b.diffie_hellman(&PublicKey::from(&a));
    let expected = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    assert_eq!(shared_ab.as_bytes().to_vec(), expected);
    assert_eq!(shared_ba.as_bytes().to_vec(), expected);
}

// ---------------------------------------------------------------------------
// Ed25519 (RFC 8032 §7.1 TEST 1)
// ---------------------------------------------------------------------------

#[test]
fn ed25519_rfc8032_test1() {
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};

    let secret: [u8; 32] = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        .try_into()
        .unwrap();
    let key = SigningKey::from_bytes(&secret);
    assert_eq!(
        key.verifying_key().to_bytes().to_vec(),
        hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    );

    let signature = key.sign(b"");
    assert_eq!(
        signature.to_bytes().to_vec(),
        hex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
    );
    let sig = Signature::from_bytes(&signature.to_bytes());
    key.verifying_key().verify(b"", &sig).unwrap();
}

// ---------------------------------------------------------------------------
// BLAKE3
// ---------------------------------------------------------------------------

#[test]
fn blake3_empty_vector() {
    assert_eq!(
        blake3::hash(b"").as_bytes().to_vec(),
        hex("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
    );
}

// ---------------------------------------------------------------------------
// ML-KEM-768: portable vs multiplexed instantiation from fixed randomness
// ---------------------------------------------------------------------------

#[test]
fn mlkem768_cross_instantiation() {
    use libcrux_ml_kem::mlkem768;

    let keygen_seed: [u8; 64] = core::array::from_fn(|i| i as u8);
    let encap_seed: [u8; 32] = core::array::from_fn(|i| (255 - i) as u8);

    let pair_mux = mlkem768::generate_key_pair(keygen_seed);
    let pair_port = mlkem768::portable::generate_key_pair(keygen_seed);
    assert_eq!(
        pair_mux.public_key().as_slice(),
        pair_port.public_key().as_slice(),
        "keygen: multiplexed and portable disagree"
    );
    assert_eq!(
        pair_mux.private_key().as_slice(),
        pair_port.private_key().as_slice()
    );

    let (ct_mux, ss_mux) = mlkem768::encapsulate(pair_mux.public_key(), encap_seed);
    let (ct_port, ss_port) = mlkem768::portable::encapsulate(pair_port.public_key(), encap_seed);
    assert_eq!(ct_mux.as_slice(), ct_port.as_slice());
    assert_eq!(ss_mux, ss_port);

    let dec_mux = mlkem768::decapsulate(pair_mux.private_key(), &ct_mux);
    let dec_port = mlkem768::portable::decapsulate(pair_port.private_key(), &ct_port);
    assert_eq!(dec_mux, dec_port);
    assert_eq!(
        dec_mux, ss_mux,
        "decapsulated secret differs from encapsulated"
    );
}

// ---------------------------------------------------------------------------
// ML-DSA-65: portable vs multiplexed instantiation from fixed randomness
// ---------------------------------------------------------------------------

#[test]
fn mldsa65_cross_instantiation() {
    use libcrux_ml_dsa::ml_dsa_65;

    let keygen_seed: [u8; 32] = core::array::from_fn(|i| (i * 7) as u8);
    let sign_seed: [u8; 32] = core::array::from_fn(|i| (i * 13) as u8);
    let message = b"cross-instantiation message";
    let context: &[u8] = b"ctx";

    let pair_mux = ml_dsa_65::generate_key_pair(keygen_seed);
    let pair_port = ml_dsa_65::portable::generate_key_pair(keygen_seed);
    assert_eq!(
        pair_mux.verification_key.as_ref(),
        pair_port.verification_key.as_ref(),
        "keygen: multiplexed and portable disagree"
    );
    assert_eq!(
        pair_mux.signing_key.as_ref(),
        pair_port.signing_key.as_ref()
    );

    let sig_mux = ml_dsa_65::sign(&pair_mux.signing_key, message, context, sign_seed).unwrap();
    let sig_port =
        ml_dsa_65::portable::sign(&pair_port.signing_key, message, context, sign_seed).unwrap();
    assert_eq!(sig_mux.as_ref(), sig_port.as_ref());

    ml_dsa_65::verify(&pair_mux.verification_key, message, context, &sig_mux).unwrap();
    ml_dsa_65::portable::verify(&pair_port.verification_key, message, context, &sig_port).unwrap();
    // A wrong context must fail: that is the domain separation.
    assert!(ml_dsa_65::verify(&pair_mux.verification_key, message, b"other", &sig_mux).is_err());
}

// ---------------------------------------------------------------------------
// XChaCha20-Poly1305. Upstream has the KATs; this pins the tag and length
// behaviour the chunk format depends on.
// ---------------------------------------------------------------------------

#[test]
fn xchacha_tag_and_aad_behavior() {
    use chacha20poly1305::{
        KeyInit, XChaCha20Poly1305, XNonce,
        aead::{Aead, Payload},
    };

    let cipher = XChaCha20Poly1305::new_from_slice(&[7u8; 32]).unwrap();
    let nonce = XNonce::from_slice(&[9u8; 24]);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: b"hello",
                aad: b"aad",
            },
        )
        .unwrap();
    assert_eq!(ct.len(), 5 + 16, "Poly1305 tag must be appended");

    // Same key/nonce/aad decrypts; wrong AAD must fail.
    assert_eq!(
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ct.as_slice(),
                    aad: b"aad"
                }
            )
            .unwrap(),
        b"hello"
    );
    assert!(
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ct.as_slice(),
                    aad: b"AAD"
                }
            )
            .is_err()
    );
}
