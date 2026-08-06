// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//! Device identity: hybrid Ed25519 + ML-DSA-65 signing (§7.2, §8.2.6).
//!
//! Identities are self-asserted key bundles exchanged in the handshake, so
//! trust-on-first-use. The §7.2 certificate chain lives elsewhere.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

use zeroize::Zeroizing;

use crate::{
    cbor::{CborError, MapWriter, Reader, Writer},
    crypto::{self, os_random_array},
    pqc::{self, MLDSA65_SIGNATURE_LEN, MLDSA65_VERIFICATION_KEY_LEN, MlDsaKeyPair},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityError;

impl From<CborError> for IdentityError {
    fn from(_: CborError) -> Self {
        IdentityError
    }
}

/// Length of the master seed a persistent identity stores.
pub const IDENTITY_SEED_LEN: usize = 32;

/// §7.2 says what a certificate binds, not how device keys are made, so the
/// whole identity hangs off one 32-byte seed:
///
///   prk           = HKDF-Extract-SHA384("RTP2-IDENTITY-SALT-v1", seed)
///   device_id     = HKDF-Expand(prk, "RTP2 device id v1",       32)
///   ed25519_seed  = HKDF-Expand(prk, "RTP2 device ed25519 v1",  32)
///   mldsa_seed    = HKDF-Expand(prk, "RTP2 device mldsa65 v1",  32)
///   endpoint_seed = HKDF-Expand(prk, "RTP2 device endpoint v1", 32)
///
/// So 32 secret bytes need protecting instead of 4064, and a record naming a
/// device id whose keys belong to someone else cannot be built. The cost is
/// that one seed leak is the whole device, which is the right granularity.
const SEED_SALT: &[u8] = b"RTP2-IDENTITY-SALT-v1";
const INFO_DEVICE_ID: &[u8] = b"RTP2 device id v1";
const INFO_ED25519: &[u8] = b"RTP2 device ed25519 v1";
const INFO_MLDSA: &[u8] = b"RTP2 device mldsa65 v1";
const INFO_ENDPOINT: &[u8] = b"RTP2 device endpoint v1";

/// Private device identity. Never crosses the C ABI, and deliberately not
/// `Debug`, `Clone` or serializable.
pub struct DeviceIdentity {
    pub device_id: [u8; 32],
    seed: Zeroizing<[u8; IDENTITY_SEED_LEN]>,
    ed25519: SigningKey,
    mldsa: MlDsaKeyPair,
}

impl DeviceIdentity {
    /// A fresh identity from the OS CSPRNG.
    pub fn generate() -> Self {
        Self::generate_with_seed().1
    }

    /// A fresh identity plus its seed. The seed is the only thing worth
    /// protecting; the rest recomputes.
    pub fn generate_with_seed() -> (Zeroizing<[u8; IDENTITY_SEED_LEN]>, Self) {
        let seed = Zeroizing::new(os_random_array::<IDENTITY_SEED_LEN>());
        let identity = Self::from_seed(&seed);
        (seed, identity)
    }

    /// Derives the whole identity deterministically from a seed.
    pub fn from_seed(seed: &[u8; IDENTITY_SEED_LEN]) -> Self {
        let prk = crypto::hkdf_extract(SEED_SALT, seed);
        let device_id = *crypto::hkdf_expand::<32>(&prk, &[INFO_DEVICE_ID]);
        let ed25519_seed = crypto::hkdf_expand::<32>(&prk, &[INFO_ED25519]);
        let mldsa_seed = crypto::hkdf_expand::<32>(&prk, &[INFO_MLDSA]);

        Self {
            device_id,
            seed: Zeroizing::new(*seed),
            ed25519: SigningKey::from_bytes(&ed25519_seed),
            mldsa: MlDsaKeyPair::from_seed(&mldsa_seed),
        }
    }

    /// Iroh endpoint secret. Same seed means a stable Endpoint ID across
    /// restarts, which §7.4 needs to match a certificate to an observed peer.
    /// The tradeoff is that a relay can link a device's sessions over time.
    pub fn endpoint_secret(&self) -> Zeroizing<[u8; 32]> {
        let prk = crypto::hkdf_extract(SEED_SALT, self.seed.as_ref());
        crypto::hkdf_expand::<32>(&prk, &[INFO_ENDPOINT])
    }

    pub fn public(&self) -> DevicePublic {
        DevicePublic {
            device_id: self.device_id,
            ed25519: self.ed25519.verifying_key().to_bytes(),
            mldsa: *self.mldsa.verification_bytes(),
        }
    }

    /// §8.2.6, both signatures over the same transcript hash.
    pub fn hybrid_sign(&self, transcript_hash: &[u8]) -> Result<HybridSignature, IdentityError> {
        let ed25519 = self.ed25519.sign(transcript_hash).to_bytes();
        let mldsa = self
            .mldsa
            .sign(transcript_hash)
            .map_err(|_| IdentityError)?;
        Ok(HybridSignature { ed25519, mldsa })
    }
}

/// Public device bundle carried as `cert_A` / `cert_B` in the handshake.
#[derive(Clone, PartialEq, Eq)]
pub struct DevicePublic {
    pub device_id: [u8; 32],
    pub ed25519: [u8; 32],
    pub mldsa: [u8; MLDSA65_VERIFICATION_KEY_LEN],
}

impl DevicePublic {
    pub fn encode(&self, w: &mut Writer) {
        let mut m = MapWriter::begin(w, 3);
        m.bytes(0, &self.device_id);
        m.bytes(1, &self.ed25519);
        m.bytes(2, &self.mldsa);
        m.end();
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, CborError> {
        let mut m = r.map()?;
        m.expect_key(0)?;
        let device_id = m.reader.bytes_exact::<32>()?;
        m.expect_key(1)?;
        let ed25519 = m.reader.bytes_exact::<32>()?;
        m.expect_key(2)?;
        let mldsa = m.reader.bytes_exact::<MLDSA65_VERIFICATION_KEY_LEN>()?;
        if m.next_key()?.is_some() {
            return Err(CborError::InvalidValue);
        }
        Ok(Self {
            device_id,
            ed25519,
            mldsa,
        })
    }

    /// §8.2.6: verification succeeds only if BOTH signatures verify.
    pub fn hybrid_verify(
        &self,
        transcript_hash: &[u8],
        sig: &HybridSignature,
    ) -> Result<(), IdentityError> {
        let vk = VerifyingKey::from_bytes(&self.ed25519).map_err(|_| IdentityError)?;
        let ed_sig = ed25519_dalek::Signature::from_bytes(&sig.ed25519);
        vk.verify(transcript_hash, &ed_sig)
            .map_err(|_| IdentityError)?;
        pqc::mldsa_verify(&self.mldsa, transcript_hash, &sig.mldsa).map_err(|_| IdentityError)
    }
}

#[derive(Clone)]
pub struct HybridSignature {
    pub ed25519: [u8; 64],
    pub mldsa: [u8; MLDSA65_SIGNATURE_LEN],
}

impl HybridSignature {
    pub fn encode(&self, w: &mut Writer) {
        let mut m = MapWriter::begin(w, 2);
        m.bytes(0, &self.ed25519);
        m.bytes(1, &self.mldsa);
        m.end();
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, CborError> {
        let mut m = r.map()?;
        m.expect_key(0)?;
        let ed25519 = m.reader.bytes_exact::<64>()?;
        m.expect_key(1)?;
        let mldsa = m.reader.bytes_exact::<MLDSA65_SIGNATURE_LEN>()?;
        if m.next_key()?.is_some() {
            return Err(CborError::InvalidValue);
        }
        Ok(Self { ed25519, mldsa })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_deterministic_in_the_seed() {
        // What persistence rests on: same seed, same device.
        let seed = [0x42u8; IDENTITY_SEED_LEN];
        let a = DeviceIdentity::from_seed(&seed);
        let b = DeviceIdentity::from_seed(&seed);
        assert_eq!(a.device_id, b.device_id);
        assert!(a.public() == b.public());
        assert_eq!(a.endpoint_secret().as_ref(), b.endpoint_secret().as_ref());

        // One bit of seed difference changes everything.
        let mut other_seed = seed;
        other_seed[0] ^= 1;
        let c = DeviceIdentity::from_seed(&other_seed);
        assert_ne!(a.device_id, c.device_id);
        assert_ne!(a.public().ed25519, c.public().ed25519);
        assert_ne!(a.public().mldsa, c.public().mldsa);
        assert_ne!(a.endpoint_secret().as_ref(), c.endpoint_secret().as_ref());

        // A signature from one verifies under the other's public bundle.
        let sig = a.hybrid_sign(b"transcript").unwrap();
        b.public().hybrid_verify(b"transcript", &sig).unwrap();
    }

    #[test]
    fn device_id_is_derived_not_random() {
        // Recompute the id from the documented formula. Independent
        // randomness could not match.
        let seed = [0x11u8; IDENTITY_SEED_LEN];
        let identity = DeviceIdentity::from_seed(&seed);
        let prk = crypto::hkdf_extract(b"RTP2-IDENTITY-SALT-v1", &seed);
        let expected = crypto::hkdf_expand::<32>(&prk, &[b"RTP2 device id v1"]);
        assert_eq!(identity.device_id, *expected);
    }

    #[test]
    fn derivations_are_domain_separated() {
        // Four outputs from one PRK must differ. Two equal info strings
        // would collide two different keys.
        let seed = [0x7fu8; IDENTITY_SEED_LEN];
        let prk = crypto::hkdf_extract(SEED_SALT, &seed);
        let outputs = [
            *crypto::hkdf_expand::<32>(&prk, &[INFO_DEVICE_ID]),
            *crypto::hkdf_expand::<32>(&prk, &[INFO_ED25519]),
            *crypto::hkdf_expand::<32>(&prk, &[INFO_MLDSA]),
            *crypto::hkdf_expand::<32>(&prk, &[INFO_ENDPOINT]),
        ];
        for i in 0..outputs.len() {
            for j in (i + 1)..outputs.len() {
                assert_ne!(outputs[i], outputs[j], "derivations {i} and {j} collide");
            }
        }
        // And the info strings themselves are pairwise distinct.
        let infos = [INFO_DEVICE_ID, INFO_ED25519, INFO_MLDSA, INFO_ENDPOINT];
        for i in 0..infos.len() {
            for j in (i + 1)..infos.len() {
                assert_ne!(infos[i], infos[j]);
            }
        }
    }

    #[test]
    fn generated_identities_are_distinct() {
        let (seed_a, a) = DeviceIdentity::generate_with_seed();
        let (seed_b, b) = DeviceIdentity::generate_with_seed();
        assert_ne!(seed_a.as_ref(), seed_b.as_ref());
        assert_ne!(a.device_id, b.device_id);
        // The returned seed really is the one that produced the identity.
        assert_eq!(DeviceIdentity::from_seed(&seed_a).device_id, a.device_id);
    }

    #[test]
    fn hybrid_requires_both_signatures() {
        let id = DeviceIdentity::generate();
        let public = id.public();
        let sig = id.hybrid_sign(b"th").unwrap();
        assert!(public.hybrid_verify(b"th", &sig).is_ok());

        // Break only the classical branch.
        let mut broken = sig.clone();
        broken.ed25519[0] ^= 1;
        assert!(public.hybrid_verify(b"th", &broken).is_err());

        // Break only the post-quantum branch.
        let mut broken = sig.clone();
        broken.mldsa[0] ^= 1;
        assert!(public.hybrid_verify(b"th", &broken).is_err());
    }

    #[test]
    fn bundle_roundtrip() {
        let id = DeviceIdentity::generate();
        let public = id.public();
        let mut w = Writer::new();
        public.encode(&mut w);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes).unwrap();
        let decoded = DevicePublic::decode(&mut r).unwrap();
        r.finish().unwrap();
        assert!(decoded == public);
    }
}
