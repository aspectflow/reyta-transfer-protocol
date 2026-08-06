// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//! PQC provider: ML-KEM-768 (FIPS 203) and ML-DSA-65 (FIPS 204) via libcrux.
//!
//! Version pinned in Cargo.toml. Going to production still needs upstream KAT
//! runs; this API is the seam another audited provider would slot into.

use libcrux_ml_dsa::ml_dsa_65::{
    self, MLDSA65Signature, MLDSA65SigningKey, MLDSA65VerificationKey,
};
use libcrux_ml_kem::mlkem768::{self, MlKem768Ciphertext, MlKem768PrivateKey, MlKem768PublicKey};

use crate::crypto::os_random_array;

pub const MLKEM768_PUBLIC_KEY_LEN: usize = 1184;
pub const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
pub const MLKEM768_SHARED_SECRET_LEN: usize = 32;
pub const MLDSA65_VERIFICATION_KEY_LEN: usize = 1952;
pub const MLDSA65_SIGNATURE_LEN: usize = 3309;

/// Domain-separation context for RTP/2 device signatures (FIPS 204 ctx input).
const MLDSA_CONTEXT: &[u8] = b"RTP2-DEVICE-SIG-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PqcError;

// ---------------------------------------------------------------------------
// ML-KEM-768
// ---------------------------------------------------------------------------

pub struct MlKemKeyPair {
    secret: MlKem768PrivateKey,
    public: MlKem768PublicKey,
}

impl MlKemKeyPair {
    pub fn generate() -> Self {
        let randomness: [u8; 64] = os_random_array();
        let pair = mlkem768::generate_key_pair(randomness);
        let (secret, public) = pair.into_parts();
        Self { secret, public }
    }

    pub fn public_bytes(&self) -> &[u8; MLKEM768_PUBLIC_KEY_LEN] {
        self.public.as_slice()
    }

    /// Decapsulation. Implicit rejection makes it total: a bad ciphertext
    /// gives an unrelated secret and the finished MAC fails later (§8.2.4).
    pub fn decapsulate(
        &self,
        ciphertext: &[u8],
    ) -> Result<[u8; MLKEM768_SHARED_SECRET_LEN], PqcError> {
        let ct = MlKem768Ciphertext::try_from(ciphertext).map_err(|_| PqcError)?;
        Ok(mlkem768::decapsulate(&self.secret, &ct))
    }
}

/// Validates and encapsulates to a peer ML-KEM-768 public key (§8.2.4).
pub fn mlkem_encapsulate(
    public_key: &[u8],
) -> Result<(Vec<u8>, [u8; MLKEM768_SHARED_SECRET_LEN]), PqcError> {
    let pk = MlKem768PublicKey::try_from(public_key).map_err(|_| PqcError)?;
    if !mlkem768::validate_public_key(&pk) {
        return Err(PqcError);
    }
    let randomness: [u8; 32] = os_random_array();
    let (ct, ss) = mlkem768::encapsulate(&pk, randomness);
    Ok((ct.as_slice().to_vec(), ss))
}

// ---------------------------------------------------------------------------
// ML-DSA-65
// ---------------------------------------------------------------------------

pub struct MlDsaKeyPair {
    signing: MLDSA65SigningKey,
    verification: MLDSA65VerificationKey,
}

impl MlDsaKeyPair {
    pub fn generate() -> Self {
        Self::from_seed(&os_random_array())
    }

    /// Regenerates a keypair from its 32-byte seed. KeyGen is deterministic
    /// in the seed, so an identity stores 32 bytes rather than the 4032-byte
    /// expanded key. `mldsa_seed_kat` pins the mapping so a provider swap
    /// cannot change it quietly.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let pair = ml_dsa_65::generate_key_pair(*seed);
        Self {
            signing: pair.signing_key,
            verification: pair.verification_key,
        }
    }

    /// libcrux's key types have no `Zeroize`, so wipe the expanded signing
    /// key here (§28.1). Named, not inlined into `Drop`, so it is testable.
    fn wipe(&mut self) {
        use zeroize::Zeroize;
        self.signing.as_ref_mut().zeroize();
    }

    pub fn verification_bytes(&self) -> &[u8; MLDSA65_VERIFICATION_KEY_LEN] {
        self.verification.as_ref()
    }

    pub fn sign(&self, message: &[u8]) -> Result<[u8; MLDSA65_SIGNATURE_LEN], PqcError> {
        let randomness: [u8; 32] = os_random_array();
        let sig = ml_dsa_65::sign(&self.signing, message, MLDSA_CONTEXT, randomness)
            .map_err(|_| PqcError)?;
        Ok(*sig.as_ref())
    }
}

impl Drop for MlDsaKeyPair {
    fn drop(&mut self) {
        self.wipe();
    }
}

pub fn mldsa_verify(
    verification_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), PqcError> {
    let vk_bytes: [u8; MLDSA65_VERIFICATION_KEY_LEN] =
        verification_key.try_into().map_err(|_| PqcError)?;
    let sig_bytes: [u8; MLDSA65_SIGNATURE_LEN] = signature.try_into().map_err(|_| PqcError)?;
    let vk = MLDSA65VerificationKey::new(vk_bytes);
    let sig = MLDSA65Signature::new(sig_bytes);
    ml_dsa_65::verify(&vk, message, MLDSA_CONTEXT, &sig).map_err(|_| PqcError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mlkem_roundtrip() {
        let pair = MlKemKeyPair::generate();
        let (ct, ss_enc) = mlkem_encapsulate(pair.public_bytes()).unwrap();
        let ss_dec = pair.decapsulate(&ct).unwrap();
        assert_eq!(ss_enc, ss_dec);
    }

    #[test]
    fn mlkem_tampered_ciphertext_diverges() {
        let pair = MlKemKeyPair::generate();
        let (mut ct, ss_enc) = mlkem_encapsulate(pair.public_bytes()).unwrap();
        ct[0] ^= 0x01;
        // Implicit rejection: decapsulation succeeds with a different secret.
        let ss_dec = pair.decapsulate(&ct).unwrap();
        assert_ne!(ss_enc, ss_dec);
    }

    #[test]
    fn mldsa_seed_is_deterministic() {
        // What a persistent identity depends on: same seed, same keypair.
        let a = MlDsaKeyPair::from_seed(&[7u8; 32]);
        let b = MlDsaKeyPair::from_seed(&[7u8; 32]);
        assert_eq!(a.verification_bytes(), b.verification_bytes());

        let mut other = [7u8; 32];
        other[31] ^= 1;
        let c = MlDsaKeyPair::from_seed(&other);
        assert_ne!(a.verification_bytes(), c.verification_bytes());

        // One's signature verifies under the other's public key, which only
        // holds if the private halves match.
        let sig = a.sign(b"same key").unwrap();
        mldsa_verify(b.verification_bytes(), b"same key", &sig).unwrap();
    }

    #[test]
    fn mldsa_seed_kat() {
        // Pins seed -> verification key. If a dependency bump changed this,
        // every persisted identity would quietly become a different device.
        let pair = MlDsaKeyPair::from_seed(&[0u8; 32]);
        let digest = blake3::hash(pair.verification_bytes());
        assert_eq!(
            digest.to_hex().as_str(),
            "578afd7e6e199ea6f7541b953c29c94250fed8340ce751694fcd4a011ecc859c",
            "BLAKE3(ML-DSA-65 verification key from an all-zero seed) changed"
        );
    }

    #[test]
    fn mldsa_wipe_zeroes_the_signing_key() {
        let mut pair = MlDsaKeyPair::from_seed(&[3u8; 32]);
        assert!(pair.signing.as_ref().iter().any(|b| *b != 0));
        pair.wipe();
        assert!(
            pair.signing.as_ref().iter().all(|b| *b == 0),
            "§28.1: the signing key must be zeroized"
        );
    }

    #[test]
    fn mldsa_sign_verify() {
        let pair = MlDsaKeyPair::generate();
        let sig = pair.sign(b"transcript-hash").unwrap();
        mldsa_verify(pair.verification_bytes(), b"transcript-hash", &sig).unwrap();
        assert!(mldsa_verify(pair.verification_bytes(), b"other", &sig).is_err());
        let mut bad = sig;
        bad[10] ^= 0xff;
        assert!(mldsa_verify(pair.verification_bytes(), b"transcript-hash", &bad).is_err());
    }
}
