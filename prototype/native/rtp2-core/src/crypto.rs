// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//! Suite constants and the KDF/MAC primitives everything else builds on (§6).

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha384};
use zeroize::Zeroizing;

pub const SUITE_ID: u16 = 0x0001;
pub const PROTOCOL_MAJOR: u16 = 2;
pub const PROTOCOL_MINOR: u16 = 0;
pub const ALPN: &[u8] = b"reyta-transfer/2";

pub const HASH_LEN: usize = 48;

pub type HmacSha384 = Hmac<Sha384>;

/// SHA-384 over the concatenation of `parts`.
pub fn sha384(parts: &[&[u8]]) -> [u8; HASH_LEN] {
    let mut h = Sha384::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// HKDF-Extract-SHA384 (§8.2.8, §9.2).
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Zeroizing<[u8; HASH_LEN]> {
    let (prk, _) = hkdf::Hkdf::<Sha384>::extract(Some(salt), ikm);
    Zeroizing::new(prk.into())
}

/// HKDF-Expand-SHA384 from a 48-byte PRK (§8.2.9, §9.3).
pub fn hkdf_expand<const N: usize>(prk: &[u8; HASH_LEN], info: &[&[u8]]) -> Zeroizing<[u8; N]> {
    let hk = hkdf::Hkdf::<Sha384>::from_prk(prk).expect("valid SHA-384 PRK length");
    let mut out = Zeroizing::new([0u8; N]);
    let joined: Vec<u8> = info.concat();
    hk.expand(&joined, out.as_mut())
        .expect("output length within HKDF bounds");
    out
}

/// HMAC-SHA-384 (§8.2.10 finished MACs).
pub fn hmac_sha384(key: &[u8], data: &[u8]) -> [u8; HASH_LEN] {
    let mut mac = HmacSha384::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Constant-time equality for MACs and digests.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// Fills `buf` from the operating-system CSPRNG (§6.2, §9.1).
pub fn os_random(buf: &mut [u8]) {
    use rand_core::RngCore;
    rand_core::OsRng.fill_bytes(buf);
}

pub fn os_random_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    os_random(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_matches_rfc_shape() {
        // Extract-then-expand must be deterministic and the right length.
        let prk = hkdf_extract(b"salt", b"ikm");
        let a: Zeroizing<[u8; 32]> = hkdf_expand(&prk, &[b"info"]);
        let b: Zeroizing<[u8; 32]> = hkdf_expand(&prk, &[b"in", b"fo"]);
        assert_eq!(a.as_ref(), b.as_ref());
        let c: Zeroizing<[u8; 32]> = hkdf_expand(&prk, &[b"other"]);
        assert_ne!(a.as_ref(), c.as_ref());
    }

    #[test]
    fn hmac_is_keyed() {
        let m1 = hmac_sha384(b"k1", b"msg");
        let m2 = hmac_sha384(b"k2", b"msg");
        assert_ne!(m1, m2);
        assert!(ct_eq(&m1, &hmac_sha384(b"k1", b"msg")));
    }
}
