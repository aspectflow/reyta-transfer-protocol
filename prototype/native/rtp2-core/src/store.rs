// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//! Long-lived device state: the identity (§7.2), and later the prekey batch
//! (§8.3) and resumption secrets (§8.4).
//!
//! Not `resume.rs`, which holds per-object transfer state: losing resume
//! progress is safe, so a corrupt record is dropped, while a corrupt identity
//! record is an error rather than grounds for a new identity.
//!
//! The default [`PlaintextSealer`] leaves the seed on disk behind file
//! permissions, so the core runs unattended with no prompt. [`SecretSealer`]
//! is where a keystore-backed sealer slots in; the protection level is bound
//! into the AAD, so a caller can demand a minimum and be refused instead of
//! quietly downgraded.
//!
//! `mlock` is not implemented: it fails under container RLIMIT_MEMLOCK
//! defaults, which would break the unattended case.

use std::io::Write;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::{
    cbor::{CborError, MapWriter, Reader, Writer},
    crypto,
    identity::{DeviceIdentity, IDENTITY_SEED_LEN},
};

/// Record format version. A record from another version is refused, never
/// guessed at.
pub const RECORD_VERSION: u64 = 1;
/// Bound on any store record, so a corrupt file cannot drive an allocation.
const MAX_RECORD_BYTES: usize = 256 * 1024;

pub(crate) const IDENTITY_DOMAIN: &[u8] = b"RTP2-IDENTITY-RECORD-v1";
const IDENTITY_PAYLOAD_VERSION: u64 = 1;

#[derive(Debug)]
pub enum StoreError {
    Io(String),
    Corrupt,
    VersionMismatch,
    /// The stored record is protected more weakly than policy requires.
    ProtectionDowngrade,
    /// The state directory or record has unsafe ownership or mode.
    UnsafePath(String),
    /// The path is not a regular file, or not a directory where one is
    /// wanted. Separate from `UnsafePath` so a test can tell which guard
    /// caught a planted symlink: a symlink's own mode is 0777, so the
    /// permission check would refuse it too and hide a missing type check.
    NotRegularFile(String),
    /// The sealer could not wrap or unwrap the payload.
    Seal,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Io(e) => write!(f, "store io: {e}"),
            StoreError::Corrupt => write!(f, "store record is corrupt"),
            StoreError::VersionMismatch => write!(f, "store record version mismatch"),
            StoreError::ProtectionDowngrade => {
                write!(f, "store record is protected below the required level")
            }
            StoreError::UnsafePath(p) => write!(f, "unsafe store path: {p}"),
            StoreError::NotRegularFile(p) => write!(f, "not a regular file: {p}"),
            StoreError::Seal => write!(f, "store record could not be sealed or opened"),
        }
    }
}

impl From<CborError> for StoreError {
    fn from(_: CborError) -> Self {
        StoreError::Corrupt
    }
}

fn io_err<E: std::fmt::Display>(e: E) -> StoreError {
    StoreError::Io(e.to_string())
}

// ---------------------------------------------------------------------------
// Protection level and the sealer seam
// ---------------------------------------------------------------------------

/// How a record's secret bytes are protected at rest. Ordered, so a policy
/// check is just `found < minimum`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Protection {
    /// Plaintext in a 0600 file. Confidentiality is the OS's problem.
    Plaintext = 0,
    /// AEAD under a key the keystore hands back. Software-exportable:
    /// whatever can read the item gets the key.
    PlatformKeystore = 1,
    /// AEAD under a key that only a non-exportable hardware key can unwrap.
    /// Strictly stronger than `PlatformKeystore`: the unwrapping key cannot
    /// leave the security processor, so the attack has to run on that machine
    /// rather than on a copy of its disk or keychain.
    HardwareKeystore = 2,
}

impl Protection {
    pub fn as_u64(self) -> u64 {
        self as u64
    }

    pub fn from_u64(v: u64) -> Result<Self, StoreError> {
        match v {
            0 => Ok(Protection::Plaintext),
            1 => Ok(Protection::PlatformKeystore),
            2 => Ok(Protection::HardwareKeystore),
            _ => Err(StoreError::VersionMismatch),
        }
    }
}

/// Wraps and unwraps the at-rest secret payload.
pub trait SecretSealer: Send + Sync {
    fn protection(&self) -> Protection;
    fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, StoreError>;
    fn open(&self, sealed: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, StoreError>;
}

/// The prototype default: seal and open are the identity function.
pub struct PlaintextSealer;

impl SecretSealer for PlaintextSealer {
    fn protection(&self) -> Protection {
        Protection::Plaintext
    }

    fn seal(&self, plaintext: &[u8], _aad: &[u8]) -> Result<Vec<u8>, StoreError> {
        Ok(plaintext.to_vec())
    }

    fn open(&self, sealed: &[u8], _aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        Ok(Zeroizing::new(sealed.to_vec()))
    }
}

/// XChaCha20-Poly1305 under a caller-supplied 32-byte key.
///
/// The sealed form is `nonce(24) || ciphertext || tag(16)`, with a random
/// nonce per seal: XChaCha20's 192-bit nonce makes repetition across a
/// device's handful of writes a non-issue, so no durable counter is needed.
///
/// [`crate::keystore::KeystoreSealer`] is this type with the key fetched from
/// the platform. Tests construct it directly so AAD binding and downgrade
/// refusal are exercised even where no keystore backend exists.
pub struct AeadSealer {
    key: Zeroizing<[u8; 32]>,
    protection: Protection,
}

impl AeadSealer {
    /// `protection` is what sealed records will claim. A parameter, not a
    /// constant, because it describes where the key lives and this type does
    /// not know that.
    pub fn new(key: [u8; 32], protection: Protection) -> Self {
        Self {
            key: Zeroizing::new(key),
            protection,
        }
    }
}

impl SecretSealer for AeadSealer {
    fn protection(&self) -> Protection {
        self.protection
    }

    fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, StoreError> {
        use chacha20poly1305::{
            KeyInit, XChaCha20Poly1305, XNonce,
            aead::{Aead, Payload},
        };
        let cipher =
            XChaCha20Poly1305::new_from_slice(self.key.as_ref()).map_err(|_| StoreError::Seal)?;
        let nonce: [u8; 24] = crypto::os_random_array();
        let mut out = nonce.to_vec();
        out.extend_from_slice(
            &cipher
                .encrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| StoreError::Seal)?,
        );
        Ok(out)
    }

    fn open(&self, sealed: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        use chacha20poly1305::{
            KeyInit, XChaCha20Poly1305, XNonce,
            aead::{Aead, Payload},
        };
        if sealed.len() < 24 {
            return Err(StoreError::Seal);
        }
        let (nonce, ciphertext) = sealed.split_at(24);
        let cipher =
            XChaCha20Poly1305::new_from_slice(self.key.as_ref()).map_err(|_| StoreError::Seal)?;
        Ok(Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(nonce),
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| StoreError::Seal)?,
        ))
    }
}

// ---------------------------------------------------------------------------
// Sealed record machinery: shared by identity, prekeys and resumption
// ---------------------------------------------------------------------------
//
//   file = BLAKE3(domain || body)[32] || body
//   body = RTP-CBOR { 0: record_version, 1: protection, 2: sealed_payload }
//   aad  = domain || U64BE(record_version) || U64BE(protection)

fn record_aad(domain: &[u8], protection: Protection) -> Vec<u8> {
    let mut aad = Vec::with_capacity(domain.len() + 16);
    aad.extend_from_slice(domain);
    aad.extend_from_slice(&RECORD_VERSION.to_be_bytes());
    aad.extend_from_slice(&protection.as_u64().to_be_bytes());
    aad
}

/// Writes a sealed, checksummed record atomically: tmp, sync_all, rename,
/// then a best-effort directory fsync. Like `ResumeDb::checkpoint`, a crash
/// leaves the old record or the new one, never a torn one.
pub(crate) fn write_sealed(
    path: &Path,
    domain: &[u8],
    sealer: &dyn SecretSealer,
    payload: &[u8],
) -> Result<(), StoreError> {
    let protection = sealer.protection();
    let sealed = sealer.seal(payload, &record_aad(domain, protection))?;

    let mut w = Writer::new();
    let mut m = MapWriter::begin(&mut w, 3);
    m.uint(0, RECORD_VERSION);
    m.uint(1, protection.as_u64());
    m.bytes(2, &sealed);
    m.end();
    let body = w.into_bytes();

    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(&body);
    let checksum = *h.finalize().as_bytes();

    let mut file_bytes = Vec::with_capacity(32 + body.len());
    file_bytes.extend_from_slice(&checksum);
    file_bytes.extend_from_slice(&body);
    if file_bytes.len() > MAX_RECORD_BYTES {
        return Err(StoreError::Corrupt);
    }

    let tmp = path.with_extension("tmp");
    {
        let mut file = create_private_file(&tmp)?;
        file.write_all(&file_bytes).map_err(io_err)?;
        file.sync_all().map_err(io_err)?;
    }
    std::fs::rename(&tmp, path).map_err(io_err)?;

    // The rename is only durable once the directory entry is.
    if let Some(dir) = path.parent()
        && let Ok(handle) = std::fs::File::open(dir)
    {
        let _ = handle.sync_all();
    }
    Ok(())
}

/// Reads and unseals a record. `Ok(None)` means no file; anything else that
/// goes wrong is an error. A corrupt record is never quietly replaced.
pub(crate) fn read_sealed(
    path: &Path,
    domain: &[u8],
    sealer: &dyn SecretSealer,
    minimum: Protection,
) -> Result<Option<Zeroizing<Vec<u8>>>, StoreError> {
    // 1. Regular file only. `symlink_metadata` does not follow links, so a
    //    planted symlink cannot redirect the read or make a later rename
    //    clobber whatever it points at.
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_err(e)),
    };
    if !meta.file_type().is_file() {
        return Err(StoreError::NotRegularFile(path.display().to_string()));
    }

    // 2. No group or other access.
    check_private_mode(&meta, path)?;

    // 3. Bounded length.
    let bytes = std::fs::read(path).map_err(io_err)?;
    if bytes.len() < 32 || bytes.len() > MAX_RECORD_BYTES {
        return Err(StoreError::Corrupt);
    }

    // 4. Checksum, in constant time.
    let (checksum, body) = bytes.split_at(32);
    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(body);
    if !crypto::ct_eq(checksum, h.finalize().as_bytes()) {
        return Err(StoreError::Corrupt);
    }

    // 5. Strict RTP-CBOR.
    let mut r = Reader::new(body)?;
    let mut m = r.map()?;
    m.expect_key(0)?;
    let version = m.reader.uint()?;
    m.expect_key(1)?;
    let protection_raw = m.reader.uint()?;
    m.expect_key(2)?;
    let sealed = m.reader.bytes()?.to_vec();
    if m.next_key()?.is_some() {
        return Err(StoreError::Corrupt);
    }
    r.finish()?;

    // 6. Version.
    if version != RECORD_VERSION {
        return Err(StoreError::VersionMismatch);
    }

    // 7. Refuse a downgrade rather than accept it.
    let protection = Protection::from_u64(protection_raw)?;
    if protection < minimum {
        return Err(StoreError::ProtectionDowngrade);
    }

    // 8. Unseal. The AAD binds the protection level, so rewriting that field
    //    and fixing the checksum still fails here.
    let payload = sealer.open(&sealed, &record_aad(domain, protection))?;
    Ok(Some(payload))
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> Result<std::fs::File, StoreError> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(io_err)
}

#[cfg(not(unix))]
fn create_private_file(path: &Path) -> Result<std::fs::File, StoreError> {
    std::fs::File::create(path).map_err(io_err)
}

#[cfg(unix)]
fn check_private_mode(meta: &std::fs::Metadata, path: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::MetadataExt;
    if meta.mode() & 0o077 != 0 {
        return Err(StoreError::UnsafePath(format!(
            "{} is accessible to group or other (mode {:o})",
            path.display(),
            meta.mode() & 0o777
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private_mode(_meta: &std::fs::Metadata, _path: &Path) -> Result<(), StoreError> {
    Ok(())
}

// ---------------------------------------------------------------------------
// DeviceStore
// ---------------------------------------------------------------------------

pub struct DeviceStore {
    dir: PathBuf,
    sealer: Box<dyn SecretSealer>,
    minimum_protection: Protection,
}

impl DeviceStore {
    /// Opens a state directory, creating it with mode 0700 if absent.
    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        match std::fs::symlink_metadata(dir) {
            Ok(meta) => {
                if !meta.file_type().is_dir() {
                    return Err(StoreError::NotRegularFile(format!(
                        "{} is not a directory",
                        dir.display()
                    )));
                }
                check_private_mode(&meta, dir)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => create_private_dir(dir)?,
            Err(e) => return Err(io_err(e)),
        }

        Ok(Self {
            dir: dir.to_path_buf(),
            sealer: Box::new(PlaintextSealer),
            minimum_protection: Protection::Plaintext,
        })
    }

    /// Replaces the sealer and raises the minimum protection this store will
    /// accept when reading.
    pub fn with_sealer(mut self, sealer: Box<dyn SecretSealer>, minimum: Protection) -> Self {
        self.sealer = sealer;
        self.minimum_protection = minimum;
        self
    }

    pub fn identity_path(&self) -> PathBuf {
        self.dir.join("identity.rtp2")
    }

    /// Reserved for the §8.3 prekey batch.
    pub fn prekeys_path(&self) -> PathBuf {
        self.dir.join("prekeys.rtp2")
    }

    /// Reserved for §8.4 resumption secrets.
    pub fn resumption_path(&self) -> PathBuf {
        self.dir.join("resumption.rtp2")
    }

    /// Reserved for per-transfer §18.3 resume records.
    pub fn transfers_dir(&self) -> PathBuf {
        self.dir.join("transfers")
    }

    /// This device's identity, created and persisted on first use. The `bool`
    /// is true when loaded, false when created.
    ///
    /// A record that exists but cannot be read is an error, not a reason to
    /// mint a new identity: that would invalidate every peer's pin.
    pub fn load_or_create_identity(&self) -> Result<(DeviceIdentity, bool), StoreError> {
        let path = self.identity_path();
        if let Some(payload) = read_sealed(
            &path,
            IDENTITY_DOMAIN,
            self.sealer.as_ref(),
            self.minimum_protection,
        )? {
            let seed = decode_identity_payload(&payload)?;
            return Ok((DeviceIdentity::from_seed(&seed), true));
        }

        let (seed, identity) = DeviceIdentity::generate_with_seed();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let payload = encode_identity_payload(&seed, now);
        write_sealed(&path, IDENTITY_DOMAIN, self.sealer.as_ref(), &payload)?;
        Ok((identity, false))
    }
}

// ---------------------------------------------------------------------------
// Session resumption secrets (§8.4)
// ---------------------------------------------------------------------------

const RESUMPTION_DOMAIN: &[u8] = b"RTP2-RESUMPTION-v1";
const RESUMPTION_PAYLOAD_VERSION: u64 = 1;
/// §8.4: a secret expires no later than 24 hours after the handshake.
pub const RESUMPTION_MAX_LIFETIME_SECS: u64 = 24 * 60 * 60;
/// Bound on stored entries, so the file stays small and decoding stays bounded.
const MAX_RESUMPTION_ENTRIES: u64 = 64;

/// One stored resumption secret.
///
/// §8.4 forbids resuming across a change of peer device identity, suite, or
/// protocol major, so all three are stored and checked rather than assumed.
#[derive(Clone, PartialEq, Eq)]
pub struct ResumptionEntry {
    pub resumption_id: [u8; 16],
    pub peer_device_id: [u8; 32],
    pub secret: [u8; 48],
    pub suite_id: u16,
    pub protocol_major: u16,
    pub created_at: u64,
    pub expires_at: u64,
}

impl Drop for ResumptionEntry {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret.zeroize();
    }
}

impl DeviceStore {
    /// Stores a resumption secret, replacing any entry with the same id.
    ///
    /// The lifetime is clamped to §8.4's 24-hour ceiling rather than trusted
    /// from the caller.
    pub fn store_resumption(&self, entry: &ResumptionEntry, now: u64) -> Result<(), StoreError> {
        let mut entries = self.load_resumption_entries()?;
        entries.retain(|e| e.resumption_id != entry.resumption_id && e.expires_at > now);

        let mut stored = entry.clone();
        stored.expires_at = stored.expires_at.min(
            stored
                .created_at
                .saturating_add(RESUMPTION_MAX_LIFETIME_SECS),
        );
        entries.push(stored);

        // Oldest first out, so a flood cannot evict a fresh secret.
        entries.sort_by_key(|e| e.created_at);
        while entries.len() as u64 > MAX_RESUMPTION_ENTRIES {
            entries.remove(0);
        }
        self.write_resumption_entries(&entries)
    }

    /// Takes a resumption secret for single use (§8.4). The entry is removed
    /// and the file rewritten durably *before* the secret is returned, so a
    /// crash can lose a resumption but never reuse one.
    ///
    /// `None` when the id is unknown, expired, or bound to a different peer
    /// device, suite, or protocol major.
    pub fn take_resumption(
        &self,
        resumption_id: &[u8; 16],
        peer_device_id: &[u8; 32],
        suite_id: u16,
        protocol_major: u16,
        now: u64,
    ) -> Result<Option<ResumptionEntry>, StoreError> {
        let mut entries = self.load_resumption_entries()?;
        let found = entries
            .iter()
            .position(|e| crypto::ct_eq(&e.resumption_id, resumption_id));

        let Some(index) = found else {
            return Ok(None);
        };
        let candidate = entries.remove(index);

        // Rewrite without the entry first: consumption must be durable before
        // the secret leaves this function, whatever the checks below decide.
        entries.retain(|e| e.expires_at > now);
        self.write_resumption_entries(&entries)?;

        if now >= candidate.expires_at
            || !crypto::ct_eq(&candidate.peer_device_id, peer_device_id)
            || candidate.suite_id != suite_id
            || candidate.protocol_major != protocol_major
        {
            return Ok(None);
        }
        Ok(Some(candidate))
    }

    fn load_resumption_entries(&self) -> Result<Vec<ResumptionEntry>, StoreError> {
        let Some(payload) = read_sealed(
            &self.resumption_path(),
            RESUMPTION_DOMAIN,
            self.sealer.as_ref(),
            self.minimum_protection,
        )?
        else {
            return Ok(Vec::new());
        };

        let mut r = Reader::new(&payload)?;
        let mut m = r.map()?;
        m.expect_key(0)?;
        if m.reader.uint()? != RESUMPTION_PAYLOAD_VERSION {
            return Err(StoreError::VersionMismatch);
        }
        m.expect_key(1)?;
        let count = m.reader.array()?;
        if count > MAX_RESUMPTION_ENTRIES {
            return Err(StoreError::Corrupt);
        }
        let mut entries = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let mut em = m.reader.map()?;
            em.expect_key(0)?;
            let resumption_id = em.reader.bytes_exact::<16>()?;
            em.expect_key(1)?;
            let peer_device_id = em.reader.bytes_exact::<32>()?;
            em.expect_key(2)?;
            let secret = em.reader.bytes_exact::<48>()?;
            em.expect_key(3)?;
            let suite_id = em.reader.uint()?;
            em.expect_key(4)?;
            let protocol_major = em.reader.uint()?;
            em.expect_key(5)?;
            let created_at = em.reader.uint()?;
            em.expect_key(6)?;
            let expires_at = em.reader.uint()?;
            if em.next_key()?.is_some() {
                return Err(StoreError::Corrupt);
            }
            if suite_id > u16::MAX as u64 || protocol_major > u16::MAX as u64 {
                return Err(StoreError::Corrupt);
            }
            entries.push(ResumptionEntry {
                resumption_id,
                peer_device_id,
                secret,
                suite_id: suite_id as u16,
                protocol_major: protocol_major as u16,
                created_at,
                expires_at,
            });
        }
        m.reader.leave();
        if m.next_key()?.is_some() {
            return Err(StoreError::Corrupt);
        }
        r.finish()?;
        Ok(entries)
    }

    fn write_resumption_entries(&self, entries: &[ResumptionEntry]) -> Result<(), StoreError> {
        let mut w = Writer::new();
        let mut m = MapWriter::begin(&mut w, 2);
        m.uint(0, RESUMPTION_PAYLOAD_VERSION);
        {
            let inner = m.nested(1);
            inner.array(entries.len() as u64);
            for e in entries {
                let mut em = MapWriter::begin(inner, 7);
                em.bytes(0, &e.resumption_id);
                em.bytes(1, &e.peer_device_id);
                em.bytes(2, &e.secret);
                em.uint(3, e.suite_id as u64);
                em.uint(4, e.protocol_major as u64);
                em.uint(5, e.created_at);
                em.uint(6, e.expires_at);
                em.end();
            }
        }
        m.end();
        let payload = Zeroizing::new(w.into_bytes());
        write_sealed(
            &self.resumption_path(),
            RESUMPTION_DOMAIN,
            self.sealer.as_ref(),
            &payload,
        )
    }
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(io_err)
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> Result<(), StoreError> {
    std::fs::create_dir_all(dir).map_err(io_err)
}

/// `{ 0: payload_version, 1: seed, 2: created_at }`.
///
/// `device_id` is deliberately absent: it is derived from the seed, so a
/// record cannot name one that disagrees with the keys.
fn encode_identity_payload(seed: &[u8; IDENTITY_SEED_LEN], created_at: u64) -> Zeroizing<Vec<u8>> {
    let mut w = Writer::new();
    let mut m = MapWriter::begin(&mut w, 3);
    m.uint(0, IDENTITY_PAYLOAD_VERSION);
    m.bytes(1, seed);
    m.uint(2, created_at);
    m.end();
    Zeroizing::new(w.into_bytes())
}

pub(crate) fn decode_identity_payload(
    payload: &[u8],
) -> Result<Zeroizing<[u8; IDENTITY_SEED_LEN]>, StoreError> {
    let mut r = Reader::new(payload)?;
    let mut m = r.map()?;
    m.expect_key(0)?;
    if m.reader.uint()? != IDENTITY_PAYLOAD_VERSION {
        return Err(StoreError::VersionMismatch);
    }
    m.expect_key(1)?;
    let seed = m.reader.bytes_exact::<IDENTITY_SEED_LEN>()?;
    m.expect_key(2)?;
    let _created_at = m.reader.uint()?;
    if m.next_key()?.is_some() {
        return Err(StoreError::Corrupt);
    }
    r.finish()?;
    Ok(Zeroizing::new(seed))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `DeviceIdentity` has no `Debug` by design, so `unwrap_err` cannot be
    /// used on a Result carrying one.
    fn expect_err(result: Result<(DeviceIdentity, bool), StoreError>) -> StoreError {
        match result {
            Ok(_) => panic!("expected an error"),
            Err(e) => e,
        }
    }

    fn workdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rtp2-store-{}-{}-{tag}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn first_run_creates_second_run_loads() {
        let base = workdir("roundtrip");
        let dir = base.join("state");

        let (first, loaded) = DeviceStore::open(&dir)
            .unwrap()
            .load_or_create_identity()
            .unwrap();
        assert!(!loaded, "first run must create");

        let (second, loaded) = DeviceStore::open(&dir)
            .unwrap()
            .load_or_create_identity()
            .unwrap();
        assert!(loaded, "second run must load");

        assert_eq!(first.device_id, second.device_id);
        assert!(first.public() == second.public());
        assert_eq!(
            first.endpoint_secret().as_ref(),
            second.endpoint_secret().as_ref()
        );

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn two_state_dirs_are_two_identities() {
        let base = workdir("two");
        let (a, _) = DeviceStore::open(&base.join("a"))
            .unwrap()
            .load_or_create_identity()
            .unwrap();
        let (b, _) = DeviceStore::open(&base.join("b"))
            .unwrap()
            .load_or_create_identity()
            .unwrap();
        assert_ne!(a.device_id, b.device_id);
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn corrupt_record_is_an_error_and_the_file_is_left_alone() {
        let base = workdir("corrupt");
        let dir = base.join("state");
        let store = DeviceStore::open(&dir).unwrap();
        store.load_or_create_identity().unwrap();

        let path = store.identity_path();
        let mut bytes = std::fs::read(&path).unwrap();
        let pos = bytes.len() - 3;
        bytes[pos] ^= 0x01;
        std::fs::write(&path, &bytes).unwrap();

        let err = expect_err(DeviceStore::open(&dir).unwrap().load_or_create_identity());
        assert!(matches!(err, StoreError::Corrupt), "got {err:?}");

        // The whole point: a corrupt identity is NOT replaced.
        assert_eq!(
            std::fs::read(&path).unwrap(),
            bytes,
            "a corrupt identity record must not be overwritten"
        );

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn truncated_record_is_refused() {
        let base = workdir("trunc");
        let dir = base.join("state");
        let store = DeviceStore::open(&dir).unwrap();
        store.load_or_create_identity().unwrap();

        std::fs::write(store.identity_path(), [0u8; 10]).unwrap();
        assert!(matches!(
            expect_err(DeviceStore::open(&dir).unwrap().load_or_create_identity()),
            StoreError::Corrupt
        ));
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn version_mismatch_is_refused() {
        let base = workdir("version");
        let dir = base.join("state");
        let store = DeviceStore::open(&dir).unwrap();

        // Hand-build a record naming version 2, with a valid checksum.
        let mut w = Writer::new();
        let mut m = MapWriter::begin(&mut w, 3);
        m.uint(0, 2);
        m.uint(1, 0);
        m.bytes(2, b"payload");
        m.end();
        let body = w.into_bytes();
        let mut h = blake3::Hasher::new();
        h.update(IDENTITY_DOMAIN);
        h.update(&body);
        let mut file_bytes = h.finalize().as_bytes().to_vec();
        file_bytes.extend_from_slice(&body);
        {
            let mut f = create_private_file(&store.identity_path()).unwrap();
            f.write_all(&file_bytes).unwrap();
        }

        assert!(matches!(
            expect_err(store.load_or_create_identity()),
            StoreError::VersionMismatch
        ));
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn partial_write_cannot_be_observed() {
        let base = workdir("partial");
        let dir = base.join("state");
        let store = DeviceStore::open(&dir).unwrap();
        let (first, _) = store.load_or_create_identity().unwrap();

        // A crash mid-checkpoint leaves a garbage .tmp sibling behind.
        std::fs::write(
            store.identity_path().with_extension("tmp"),
            b"half-written garbage",
        )
        .unwrap();

        let (second, loaded) = DeviceStore::open(&dir)
            .unwrap()
            .load_or_create_identity()
            .unwrap();
        assert!(loaded);
        assert_eq!(first.device_id, second.device_id);
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn the_write_consumes_its_temporary_file() {
        // The atomic write is `.tmp` -> fsync -> rename. Rename *moves* the
        // temporary file, so nothing is left behind. A non-atomic write that
        // copied instead would leave the `.tmp` in place, which is both the
        // observable signature of losing atomicity and a real problem in its
        // own right, because that file holds a second copy of the seed.
        let base = workdir("tmp-consumed");
        let dir = base.join("state");
        let store = DeviceStore::open(&dir).unwrap();
        store.load_or_create_identity().unwrap();

        let tmp = store.identity_path().with_extension("tmp");
        assert!(
            !tmp.exists(),
            "the temporary file must be renamed, not copied: {} still exists",
            tmp.display()
        );

        // And the seed exists in exactly one file in the directory.
        let payload = read_sealed(
            &store.identity_path(),
            IDENTITY_DOMAIN,
            &PlaintextSealer,
            Protection::Plaintext,
        )
        .unwrap()
        .unwrap();
        let seed = decode_identity_payload(&payload).unwrap();
        let mut holders = 0;
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file()
                && std::fs::read(&path)
                    .unwrap()
                    .windows(32)
                    .any(|w| w == seed.as_ref())
            {
                holders += 1;
            }
        }
        assert_eq!(holders, 1, "the seed must live in exactly one file");

        std::fs::remove_dir_all(&base).ok();
    }

    #[cfg(unix)]
    #[test]
    fn dir_is_0700_and_record_is_0600() {
        use std::os::unix::fs::MetadataExt;
        let base = workdir("modes");
        let dir = base.join("state");
        let store = DeviceStore::open(&dir).unwrap();
        store.load_or_create_identity().unwrap();

        assert_eq!(std::fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        assert_eq!(
            std::fs::metadata(store.identity_path()).unwrap().mode() & 0o777,
            0o600
        );
        std::fs::remove_dir_all(&base).ok();
    }

    #[cfg(unix)]
    #[test]
    fn world_readable_record_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let base = workdir("perms");
        let dir = base.join("state");
        let store = DeviceStore::open(&dir).unwrap();
        store.load_or_create_identity().unwrap();

        std::fs::set_permissions(
            store.identity_path(),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();

        assert!(matches!(
            expect_err(DeviceStore::open(&dir).unwrap().load_or_create_identity()),
            StoreError::UnsafePath(_)
        ));
        std::fs::remove_dir_all(&base).ok();
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_record_is_refused() {
        let base = workdir("symlink");
        let real_dir = base.join("real");
        let store = DeviceStore::open(&real_dir).unwrap();
        store.load_or_create_identity().unwrap();

        // A second state dir whose identity file is a symlink to the first.
        let link_dir = base.join("linked");
        let link_store = DeviceStore::open(&link_dir).unwrap();
        std::os::unix::fs::symlink(store.identity_path(), link_store.identity_path()).unwrap();

        // Must be the type guard, not the mode guard. A symlink's own mode is
        // 0777, so asserting the looser UnsafePath would pass even with the
        // is_file check removed.
        let err = expect_err(link_store.load_or_create_identity());
        assert!(
            matches!(err, StoreError::NotRegularFile(_)),
            "a planted symlink must be refused by the file-type check, got {err:?}"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn state_dir_that_is_a_file_is_refused() {
        let base = workdir("notadir");
        let path = base.join("state");
        std::fs::write(&path, b"not a directory").unwrap();
        match DeviceStore::open(&path) {
            Ok(_) => panic!("a regular file was accepted as a state directory"),
            Err(e) => assert!(matches!(e, StoreError::NotRegularFile(_)), "got {e:?}"),
        }
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn protection_downgrade_is_refused() {
        let base = workdir("downgrade");
        let dir = base.join("state");

        // Written with the plaintext sealer...
        DeviceStore::open(&dir)
            .unwrap()
            .load_or_create_identity()
            .unwrap();

        // ...and read by a store that demands keystore protection.
        let strict = DeviceStore::open(&dir).unwrap().with_sealer(
            Box::new(AeadSealer::new([9u8; 32], Protection::PlatformKeystore)),
            Protection::PlatformKeystore,
        );
        assert!(matches!(
            expect_err(strict.load_or_create_identity()),
            StoreError::ProtectionDowngrade
        ));
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn sealed_payload_binds_the_protection_level() {
        let base = workdir("aad");
        let dir = base.join("state");
        let store = DeviceStore::open(&dir).unwrap().with_sealer(
            Box::new(AeadSealer::new([4u8; 32], Protection::PlatformKeystore)),
            Protection::Plaintext,
        );
        store.load_or_create_identity().unwrap();

        // Rewrite the protection field to 0 and fix the checksum, as an
        // attacker downgrading the record would.
        let path = store.identity_path();
        let bytes = std::fs::read(&path).unwrap();
        let body = &bytes[32..];
        let mut r = Reader::new(body).unwrap();
        let mut m = r.map().unwrap();
        m.expect_key(0).unwrap();
        m.reader.uint().unwrap();
        m.expect_key(1).unwrap();
        m.reader.uint().unwrap();
        m.expect_key(2).unwrap();
        let sealed = m.reader.bytes().unwrap().to_vec();

        let mut w = Writer::new();
        let mut mw = MapWriter::begin(&mut w, 3);
        mw.uint(0, RECORD_VERSION);
        mw.uint(1, Protection::Plaintext.as_u64());
        mw.bytes(2, &sealed);
        mw.end();
        let new_body = w.into_bytes();
        let mut h = blake3::Hasher::new();
        h.update(IDENTITY_DOMAIN);
        h.update(&new_body);
        let mut forged = h.finalize().as_bytes().to_vec();
        forged.extend_from_slice(&new_body);
        {
            let mut f = create_private_file(&path).unwrap();
            f.write_all(&forged).unwrap();
        }

        // The checksum is valid, but the AAD no longer matches.
        let reopened = DeviceStore::open(&dir).unwrap().with_sealer(
            Box::new(AeadSealer::new([4u8; 32], Protection::PlatformKeystore)),
            Protection::Plaintext,
        );
        assert!(matches!(
            expect_err(reopened.load_or_create_identity()),
            StoreError::Seal
        ));
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn sealing_hides_the_seed_and_plaintext_does_not() {
        let base = workdir("hides");

        // Sealed: the seed must not appear in the file.
        let sealed_dir = base.join("sealed");
        let sealed_store = DeviceStore::open(&sealed_dir).unwrap().with_sealer(
            Box::new(AeadSealer::new([1u8; 32], Protection::PlatformKeystore)),
            Protection::PlatformKeystore,
        );
        let (identity, _) = sealed_store.load_or_create_identity().unwrap();
        let bytes = std::fs::read(sealed_store.identity_path()).unwrap();
        // Reconstruct the seed by reading it back through the sealer.
        let payload = read_sealed(
            &sealed_store.identity_path(),
            IDENTITY_DOMAIN,
            &AeadSealer::new([1u8; 32], Protection::PlatformKeystore),
            Protection::PlatformKeystore,
        )
        .unwrap()
        .unwrap();
        let seed = decode_identity_payload(&payload).unwrap();
        assert!(
            !bytes.windows(32).any(|w| w == seed.as_ref()),
            "a sealed record must not contain the seed"
        );
        assert_eq!(
            DeviceIdentity::from_seed(&seed).device_id,
            identity.device_id
        );

        // Plaintext: the seed IS in the file. Pinning the documented tradeoff
        // rather than assuming it.
        let plain_dir = base.join("plain");
        let plain_store = DeviceStore::open(&plain_dir).unwrap();
        plain_store.load_or_create_identity().unwrap();
        let plain_payload = read_sealed(
            &plain_store.identity_path(),
            IDENTITY_DOMAIN,
            &PlaintextSealer,
            Protection::Plaintext,
        )
        .unwrap()
        .unwrap();
        let plain_seed = decode_identity_payload(&plain_payload).unwrap();
        let plain_bytes = std::fs::read(plain_store.identity_path()).unwrap();
        assert!(
            plain_bytes.windows(32).any(|w| w == plain_seed.as_ref()),
            "the default sealer stores the seed in the clear; that is the documented tradeoff"
        );

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn record_stores_a_seed_not_expanded_keys() {
        let base = workdir("size");
        let dir = base.join("state");
        let store = DeviceStore::open(&dir).unwrap();
        store.load_or_create_identity().unwrap();
        let len = std::fs::metadata(store.identity_path()).unwrap().len();
        assert!(
            len < 256,
            "record is {len} bytes; an expanded ML-DSA key would be over 4000"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    fn entry(id: u8, peer: u8, created: u64) -> ResumptionEntry {
        ResumptionEntry {
            resumption_id: [id; 16],
            peer_device_id: [peer; 32],
            secret: [id.wrapping_add(1); 48],
            suite_id: 1,
            protocol_major: 2,
            created_at: created,
            expires_at: created + 3600,
        }
    }

    #[test]
    fn resumption_secret_is_single_use() {
        let base = workdir("resume-once");
        let store = DeviceStore::open(&base.join("state")).unwrap();
        let e = entry(1, 9, 1_000);
        store.store_resumption(&e, 1_000).unwrap();

        let taken = store
            .take_resumption(&e.resumption_id, &e.peer_device_id, 1, 2, 1_500)
            .unwrap()
            .expect("first take succeeds");
        assert_eq!(taken.secret, e.secret);

        // §8.4: at most once.
        assert!(
            store
                .take_resumption(&e.resumption_id, &e.peer_device_id, 1, 2, 1_500)
                .unwrap()
                .is_none()
        );

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn resumption_is_bound_to_peer_suite_and_version() {
        let base = workdir("resume-bind");
        let store = DeviceStore::open(&base.join("state")).unwrap();

        // Wrong peer device.
        let e = entry(2, 9, 1_000);
        store.store_resumption(&e, 1_000).unwrap();
        assert!(
            store
                .take_resumption(&e.resumption_id, &[0xff; 32], 1, 2, 1_500)
                .unwrap()
                .is_none()
        );

        // Wrong suite.
        let e = entry(3, 9, 1_000);
        store.store_resumption(&e, 1_000).unwrap();
        assert!(
            store
                .take_resumption(&e.resumption_id, &e.peer_device_id, 2, 2, 1_500)
                .unwrap()
                .is_none()
        );

        // Wrong protocol major.
        let e = entry(4, 9, 1_000);
        store.store_resumption(&e, 1_000).unwrap();
        assert!(
            store
                .take_resumption(&e.resumption_id, &e.peer_device_id, 1, 3, 1_500)
                .unwrap()
                .is_none()
        );

        // Each rejected attempt still consumed the entry: a mismatch must not
        // leave a secret available for another try.
        let e = entry(5, 9, 1_000);
        store.store_resumption(&e, 1_000).unwrap();
        assert!(
            store
                .take_resumption(&e.resumption_id, &[0xff; 32], 1, 2, 1_500)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .take_resumption(&e.resumption_id, &e.peer_device_id, 1, 2, 1_500)
                .unwrap()
                .is_none()
        );

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn resumption_expiry_is_enforced_and_clamped() {
        let base = workdir("resume-expiry");
        let store = DeviceStore::open(&base.join("state")).unwrap();

        let e = entry(6, 9, 1_000);
        store.store_resumption(&e, 1_000).unwrap();
        assert!(
            store
                .take_resumption(&e.resumption_id, &e.peer_device_id, 1, 2, 5_000)
                .unwrap()
                .is_none(),
            "past expires_at"
        );

        // §8.4 caps the lifetime at 24 h regardless of what the caller asks.
        let mut greedy = entry(7, 9, 1_000);
        greedy.expires_at = 1_000 + 10 * RESUMPTION_MAX_LIFETIME_SECS;
        store.store_resumption(&greedy, 1_000).unwrap();
        let just_inside = 1_000 + RESUMPTION_MAX_LIFETIME_SECS - 1;
        assert!(
            store
                .take_resumption(
                    &greedy.resumption_id,
                    &greedy.peer_device_id,
                    1,
                    2,
                    just_inside
                )
                .unwrap()
                .is_some()
        );

        let mut greedy2 = entry(8, 9, 1_000);
        greedy2.expires_at = 1_000 + 10 * RESUMPTION_MAX_LIFETIME_SECS;
        store.store_resumption(&greedy2, 1_000).unwrap();
        let past_cap = 1_000 + RESUMPTION_MAX_LIFETIME_SECS;
        assert!(
            store
                .take_resumption(
                    &greedy2.resumption_id,
                    &greedy2.peer_device_id,
                    1,
                    2,
                    past_cap
                )
                .unwrap()
                .is_none(),
            "the 24-hour ceiling must be enforced, not the caller's value"
        );

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn resumption_survives_a_restart_and_is_sealed() {
        let base = workdir("resume-persist");
        let dir = base.join("state");
        let e = entry(10, 9, 1_000);
        DeviceStore::open(&dir)
            .unwrap()
            .store_resumption(&e, 1_000)
            .unwrap();

        // A separate store instance, as a restarted process would build.
        let taken = DeviceStore::open(&dir)
            .unwrap()
            .take_resumption(&e.resumption_id, &e.peer_device_id, 1, 2, 1_500)
            .unwrap()
            .expect("secret survives a restart");
        assert_eq!(taken.secret, e.secret);

        // With a sealer, the secret is not readable from the file.
        let sealed_dir = base.join("sealed");
        let sealed = DeviceStore::open(&sealed_dir).unwrap().with_sealer(
            Box::new(AeadSealer::new([2u8; 32], Protection::PlatformKeystore)),
            Protection::PlatformKeystore,
        );
        let e2 = entry(11, 9, 1_000);
        sealed.store_resumption(&e2, 1_000).unwrap();
        let bytes = std::fs::read(sealed.resumption_path()).unwrap();
        assert!(
            !bytes.windows(48).any(|w| w == e2.secret),
            "a sealed resumption file must not contain the secret"
        );

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn sealed_roundtrip_for_an_arbitrary_payload() {
        // The machinery §8.3 and §8.4 will inherit.
        let base = workdir("generic");
        let path = base.join("blob.rtp2");
        let payload: Vec<u8> = (0..500u32).map(|i| (i % 256) as u8).collect();

        write_sealed(&path, b"RTP2-TEST-BLOB-v1", &PlaintextSealer, &payload).unwrap();
        let read = read_sealed(
            &path,
            b"RTP2-TEST-BLOB-v1",
            &PlaintextSealer,
            Protection::Plaintext,
        )
        .unwrap()
        .unwrap();
        assert_eq!(read.as_slice(), payload.as_slice());

        // A different domain rejects the same file: domains are separated.
        assert!(matches!(
            read_sealed(
                &path,
                b"RTP2-OTHER-BLOB-v1",
                &PlaintextSealer,
                Protection::Plaintext
            ),
            Err(StoreError::Corrupt)
        ));

        // A missing file is None, not an error.
        assert!(
            read_sealed(
                &base.join("absent.rtp2"),
                b"RTP2-TEST-BLOB-v1",
                &PlaintextSealer,
                Protection::Plaintext
            )
            .unwrap()
            .is_none()
        );

        std::fs::remove_dir_all(&base).ok();
    }
}
