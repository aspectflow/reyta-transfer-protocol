// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//! Resume database: persistent receiver state (§18.3) with the crash
//! consistency §26.3 requires.
//!
//! Verified ranges, not a byte offset, so a resume asks only for what is
//! missing (§18.5).
//!
//! A chunk is durable once its bytes are flushed and the bitmap commit is
//! itself durable. The commit writes a temp file, fsyncs, then renames, which
//! is atomic on POSIX; a BLAKE3 checksum catches what rename cannot.
//!
//! Checkpoints are batched, since an fsync per chunk would dominate a transfer
//! on mobile storage. Losing the last batch just re-requests those chunks.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::{
    bitmap::ChunkBitmap,
    cbor::{CborError, MapWriter, Reader, Writer},
};

/// Format version. A record from another version is discarded, not guessed
/// at.
const RECORD_VERSION: u64 = 1;
const RECORD_DOMAIN: &[u8] = b"RTP2-RESUME-RECORD-v1";
/// Cap on a stored record, so a corrupt file cannot drive an allocation.
const MAX_RECORD_BYTES: usize = 8 * 1024 * 1024;

/// Default checkpoint interval, in chunks.
pub const DEFAULT_CHECKPOINT_CHUNKS: u64 = 64;

#[derive(Debug)]
pub enum ResumeError {
    Io(String),
    Corrupt,
    VersionMismatch,
    /// The stored record describes a different object than the one on offer.
    ObjectMismatch,
}

impl std::fmt::Display for ResumeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResumeError::Io(e) => write!(f, "resume io: {e}"),
            ResumeError::Corrupt => write!(f, "resume record is corrupt"),
            ResumeError::VersionMismatch => write!(f, "resume record version mismatch"),
            ResumeError::ObjectMismatch => write!(f, "resume record is for a different object"),
        }
    }
}

impl From<CborError> for ResumeError {
    fn from(_: CborError) -> Self {
        ResumeError::Corrupt
    }
}

fn io_err<E: std::fmt::Display>(e: E) -> ResumeError {
    ResumeError::Io(e.to_string())
}

/// The identity of the object a record belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectIdentity {
    pub transfer_id: [u8; 32],
    pub object_id: [u8; 32],
    pub manifest_commitment: [u8; 32],
    pub ciphertext_root: [u8; 32],
    pub chunk_count: u64,
    pub chunk_ciphertext_size: u64,
    pub logical_plaintext_size: u64,
}

impl ObjectIdentity {
    /// Whether a stored record fits this object. A different ciphertext root
    /// or chunk size disqualifies the bytes on disk (§18.4.1), and the root
    /// alone already pins every one of them.
    ///
    /// `manifest_commitment` is not compared: it covers the offer timestamps
    /// and the private manifest's random nonce, so an honest re-offer gets a
    /// different one and matching on it would break every resume.
    pub fn matches(&self, other: &Self) -> bool {
        self.transfer_id == other.transfer_id
            && self.object_id == other.object_id
            && self.ciphertext_root == other.ciphertext_root
            && self.chunk_count == other.chunk_count
            && self.chunk_ciphertext_size == other.chunk_ciphertext_size
            && self.logical_plaintext_size == other.logical_plaintext_size
    }
}

/// Persistent receiver state for one object (§18.3).
#[derive(Debug, Clone)]
pub struct ResumeRecord {
    pub identity: ObjectIdentity,
    pub verified: ChunkBitmap,
    pub durable: ChunkBitmap,
    pub temporary_path: String,
    pub last_provider: Vec<u8>,
    pub last_activity: u64,
}

impl ResumeRecord {
    pub fn new(identity: ObjectIdentity, temporary_path: &Path) -> Result<Self, ResumeError> {
        let verified = ChunkBitmap::new(identity.chunk_count).map_err(|_| ResumeError::Corrupt)?;
        let durable = verified.clone();
        Ok(Self {
            identity,
            verified,
            durable,
            temporary_path: temporary_path.to_string_lossy().into_owned(),
            last_provider: Vec::new(),
            last_activity: 0,
        })
    }

    /// Chunk-index ranges still needed, capped per §18.2.
    pub fn missing_ranges(&self, max_ranges: usize) -> Vec<(u64, u64)> {
        self.durable.missing_ranges(max_ranges)
    }

    pub fn is_complete(&self) -> bool {
        self.durable.is_complete()
    }

    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        let mut m = MapWriter::begin(&mut w, 12);
        m.uint(0, RECORD_VERSION);
        m.bytes(1, &self.identity.transfer_id);
        m.bytes(2, &self.identity.object_id);
        m.bytes(3, &self.identity.manifest_commitment);
        m.bytes(4, &self.identity.ciphertext_root);
        m.uint(5, self.identity.chunk_count);
        m.uint(6, self.identity.chunk_ciphertext_size);
        m.uint(7, self.identity.logical_plaintext_size);
        m.bytes(8, &self.verified.encode_rle());
        m.bytes(9, &self.durable.encode_rle());
        m.text(10, &self.temporary_path);
        m.uint(11, self.last_activity);
        m.end();
        let body = w.into_bytes();

        // The domain goes into the checksum, so this cannot be confused with
        // another checksummed blob.
        let mut h = blake3::Hasher::new();
        h.update(RECORD_DOMAIN);
        h.update(&body);
        let checksum = *h.finalize().as_bytes();

        let mut out = Vec::with_capacity(body.len() + 32);
        out.extend_from_slice(&checksum);
        out.extend_from_slice(&body);
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, ResumeError> {
        if bytes.len() < 32 || bytes.len() > MAX_RECORD_BYTES {
            return Err(ResumeError::Corrupt);
        }
        let (checksum, body) = bytes.split_at(32);
        let mut h = blake3::Hasher::new();
        h.update(RECORD_DOMAIN);
        h.update(body);
        if !crate::crypto::ct_eq(checksum, h.finalize().as_bytes()) {
            return Err(ResumeError::Corrupt);
        }

        let mut r = Reader::new_unbounded(body);
        let mut m = r.map()?;
        m.expect_key(0)?;
        if m.reader.uint()? != RECORD_VERSION {
            return Err(ResumeError::VersionMismatch);
        }
        m.expect_key(1)?;
        let transfer_id = m.reader.bytes_exact::<32>()?;
        m.expect_key(2)?;
        let object_id = m.reader.bytes_exact::<32>()?;
        m.expect_key(3)?;
        let manifest_commitment = m.reader.bytes_exact::<32>()?;
        m.expect_key(4)?;
        let ciphertext_root = m.reader.bytes_exact::<32>()?;
        m.expect_key(5)?;
        let chunk_count = m.reader.uint()?;
        m.expect_key(6)?;
        let chunk_ciphertext_size = m.reader.uint()?;
        m.expect_key(7)?;
        let logical_plaintext_size = m.reader.uint()?;
        m.expect_key(8)?;
        let verified_rle = m.reader.bytes()?.to_vec();
        m.expect_key(9)?;
        let durable_rle = m.reader.bytes()?.to_vec();
        m.expect_key(10)?;
        let temporary_path = m.reader.text()?.to_owned();
        m.expect_key(11)?;
        let last_activity = m.reader.uint()?;
        if m.next_key()?.is_some() {
            return Err(ResumeError::Corrupt);
        }
        r.finish()?;

        let verified = ChunkBitmap::decode_rle(chunk_count, &verified_rle)
            .map_err(|_| ResumeError::Corrupt)?;
        let durable =
            ChunkBitmap::decode_rle(chunk_count, &durable_rle).map_err(|_| ResumeError::Corrupt)?;

        Ok(Self {
            identity: ObjectIdentity {
                transfer_id,
                object_id,
                manifest_commitment,
                ciphertext_root,
                chunk_count,
                chunk_ciphertext_size,
                logical_plaintext_size,
            },
            verified,
            durable,
            temporary_path,
            last_provider: Vec::new(),
            last_activity,
        })
    }
}

/// One object's resume state on disk.
pub struct ResumeDb {
    path: PathBuf,
    record: ResumeRecord,
    /// Chunks marked durable since the last checkpoint.
    pending: u64,
    checkpoint_interval: u64,
}

impl ResumeDb {
    /// Opens the record at `path`, or starts a fresh one.
    ///
    /// Adopted only if it describes exactly this object (§18.4.1). Anything
    /// unreadable, corrupt or from another version is discarded and the
    /// transfer starts over: losing progress is safe, trusting a mismatched
    /// record is not.
    pub fn open(
        path: &Path,
        identity: ObjectIdentity,
        temporary_path: &Path,
    ) -> Result<(Self, bool), ResumeError> {
        let mut resumed = false;
        let record = match std::fs::read(path) {
            Ok(bytes) => match ResumeRecord::decode(&bytes) {
                Ok(stored) if stored.identity.matches(&identity) => {
                    resumed = stored.durable.set_count() > 0;
                    stored
                }
                _ => ResumeRecord::new(identity, temporary_path)?,
            },
            Err(_) => ResumeRecord::new(identity, temporary_path)?,
        };
        Ok((
            Self {
                path: path.to_path_buf(),
                record,
                pending: 0,
                checkpoint_interval: DEFAULT_CHECKPOINT_CHUNKS,
            },
            resumed,
        ))
    }

    pub fn with_checkpoint_interval(mut self, chunks: u64) -> Self {
        self.checkpoint_interval = chunks.max(1);
        self
    }

    pub fn record(&self) -> &ResumeRecord {
        &self.record
    }

    pub fn missing_ranges(&self, max_ranges: usize) -> Vec<(u64, u64)> {
        self.record.missing_ranges(max_ranges)
    }

    pub fn is_complete(&self) -> bool {
        self.record.is_complete()
    }

    pub fn durable_count(&self) -> u64 {
        self.record.durable.set_count()
    }

    /// Marks a chunk VERIFIED: proof and AEAD passed, not yet known durable.
    pub fn mark_verified(&mut self, index: u64) -> Result<(), ResumeError> {
        self.record
            .verified
            .set(index)
            .map_err(|_| ResumeError::Corrupt)?;
        Ok(())
    }

    /// Records that the bytes of chunk `index` have been written to the object
    /// file, and — when a checkpoint is due — makes them durable and commits
    /// the bitmap, in that order.
    ///
    /// The ordering is the whole point, and it used to live in the caller.
    /// `sync_data` is how this module reaches the object file it does not own:
    /// it is called only when a commit is about to happen, and the commit does
    /// not happen if it fails. A record that survives a crash therefore never
    /// names a chunk the file does not hold.
    pub async fn chunk_written<F, Fut>(
        &mut self,
        index: u64,
        sync_data: F,
    ) -> Result<(), ResumeError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = std::io::Result<()>>,
    {
        if self
            .record
            .durable
            .set(index)
            .map_err(|_| ResumeError::Corrupt)?
        {
            self.pending += 1;
        }
        if self.pending < self.checkpoint_interval {
            return Ok(());
        }
        // Data first. A commit that outran the flush would leave a record
        // naming chunks the file does not hold, and a resume would skip them.
        sync_data().await.map_err(io_err)?;
        self.checkpoint()
    }

    /// The bitmap half of `chunk_written`, without the flush.
    ///
    /// Test-only, and marked so: outside a test there is no correct reason to
    /// record a chunk as durable without first making it durable.
    ///
    /// Private on purpose: reaching this directly is how the ordering came to
    /// be the caller's problem, and how a record ended up naming chunks that
    /// were never flushed. Tests that only care about which chunks a record
    /// remembers use it; anything moving real bytes goes through
    /// `chunk_written`.
    #[cfg(test)]
    fn mark_durable(&mut self, index: u64) -> Result<(), ResumeError> {
        if self
            .record
            .durable
            .set(index)
            .map_err(|_| ResumeError::Corrupt)?
        {
            self.pending += 1;
        }
        if self.pending >= self.checkpoint_interval {
            self.checkpoint()?;
        }
        Ok(())
    }

    pub fn set_last_activity(&mut self, unix_seconds: u64) {
        self.record.last_activity = unix_seconds;
    }

    /// Commits the bitmaps atomically: temp file, fsync, rename, then fsync
    /// the directory so the rename itself survives.
    pub fn checkpoint(&mut self) -> Result<(), ResumeError> {
        let encoded = self.record.encode();
        let tmp = self.path.with_extension("tmp");

        {
            let mut file = std::fs::File::create(&tmp).map_err(io_err)?;
            file.write_all(&encoded).map_err(io_err)?;
            file.sync_all().map_err(io_err)?;
        }
        std::fs::rename(&tmp, &self.path).map_err(io_err)?;

        if let Some(dir) = self.path.parent() {
            // What makes the rename survive power loss. Not supported
            // everywhere, and failing here is not fatal.
            if let Ok(handle) = std::fs::File::open(dir) {
                let _ = handle.sync_all();
            }
        }
        self.pending = 0;
        Ok(())
    }

    /// Deletes the record, once the object is complete and in place.
    pub fn remove(self) -> Result<(), ResumeError> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io_err(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(chunk_count: u64) -> ObjectIdentity {
        ObjectIdentity {
            transfer_id: [1; 32],
            object_id: [2; 32],
            manifest_commitment: [3; 32],
            ciphertext_root: [4; 32],
            chunk_count,
            chunk_ciphertext_size: 256 * 1024 + 16,
            logical_plaintext_size: chunk_count * 256 * 1024,
        }
    }

    fn tempdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rtp2-resume-{}-{}-{tag}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The invariant a resume record exists to keep: after a crash, every
    /// chunk it names must actually be in the file.
    ///
    /// This was not held. The fsync lived in the caller, behind
    /// `durable_count() + DEFAULT_CHECKPOINT_CHUNKS <= have.set_count()` — a
    /// condition that could never be true, because both counters advanced
    /// together on every chunk. The bitmap was committed every 64 chunks with
    /// nothing flushed before it.
    ///
    /// The check has to happen *inside* the flush, because that is the only
    /// moment the two orders differ: a version that commits first has already
    /// written the claim by the time the data is being flushed. Asserting
    /// afterwards passes either way — the first attempt at this test did
    /// exactly that and reported a clean bill of health for the broken order.
    #[tokio::test]
    async fn a_committed_record_never_claims_more_than_the_file_holds() {
        let dir = tempdir("durability-order");
        let path = dir.join("state");
        let data = dir.join("data");

        let (mut db, _) = ResumeDb::open(&path, identity(200), &data).unwrap();

        // How many chunks the object file is known to hold.
        let on_disk = std::rc::Rc::new(std::cell::Cell::new(0u64));

        for i in 0..200u64 {
            db.mark_verified(i).unwrap();

            let reached = on_disk.clone();
            let path_in_flush = path.clone();
            let data_in_flush = data.clone();

            db.chunk_written(i, move || {
                // Mid-flush: whatever the record on disk claims right now has
                // to be covered by what was already flushed, because this
                // flush has not finished yet.
                let (persisted, _) =
                    ResumeDb::open(&path_in_flush, identity(200), &data_in_flush).unwrap();
                assert!(
                    persisted.durable_count() <= reached.get(),
                    "the record already claims {} chunks durable while only {} \
                     had reached the disk — it was committed before the flush",
                    persisted.durable_count(),
                    reached.get()
                );
                reached.set(i + 1);
                async { Ok(()) }
            })
            .await
            .unwrap();
        }

        // And the end state is what it should be.
        let (persisted, resumed) = ResumeDb::open(&path, identity(200), &data).unwrap();
        assert!(resumed);
        assert_eq!(persisted.durable_count(), 192, "four checkpoints of 64");
    }

    /// A flush that fails must not be followed by a commit. Otherwise the one
    /// case the ordering exists for — the disk refusing the write — is the one
    /// case where the record lies about it.
    #[tokio::test]
    async fn a_failed_flush_leaves_the_record_where_it_was() {
        let dir = tempdir("durability-flush-fails");
        let path = dir.join("state");
        let data = dir.join("data");

        let (mut db, _) = ResumeDb::open(&path, identity(200), &data).unwrap();

        for i in 0..63u64 {
            db.chunk_written(i, || async { Ok(()) }).await.unwrap();
        }
        // The 64th completes the interval, so this one triggers the flush.
        let err = db
            .chunk_written(63, || async {
                Err(std::io::Error::other("the disk said no"))
            })
            .await
            .expect_err("a failed flush must be reported, not swallowed");
        assert!(matches!(err, ResumeError::Io(_)), "got {err:?}");

        // Nothing was ever committed, so a resume starts from zero rather than
        // from a claim the file cannot back.
        let (persisted, resumed) = ResumeDb::open(&path, identity(200), &data).unwrap();
        assert!(!resumed, "a record was written despite the flush failing");
        assert_eq!(persisted.durable_count(), 0);
    }

    #[test]
    fn records_ranges_not_a_single_offset() {
        let dir = tempdir("ranges");
        let path = dir.join("state");
        let data = dir.join("data");

        let (mut db, resumed) = ResumeDb::open(&path, identity(10), &data).unwrap();
        assert!(!resumed);
        // Out of order, as they arrive from several sources.
        for i in [0u64, 1, 2, 7, 8] {
            db.mark_verified(i).unwrap();
            db.mark_durable(i).unwrap();
        }
        db.checkpoint().unwrap();
        assert_eq!(db.missing_ranges(100), vec![(3, 7), (9, 10)]);

        // Reopening keeps the gaps, not just a high-water mark.
        let (db2, resumed) = ResumeDb::open(&path, identity(10), &data).unwrap();
        assert!(resumed);
        assert_eq!(db2.missing_ranges(100), vec![(3, 7), (9, 10)]);
        assert_eq!(db2.durable_count(), 5);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn mismatched_object_is_refused_and_restarted() {
        let dir = tempdir("mismatch");
        let path = dir.join("state");
        let data = dir.join("data");

        let (mut db, _) = ResumeDb::open(&path, identity(10), &data).unwrap();
        for i in 0..5u64 {
            db.mark_verified(i).unwrap();
            db.mark_durable(i).unwrap();
        }
        db.checkpoint().unwrap();

        // Same transfer id, different content: the root changed.
        let mut other = identity(10);
        other.ciphertext_root = [9; 32];
        let (db2, resumed) = ResumeDb::open(&path, other, &data).unwrap();
        assert!(!resumed, "a different root must not resume");
        assert_eq!(db2.durable_count(), 0);

        // Different chunk size is equally disqualifying (§18.4.1).
        let mut other = identity(10);
        other.chunk_ciphertext_size = 64 * 1024 + 16;
        let (db3, resumed) = ResumeDb::open(&path, other, &data).unwrap();
        assert!(!resumed);
        assert_eq!(db3.durable_count(), 0);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn corrupt_record_is_discarded_not_trusted() {
        let dir = tempdir("corrupt");
        let path = dir.join("state");
        let data = dir.join("data");

        let (mut db, _) = ResumeDb::open(&path, identity(10), &data).unwrap();
        for i in 0..6u64 {
            db.mark_verified(i).unwrap();
            db.mark_durable(i).unwrap();
        }
        db.checkpoint().unwrap();

        // Flip a byte inside the record body.
        let mut bytes = std::fs::read(&path).unwrap();
        let pos = bytes.len() - 4;
        bytes[pos] ^= 0x01;
        std::fs::write(&path, &bytes).unwrap();

        let (db2, resumed) = ResumeDb::open(&path, identity(10), &data).unwrap();
        assert!(!resumed, "corrupt record must not resume");
        assert_eq!(db2.durable_count(), 0);

        // Truncation is handled too.
        std::fs::write(&path, &bytes[..10]).unwrap();
        let (db3, resumed) = ResumeDb::open(&path, identity(10), &data).unwrap();
        assert!(!resumed);
        assert_eq!(db3.durable_count(), 0);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn partial_write_cannot_be_observed() {
        // Leave a partial .tmp behind, as a crash mid-write would. The real
        // record must be untouched and still load.
        let dir = tempdir("partial");
        let path = dir.join("state");
        let data = dir.join("data");

        let (mut db, _) = ResumeDb::open(&path, identity(10), &data).unwrap();
        for i in 0..4u64 {
            db.mark_verified(i).unwrap();
            db.mark_durable(i).unwrap();
        }
        db.checkpoint().unwrap();

        std::fs::write(path.with_extension("tmp"), b"half-written garbage").unwrap();

        let (db2, resumed) = ResumeDb::open(&path, identity(10), &data).unwrap();
        assert!(resumed);
        assert_eq!(db2.durable_count(), 4);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn checkpoint_batching_loses_only_the_last_batch() {
        let dir = tempdir("batch");
        let path = dir.join("state");
        let data = dir.join("data");

        let (mut db, _) = ResumeDb::open(&path, identity(100), &data).unwrap();
        let db_ref = &mut db;
        *db_ref = std::mem::replace(
            db_ref,
            ResumeDb::open(&path, identity(100), &data).unwrap().0,
        )
        .with_checkpoint_interval(10);

        for i in 0..25u64 {
            db.mark_verified(i).unwrap();
            db.mark_durable(i).unwrap();
        }
        // 25 marks at an interval of 10 checkpoints at 10 and 20, leaving
        // five pending. Dropping stands in for a crash.
        drop(db);

        let (db2, resumed) = ResumeDb::open(&path, identity(100), &data).unwrap();
        assert!(resumed);
        assert_eq!(
            db2.durable_count(),
            20,
            "only the uncommitted batch is lost"
        );
        assert_eq!(db2.missing_ranges(10), vec![(20, 100)]);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn completion_and_removal() {
        let dir = tempdir("complete");
        let path = dir.join("state");
        let data = dir.join("data");

        let (mut db, _) = ResumeDb::open(&path, identity(4), &data).unwrap();
        for i in 0..4u64 {
            db.mark_verified(i).unwrap();
            db.mark_durable(i).unwrap();
        }
        db.checkpoint().unwrap();
        assert!(db.is_complete());
        assert!(db.missing_ranges(10).is_empty());
        db.remove().unwrap();
        assert!(!path.exists());

        std::fs::remove_dir_all(&dir).ok();
    }
}
