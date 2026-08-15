// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end resume over a real Iroh QUIC connection.
//!
//! What §18.5 actually promises: an interrupted transfer continues from its
//! verified ranges, and only the missing chunks cross the wire the second
//! time.

use std::path::{Path, PathBuf};
use std::time::Duration;

use iroh::{Endpoint, endpoint::presets};
use rtp2_core::bitmap::ChunkBitmap;
use rtp2_core::crypto::ALPN;
use rtp2_core::handshake::ReplayCache;
use rtp2_core::identity::DeviceIdentity;
use rtp2_core::resume::{ObjectIdentity, ResumeDb};
use rtp2_core::transfer;

const CHUNK: u64 = 256 * 1024;

/// These tests exercise which chunks a record remembers, not whether bytes
/// reached the platter — there is no object file behind them to flush.
async fn no_data_to_flush() -> std::io::Result<()> {
    Ok(())
}


fn workdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "rtp2-resume-e2e-{}-{}-{tag}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn payload(bytes: usize) -> Vec<u8> {
    (0..bytes).map(|i| (i % 251) as u8).collect()
}

async fn endpoint() -> Endpoint {
    Endpoint::builder(presets::N0)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .unwrap()
}

/// Runs one attempt for an already-prepared object.
async fn attempt(
    pending: &transfer::PendingTransfer,
    dst: &Path,
    state: Option<&Path>,
) -> Result<transfer::TransferReport, String> {
    let sender_id = DeviceIdentity::generate();
    let receiver_id = DeviceIdentity::generate();
    let sender_ep = endpoint().await;
    let receiver_ep = endpoint().await;
    let addr = receiver_ep.addr();

    let mut replay = ReplayCache::default();
    let recv = transfer::receive_file(
        &receiver_ep,
        &receiver_id,
        &mut replay,
        dst,
        Duration::from_secs(30),
        transfer::ReceiveOptions {
            resume_state: state,
            ..Default::default()
        },
    );
    let send = transfer::send_pending(
        &sender_ep,
        &sender_id,
        addr,
        pending,
        None,
        rtp2_core::route::RoutePolicy::Any,
    );
    let (sent, received) = tokio::join!(send, recv);
    sent.map_err(|e| e.to_string())?;
    received.map_err(|e| e.to_string())
}

// Builds its own runtime, so it stays a plain test — the awaits inside live in
// the block_on body.
#[test]
fn interrupted_transfer_resumes_from_verified_ranges() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let dir = workdir("resume");
        let src = dir.join("source.bin");
        let dst = dir.join("received.bin");
        let state = dir.join("received.bin.rtp2state");

        // 10 chunks exactly, so the arithmetic below is unambiguous.
        let data = payload((10 * CHUNK) as usize);
        std::fs::write(&src, &data).unwrap();

        // The object is prepared once. Re-offering the same PendingTransfer
        // is what a retry after a dropped connection does.
        let pending = transfer::PendingTransfer::prepare(&src, CHUNK as u32)
            .await
            .unwrap();
        assert_eq!(pending.chunk_count(), 10);

        // --- Simulate an interruption partway through ---------------------
        // The receiver already holds and has verified chunks 0..4 of exactly
        // this object; the rest of the file on disk is garbage.
        let identity = ObjectIdentity {
            transfer_id: pending.transfer_id(),
            object_id: pending.object_id(),
            manifest_commitment: [0; 32], // filled in below from the offer
            ciphertext_root: pending.ciphertext_root(),
            chunk_count: pending.chunk_count(),
            chunk_ciphertext_size: pending.chunk_ciphertext_size(),
            logical_plaintext_size: pending.logical_plaintext_size(),
        };

        let mut damaged = data.clone();
        for byte in damaged[(4 * CHUNK) as usize..].iter_mut() {
            *byte = 0xff;
        }
        std::fs::write(&dst, &damaged).unwrap();

        // The commitment only exists once an offer does, so run one attempt
        // without resume state to get it, then rebuild the record the way an
        // interruption would have left it.
        let first = attempt(&pending, &dst, None).await.unwrap();
        assert_eq!(first.chunks, 10);
        assert_eq!(std::fs::read(&dst).unwrap(), data);

        let identity = ObjectIdentity {
            manifest_commitment: first.manifest_commitment,
            ..identity
        };
        {
            let (mut db, resumed) = ResumeDb::open(&state, identity.clone(), &dst).unwrap();
            assert!(!resumed);
            for i in 0..4u64 {
                db.mark_verified(i).unwrap();
                db.chunk_written(i, no_data_to_flush).await.unwrap();
            }
            db.checkpoint().unwrap();
            assert_eq!(db.missing_ranges(100), vec![(4, 10)]);
        }
        std::fs::write(&dst, &damaged).unwrap();

        // --- Resume: the same object is re-offered ------------------------
        let resumed_report = attempt(&pending, &dst, Some(&state)).await.unwrap();

        // Only the six missing chunks crossed the wire.
        assert_eq!(
            resumed_report.chunks_transferred, 6,
            "a resumed transfer must not re-send verified chunks"
        );
        assert_eq!(resumed_report.chunks, 10, "the object still has 10 chunks");

        // The file is whole again: the damaged tail replaced, the intact
        // head untouched.
        assert_eq!(
            std::fs::read(&dst).unwrap(),
            data,
            "resumed transfer must repair the damaged region"
        );
        assert_eq!(resumed_report.plaintext_digest, first.plaintext_digest);

        // A completed object leaves no resume record behind.
        assert!(
            !state.exists(),
            "resume record must be deleted once the object is complete"
        );

        std::fs::remove_dir_all(&dir).ok();
    });
}

#[tokio::test]
async fn resume_record_drives_the_range_request() {
    // Scheduler and resume database must agree on what is missing, since the
    // wire request is built from it.
    use rtp2_core::scheduler::Scheduler;


    let dir = workdir("ranges");
    let state = dir.join("state");
    let data = dir.join("data");

    let identity = ObjectIdentity {
        transfer_id: [1; 32],
        object_id: [2; 32],
        manifest_commitment: [3; 32],
        ciphertext_root: [4; 32],
        chunk_count: 20,
        chunk_ciphertext_size: CHUNK + 16,
        logical_plaintext_size: 20 * CHUNK,
    };

    let (mut db, _) = ResumeDb::open(&state, identity.clone(), &data).unwrap();
    for i in [0u64, 1, 2, 3, 10, 11, 19] {
        db.mark_verified(i).unwrap();
        db.chunk_written(i, no_data_to_flush).await.unwrap();
    }
    db.checkpoint().unwrap();

    let scheduler = Scheduler::new(
        identity.transfer_id,
        identity.object_id,
        identity.chunk_count,
        identity.chunk_ciphertext_size,
    );
    let request = scheduler.full_request(&db.record().durable);
    assert_eq!(request.ranges, vec![(4, 10), (12, 19)]);
    request.validate(20).unwrap();
    assert_eq!(request.chunk_total(), 13);

    // The request survives the wire unchanged.
    let bytes = request.encode();
    assert_eq!(
        rtp2_core::scheduler::RangeRequest::decode(&bytes, 20).unwrap(),
        request
    );

    // Reopening the database yields the same picture after a restart.
    let (db2, resumed) = ResumeDb::open(&state, identity, &data).unwrap();
    assert!(resumed);
    assert_eq!(db2.missing_ranges(100), vec![(4, 10), (12, 19)]);

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn a_completed_object_asks_for_nothing() {
    let dir = workdir("complete");
    let state = dir.join("state");
    let data = dir.join("data");

    let identity = ObjectIdentity {
        transfer_id: [1; 32],
        object_id: [2; 32],
        manifest_commitment: [3; 32],
        ciphertext_root: [4; 32],
        chunk_count: 5,
        chunk_ciphertext_size: CHUNK + 16,
        logical_plaintext_size: 5 * CHUNK,
    };
    let (mut db, _) = ResumeDb::open(&state, identity.clone(), &data).unwrap();
    for i in 0..5u64 {
        db.mark_verified(i).unwrap();
        db.chunk_written(i, no_data_to_flush).await.unwrap();
    }
    db.checkpoint().unwrap();

    let scheduler = rtp2_core::scheduler::Scheduler::new(
        identity.transfer_id,
        identity.object_id,
        5,
        CHUNK + 16,
    );
    // A complete object asks for nothing — expressed as a request with no
    // ranges, which is what the wire format means by it.
    assert!(
        scheduler
            .full_request(&db.record().durable)
            .ranges
            .is_empty()
    );
    assert!(db.is_complete());

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn bitmap_survives_a_restart_with_gaps_intact() {
    // What the record exists for: ranges, not a high-water mark.
    let dir = workdir("gaps");
    let state = dir.join("state");
    let data = dir.join("data");

    let identity = ObjectIdentity {
        transfer_id: [1; 32],
        object_id: [2; 32],
        manifest_commitment: [3; 32],
        ciphertext_root: [4; 32],
        chunk_count: 1000,
        chunk_ciphertext_size: CHUNK + 16,
        logical_plaintext_size: 1000 * CHUNK,
    };

    // A scattered arrival pattern, as multi-source delivery produces.
    let arrived: Vec<u64> = (0..1000).filter(|i| i % 3 != 1).collect();
    {
        let (mut db, _) = ResumeDb::open(&state, identity.clone(), &data).unwrap();
        for i in &arrived {
            db.mark_verified(*i).unwrap();
            db.chunk_written(*i, no_data_to_flush).await.unwrap();
        }
        db.checkpoint().unwrap();
    }

    let (db, resumed) = ResumeDb::open(&state, identity, &data).unwrap();
    assert!(resumed);
    assert_eq!(db.durable_count(), arrived.len() as u64);

    let mut expected = ChunkBitmap::new(1000).unwrap();
    for i in &arrived {
        expected.set(*i).unwrap();
    }
    assert_eq!(db.record().durable, expected);

    // Every gap is still individually known.
    let missing = db.missing_ranges(2000);
    let total: u64 = missing.iter().map(|(s, e)| e - s).sum();
    assert_eq!(total, 1000 - arrived.len() as u64);

    std::fs::remove_dir_all(&dir).ok();
}

/// The streamed digest and the re-read digest must be the same number.
///
/// `receive_file` hashes chunks as they arrive when they arrive in order, and
/// otherwise reads the finished file back. Two paths producing one
/// authenticated value is the shape that drifts silently: fresh transfers only
/// take the first, resumed ones only the second, and nothing compares them.
/// This does, over the same bytes.
#[tokio::test(flavor = "multi_thread")]
async fn the_streamed_digest_equals_the_reread_digest() {
    let dir = workdir("digest-paths");
    let src = dir.join("src.bin");
    // Several chunks plus a short tail, so an off-by-one in the streamed
    // path shows up as a digest mismatch.
    let bytes = payload(3 * 64 * 1024 + 1234);
    std::fs::write(&src, &bytes).unwrap();
    let independent = *blake3::hash(&bytes).as_bytes();

    let pending = transfer::PendingTransfer::prepare(&src, 64 * 1024)
        .await
        .unwrap();

    // Fresh: every chunk arrives in order, so the digest is streamed.
    let fresh = dir.join("fresh.bin");
    let streamed = attempt(&pending, &fresh, None)
        .await
        .expect("fresh transfer");
    assert_eq!(streamed.plaintext_digest, independent, "streamed digest");

    // Resumed: the receiver holds chunks it never hashed, so the digest has
    // to come from reading the file back.
    let resumed = dir.join("resumed.bin");
    let state = dir.join("resume.rtp2");
    std::fs::copy(&fresh, &resumed).unwrap();
    let first = attempt(&pending, &resumed, Some(&state)).await;
    let reread = match first {
        Ok(report) => report,
        Err(e) => panic!("resumed transfer: {e}"),
    };
    assert_eq!(reread.plaintext_digest, independent, "re-read digest");
    assert_eq!(
        reread.plaintext_digest, streamed.plaintext_digest,
        "the two digest paths must not drift apart"
    );

    std::fs::remove_dir_all(&dir).ok();
}
