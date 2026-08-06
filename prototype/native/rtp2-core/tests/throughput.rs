// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//! Per-stage crypto throughput, printed rather than asserted.
//!
//! ```bash
//! cargo test --release --test throughput -- --nocapture --ignored
//! ```
//!
//! Where the time goes inside the pipeline, no network involved. For the
//! whole transfer see `tests/e2e_bench.rs`.

use std::time::Instant;

use rtp2_core::{keys::FileSecrets, merkle, object};

const MIB: f64 = 1024.0 * 1024.0;

fn rate(bytes: usize, seconds: f64) -> f64 {
    bytes as f64 / MIB / seconds
}

#[test]
#[ignore = "measurement, not a correctness check"]
fn where_the_time_goes() {
    const CHUNK: u32 = 256 * 1024;
    const CHUNKS: u64 = 256; // 64 MiB
    let total = (CHUNK as u64 * CHUNKS) as usize;

    let secrets = FileSecrets::generate();
    let ctx = object::ObjectContext::for_file(
        secrets.transfer_id,
        secrets.object_id,
        CHUNK as u64 * CHUNKS,
        CHUNK,
    )
    .unwrap();
    let ctx_hash = ctx.context_hash();
    let schedule = secrets.key_schedule();
    let plain = vec![0xa5u8; CHUNK as usize];

    println!(
        "\n  payload            {:.0} MiB in {CHUNKS} chunks of {} KiB",
        total as f64 / MIB,
        CHUNK / 1024
    );

    // 1. Plain BLAKE3 over the payload: the floor for any hashing pass.
    let start = Instant::now();
    let mut hasher = blake3::Hasher::new();
    for _ in 0..CHUNKS {
        hasher.update(&plain);
    }
    let _ = hasher.finalize();
    let blake3_secs = start.elapsed().as_secs_f64();
    println!(
        "  BLAKE3 pass        {:>8.0} MiB/s",
        rate(total, blake3_secs)
    );

    // 2. Chunk AEAD: key derivation + nonce + XChaCha20-Poly1305.
    let start = Instant::now();
    let mut ciphertexts = Vec::with_capacity(CHUNKS as usize);
    for index in 0..CHUNKS {
        ciphertexts.push(object::encrypt_chunk(&schedule, &ctx, &ctx_hash, index, &plain).unwrap());
    }
    let aead_secs = start.elapsed().as_secs_f64();
    println!("  chunk AEAD         {:>8.0} MiB/s", rate(total, aead_secs));

    // 3. Merkle leaves over the ciphertext.
    let start = Instant::now();
    let leaves: Vec<[u8; 32]> = ciphertexts
        .iter()
        .enumerate()
        .map(|(i, ct)| merkle::leaf_hash(i as u64, ct))
        .collect();
    let root = merkle::merkle_root(&leaves);
    let merkle_secs = start.elapsed().as_secs_f64();
    println!(
        "  Merkle leaves      {:>8.0} MiB/s",
        rate(total, merkle_secs)
    );

    // 4. Proof generation, which the sender does per chunk.
    let start = Instant::now();
    for index in 0..CHUNKS {
        let _ = merkle::build_proof(&leaves, index as usize).unwrap();
    }
    let proof_secs = start.elapsed().as_secs_f64();
    println!(
        "  proof build        {:>8.0} MiB/s",
        rate(total, proof_secs)
    );

    // 5. Verification + decryption, the receiver's per-chunk work.
    let proofs: Vec<_> = (0..CHUNKS)
        .map(|i| merkle::build_proof(&leaves, i as usize).unwrap())
        .collect();
    let start = Instant::now();
    for index in 0..CHUNKS {
        let ct = &ciphertexts[index as usize];
        let leaf = merkle::leaf_hash(index, ct);
        merkle::verify_proof(&leaf, index, CHUNKS, &proofs[index as usize], &root).unwrap();
        let _ = object::decrypt_chunk(&schedule, &ctx, &ctx_hash, index, ct).unwrap();
    }
    let verify_secs = start.elapsed().as_secs_f64();
    println!(
        "  verify + decrypt   {:>8.0} MiB/s",
        rate(total, verify_secs)
    );

    // What a transfer costs, from the numbers above.
    //
    // Sender:   one AEAD pass in prepare, kept by the cache so send_pending
    //           does not repeat it, plus BLAKE3, Merkle leaves, proofs and
    //           the control AEAD around every chunk record.
    // Receiver: leaf hash, proof, chunk AEAD, control AEAD and the plaintext
    //           digest. In-order arrivals stream that digest, so the second
    //           read of the file is gone; a resumed or out-of-order transfer
    //           still pays for it.
    let sender = aead_secs + blake3_secs + merkle_secs + proof_secs + aead_secs;
    let sender_before_cache = sender + aead_secs;
    let receiver = verify_secs + aead_secs + blake3_secs;
    let receiver_with_reread = receiver + blake3_secs;
    println!();
    println!(
        "  sender total       {:>8.0} MiB/s  (AEAD x2, hash, leaves, proofs)",
        rate(total, sender)
    );
    println!(
        "  sender before §26.1{:>8.0} MiB/s  (AEAD x3: the pass the cache removed)",
        rate(total, sender_before_cache)
    );
    println!(
        "  receiver total     {:>8.0} MiB/s  (verify+decrypt, control AEAD, streamed digest)",
        rate(total, receiver)
    );
    println!(
        "  receiver on resume {:>8.0} MiB/s  (out of order or resumed: digest re-reads the file)",
        rate(total, receiver_with_reread)
    );
    println!(
        "  pipeline ceiling   {:>8.0} MiB/s  (slower of the two, no network)",
        rate(total, sender.max(receiver))
    );
    println!();
    println!("  Measure end to end with tests/e2e_bench.rs, which pins the path");
    println!("  and prints the route it actually observed. Binding to loopback");
    println!("  is NOT enough: iroh advertises globally routable IPv6 beside");
    println!("  the loopback address and the dialer may take it, so the");
    println!("  advertised address set has to be narrowed. A run that skips");
    println!("  that measures the network, not this code.");
    println!();
}
