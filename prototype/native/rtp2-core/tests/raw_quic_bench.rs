// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//! Splits the end-to-end gap: how fast is one iroh stream with no RTP/2
//! framing at all?
//!
//! ```bash
//! cargo test --release --test raw_quic_bench -- --nocapture --ignored
//! RTP2_BENCH_LOOPBACK=1 cargo test --release --test raw_quic_bench -- --nocapture --ignored
//! ```
//!
//! The control for `e2e_bench.rs`. No RTP/2 code, so what it reports is the
//! ceiling a transfer cannot beat. Run it first when an end-to-end number
//! looks wrong; it prints the server's address set, because the usual cause
//! is that the endpoints are not on the path assumed.

use std::time::Instant;

use iroh::{Endpoint, endpoint::presets};

const MIB: usize = 1024 * 1024;
const SIZE: usize = 64 * MIB;
const ALPN: &[u8] = b"raw-bench/1";

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn raw_stream_throughput() {
    let loopback = std::env::var("RTP2_BENCH_LOOPBACK").is_ok();
    let server = if loopback {
        Endpoint::builder(presets::Minimal)
            .alpns(vec![ALPN.to_vec()])
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap()
    } else {
        Endpoint::builder(presets::Minimal)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .unwrap()
    };
    let client = if loopback {
        Endpoint::builder(presets::Minimal)
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap()
    } else {
        Endpoint::builder(presets::Minimal).bind().await.unwrap()
    };
    let addr = server.addr();
    println!("  server addr: {addr:?}");

    for &frame in &[0usize, 64 * 1024, 256 * 1024] {
        let payload = vec![7u8; SIZE];
        let srv = server.clone();
        let recv_task = tokio::spawn(async move {
            let conn = srv.accept().await.unwrap().accept().unwrap().await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let mut total = 0usize;
            let mut buf = vec![0u8; 1 << 20];
            while let Some(n) = recv.read(&mut buf).await.unwrap() {
                total += n;
            }
            send.write_all(b"ok").await.unwrap();
            send.finish().ok();
            total
        });

        let start = Instant::now();
        let conn = client.connect(addr.clone(), ALPN).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        if frame == 0 {
            send.write_all(&payload).await.unwrap();
        } else {
            for c in payload.chunks(frame) {
                send.write_all(c).await.unwrap();
            }
        }
        send.finish().ok();
        let mut ack = [0u8; 2];
        let _ = recv.read_exact(&mut ack).await;
        let total = recv_task.await.unwrap();
        let secs = start.elapsed().as_secs_f64();
        assert_eq!(total, SIZE);
        let label = if frame == 0 {
            "one write_all".to_string()
        } else {
            format!("{} KiB writes", frame / 1024)
        };
        println!(
            "  {label:<20} {:>8.1} MiB/s   ({:.2}s)",
            SIZE as f64 / MIB as f64 / secs,
            secs
        );
        conn.close(0u32.into(), b"done");
    }
}

/// Whether one stream is the limit, or the endpoint is.
///
/// The end-to-end transfer sits within 2% of a single stream, so no amount of
/// work on the RTP/2 pipeline can make it faster — the question is whether the
/// transport itself has anything left. If N concurrent streams move the same
/// bytes faster than one, splitting an object across streams is worth
/// building. If they do not, this endpoint is saturated and the ceiling is not
/// ours to raise.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn concurrent_stream_throughput() {
    let server = Endpoint::builder(presets::Minimal)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let client = Endpoint::builder(presets::Minimal).bind().await.unwrap();
    let addr = server.addr();

    for &streams in &[1usize, 2, 4, 8] {
        // Same total bytes every time, so the numbers compare directly.
        let per_stream = SIZE / streams;
        let srv = server.clone();
        let recv_task = tokio::spawn(async move {
            let conn = srv.accept().await.unwrap().accept().unwrap().await.unwrap();
            let mut tasks = Vec::new();
            for _ in 0..streams {
                let (_, mut recv) = conn.accept_bi().await.unwrap();
                tasks.push(tokio::spawn(async move {
                    let mut total = 0usize;
                    let mut buf = vec![0u8; 1 << 20];
                    while let Some(n) = recv.read(&mut buf).await.unwrap() {
                        total += n;
                    }
                    total
                }));
            }
            let mut total = 0usize;
            for t in tasks {
                total += t.await.unwrap();
            }
            total
        });

        let start = Instant::now();
        let conn = client.connect(addr.clone(), ALPN).await.unwrap();
        let mut senders = Vec::new();
        for _ in 0..streams {
            let (mut send, _) = conn.open_bi().await.unwrap();
            senders.push(tokio::spawn(async move {
                let payload = vec![7u8; per_stream];
                for c in payload.chunks(256 * 1024) {
                    send.write_all(c).await.unwrap();
                }
                send.finish().ok();
            }));
        }
        for s in senders {
            s.await.unwrap();
        }
        let total = recv_task.await.unwrap();
        let secs = start.elapsed().as_secs_f64();
        assert_eq!(total, per_stream * streams);
        println!(
            "  {streams} stream(s){:<8} {:>8.1} MiB/s   ({:.2}s)",
            "",
            total as f64 / MIB as f64 / secs,
            secs
        );
        conn.close(0u32.into(), b"done");
    }
}
