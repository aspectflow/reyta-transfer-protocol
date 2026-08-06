// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end throughput, measured over a pinned path.
//!
//! ```bash
//! cargo test --release --test e2e_bench -- --nocapture --ignored
//! ```
//!
//! `tests/throughput.rs` times the crypto with no network. This times the
//! whole transfer, so the two agree only when the transport is not the
//! bottleneck.
//!
//! Binding to `127.0.0.1` does not keep a transfer local: iroh binds IPv6
//! separately and advertises routable addresses beside the loopback one, so a
//! run that only binds can report a "loopback" number measured over the
//! network. The local case narrows the advertised set and prints the route it
//! saw, with the host path beside it for contrast.

use std::time::Instant;

use iroh::{Endpoint, endpoint::presets};
use rtp2_core::{crypto::ALPN, handshake::ReplayCache, identity::DeviceIdentity, transfer};

const MIB: usize = 1024 * 1024;
const SIZE: usize = 64 * MIB;

async fn run(label: &str, loopback: bool) {
    let dir = std::env::temp_dir().join(format!(
        "rtp2-e2e-{}-{}",
        std::process::id(),
        label.replace(' ', "-")
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("src.bin");
    let dst = dir.join("dst.bin");
    let payload: Vec<u8> = (0..SIZE).map(|i| (i % 251) as u8).collect();
    std::fs::write(&src, &payload).unwrap();

    let sender_id = DeviceIdentity::generate();
    let receiver_id = DeviceIdentity::generate();

    let build = || {
        let b = Endpoint::builder(presets::Minimal).alpns(vec![ALPN.to_vec()]);
        if loopback {
            b.bind_addr("127.0.0.1:0").unwrap()
        } else {
            b
        }
    };
    let sender_ep = build().bind().await.unwrap();
    let receiver_ep = build().bind().await.unwrap();
    let mut addr = receiver_ep.addr();
    if loopback {
        // Binding alone leaves routable IPv6 candidates in the set and the
        // dialer may take one. Narrow it or this measures the network.
        addr.addrs
            .retain(|a| matches!(a, iroh::TransportAddr::Ip(ip) if ip.ip().is_loopback()));
        assert!(
            !addr.addrs.is_empty(),
            "no loopback address to measure over"
        );
    }
    let mut replay = ReplayCache::default();

    let start = Instant::now();
    let recv = transfer::receive_file(
        &receiver_ep,
        &receiver_id,
        &mut replay,
        &dst,
        std::time::Duration::from_secs(180),
        transfer::ReceiveOptions::default(),
    );
    let send = transfer::send_file(
        &sender_ep,
        &sender_id,
        addr,
        &src,
        None,
        rtp2_core::route::RoutePolicy::Any,
    );
    let (sent, received) = tokio::join!(send, recv);
    let sent = sent.unwrap();
    let received = received.unwrap();
    let secs = start.elapsed().as_secs_f64();

    // A number from a transfer that did not verify means nothing.
    assert_eq!(sent.plaintext_digest, received.plaintext_digest);
    assert_eq!(sent.ciphertext_root, received.ciphertext_root);
    assert_eq!(std::fs::read(&dst).unwrap(), payload);

    println!(
        "  {label:<34} {:>7.1} MiB/s   ({:.2}s)   route={}",
        SIZE as f64 / MIB as f64 / secs,
        secs,
        received.route.describe()
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn end_to_end_throughput() {
    println!("\n  {} MiB, two endpoints in one process\n", SIZE / MIB);
    run("loopback (measures this code)", true).await;
    run("host network (measures the network)", false).await;
    println!();
}
