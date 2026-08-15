// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//! The transport ceiling between two machines, with no RTP/2 code in the way.
//!
//! ```bash
//! raw_quic serve                 # prints an address, waits
//! raw_quic send <addr> <MiB>     # pushes that many MiB, prints the rate
//! ```
//!
//! The address is hex rather than base64 only to avoid pulling a dependency
//! into the crate for the sake of a benchmark.
//!
//! `tests/raw_quic_bench.rs` answers the same question inside one process,
//! where both endpoints share the CPU and the loopback path has no real link.
//! That makes it useless as a ceiling for a transfer between two devices: it
//! measured 104 MiB/s while a real gigabit link carried 81. Optimising against
//! the in-process number would be optimising against an artefact.

use std::time::Instant;

use iroh::{Endpoint, EndpointAddr, endpoint::presets};

const MIB: usize = 1024 * 1024;
const ALPN: &[u8] = b"raw-bench/1";
const WRITE: usize = 256 * 1024;

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("serve") => serve().await,
        Some("send") => {
            let addr = args.get(2).expect("send <addr-hex> <MiB>");
            let mib: usize = args.get(3).expect("send <addr> <MiB>").parse().unwrap();
            send(addr, mib).await;
        }
        _ => {
            eprintln!("usage: raw_quic serve | raw_quic send <addr-hex> <MiB>");
            std::process::exit(2);
        }
    }
}

async fn serve() {
    let endpoint = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let addr = endpoint.addr();
    let mut blob = Vec::new();
    ciborium::into_writer(&addr, &mut blob).unwrap();
    println!("{}", to_hex(&blob));
    eprintln!("waiting");

    let conn = endpoint
        .accept()
        .await
        .unwrap()
        .accept()
        .unwrap()
        .await
        .unwrap();
    let (mut send, mut recv) = conn.accept_bi().await.unwrap();
    let mut total = 0usize;
    let mut buf = vec![0u8; 1 << 20];
    let start = Instant::now();
    while let Some(n) = recv.read(&mut buf).await.unwrap() {
        total += n;
    }
    let secs = start.elapsed().as_secs_f64();
    send.write_all(b"ok").await.unwrap();
    send.finish().ok();
    eprintln!(
        "received {} MiB in {:.2}s = {:.1} MiB/s",
        total / MIB,
        secs,
        total as f64 / MIB as f64 / secs
    );
    // Let the ack drain before the endpoint goes away.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), conn.closed()).await;
}

async fn send(addr_base64: &str, mib: usize) {
    let blob = from_hex(addr_base64.trim()).expect("address is not hex");
    let addr: EndpointAddr = ciborium::from_reader(blob.as_slice()).expect("address blob");

    let endpoint = Endpoint::builder(presets::N0).bind().await.unwrap();
    let payload = vec![7u8; mib * MIB];

    let start = Instant::now();
    let conn = endpoint.connect(addr, ALPN).await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    for c in payload.chunks(WRITE) {
        send.write_all(c).await.unwrap();
    }
    send.finish().ok();
    let mut ack = [0u8; 2];
    let _ = recv.read_exact(&mut ack).await;
    let secs = start.elapsed().as_secs_f64();
    println!(
        "sent {mib} MiB in {secs:.2}s = {:.1} MiB/s",
        mib as f64 / secs
    );
    conn.close(0u32.into(), b"done");
}
