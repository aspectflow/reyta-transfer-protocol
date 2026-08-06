// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//! Route policy over a real connection (§16.3.1).
//!
//! The unit tests cover the decision table and the classification, but
//! neither shows the decision is actually applied: a transfer that never
//! consults the policy passes both. This does, over real QUIC.
//!
//! Binding to `127.0.0.1:0` does not keep a transfer local, since iroh binds
//! IPv6 separately and advertises routable addresses beside the loopback one.
//! So these narrow the advertised set rather than trust the bind.
//!
//! All three cases are needed: refusing everything would pass the second
//! alone, admitting everything would pass the other two.

use std::time::Duration;

use iroh::{Endpoint, endpoint::presets};
use rtp2_core::{
    crypto::ALPN,
    handshake::ReplayCache,
    identity::DeviceIdentity,
    route::{AddressClass, Route, RoutePolicy},
    transfer::{self, TransferError},
};

fn workdir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "rtp2-route-{}-{}-{tag}",
        std::process::id(),
        u64::from_be_bytes(rtp2_core::crypto::os_random_array::<8>())
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

async fn attempt(
    loopback: bool,
    policy: RoutePolicy,
    tag: &str,
) -> (
    Result<transfer::TransferReport, TransferError>,
    Result<transfer::TransferReport, TransferError>,
) {
    let dir = workdir(tag);
    let src = dir.join("src.bin");
    let dst = dir.join("dst.bin");
    std::fs::write(&src, vec![0xA5u8; 64 * 1024]).unwrap();

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
    let sender_id = DeviceIdentity::generate();
    let receiver_id = DeviceIdentity::generate();

    let mut addr = receiver_ep.addr();
    if loopback {
        // Loopback candidates only. Binding does not do this, and a routable
        // address left in the set is one the dialer may take.
        addr.addrs
            .retain(|a| matches!(a, iroh::TransportAddr::Ip(ip) if ip.ip().is_loopback()));
        assert!(
            !addr.addrs.is_empty(),
            "a loopback-bound endpoint must advertise a loopback address"
        );
    }
    let mut replay = ReplayCache::default();

    let recv = transfer::receive_file(
        &receiver_ep,
        &receiver_id,
        &mut replay,
        &dst,
        Duration::from_secs(20),
        transfer::ReceiveOptions {
            policy,
            ..Default::default()
        },
    );
    let send = transfer::send_file(&sender_ep, &sender_id, addr, &src, None, policy);
    let out = tokio::join!(send, recv);
    std::fs::remove_dir_all(&dir).ok();
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn a_loopback_bind_is_admitted_by_the_strictest_policy() {
    let (sent, received) = attempt(true, RoutePolicy::LoopbackOnly, "admit").await;
    let sent = sent.expect("a loopback path must satisfy LoopbackOnly");
    let received = received.expect("a loopback path must satisfy LoopbackOnly");

    assert_eq!(sent.route, Route::Direct(AddressClass::Loopback));
    assert_eq!(received.route, Route::Direct(AddressClass::Loopback));
    // Both ends must agree, or the field is useless for telling the user
    // anything.
    assert_eq!(sent.route, received.route);
    assert_eq!(sent.plaintext_digest, received.plaintext_digest);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_non_loopback_path_is_refused_and_says_so() {
    let (sent, received) = attempt(false, RoutePolicy::LoopbackOnly, "refuse").await;

    // Whichever side reports first, it must be a route refusal and not a
    // transport or crypto failure. An application that cannot tell will retry
    // a path that will always be refused.
    let refusal = match (&sent, &received) {
        (Err(e), _) | (_, Err(e)) => e,
        (Ok(report), Ok(_)) => panic!(
            "a {} path completed under LoopbackOnly",
            report.route.describe()
        ),
    };
    match refusal {
        TransferError::RouteRefused(route) => {
            assert_ne!(
                *route,
                Route::Direct(AddressClass::Loopback),
                "a loopback route must not be the one refused"
            );
        }
        other => panic!("expected a route refusal, got {other}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_permissive_policy_admits_the_same_path_it_refused() {
    // The other half: `Any` completes over exactly the path `LoopbackOnly`
    // rejected. Without it, refusing everything would pass the test above.
    let (sent, received) = attempt(false, RoutePolicy::Any, "any").await;
    let sent = sent.expect("RoutePolicy::Any must admit any path");
    let received = received.expect("RoutePolicy::Any must admit any path");

    assert_ne!(
        sent.route,
        Route::Direct(AddressClass::Loopback),
        "this case exists to cover a non-loopback path"
    );
    assert_eq!(sent.route, received.route);
    assert_eq!(sent.plaintext_digest, received.plaintext_digest);
}
