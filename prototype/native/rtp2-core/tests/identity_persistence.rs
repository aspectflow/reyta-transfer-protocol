// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//! Persistent device identity end to end (§7.2, §7.4).

use std::path::PathBuf;
use std::time::Duration;

use iroh::{Endpoint, endpoint::presets};
use rtp2_core::crypto::ALPN;
use rtp2_core::handshake::ReplayCache;
use rtp2_core::store::DeviceStore;
use rtp2_core::transfer;

fn workdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "rtp2-persist-{}-{}-{tag}",
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
fn endpoint_id_is_stable_across_restarts() {
    // Matching a peer certificate against an observed endpoint only works if
    // the endpoint key survives a restart.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let base = workdir("endpoint");
        let state = base.join("device");

        let bind = |secret: [u8; 32]| async move {
            Endpoint::builder(presets::N0)
                .secret_key(iroh::SecretKey::from_bytes(&secret))
                .alpns(vec![ALPN.to_vec()])
                .bind()
                .await
                .unwrap()
        };

        let (first, created) = DeviceStore::open(&state)
            .unwrap()
            .load_or_create_identity()
            .unwrap();
        assert!(!created);
        let ep1 = bind(*first.endpoint_secret()).await;
        let id1 = ep1.id();
        drop(ep1);

        // A "restart": new store, new identity object, same directory.
        let (second, loaded) = DeviceStore::open(&state)
            .unwrap()
            .load_or_create_identity()
            .unwrap();
        assert!(loaded);
        let ep2 = bind(*second.endpoint_secret()).await;
        assert_eq!(id1, ep2.id(), "endpoint id must survive a restart");
        drop(ep2);

        // A different device is a different endpoint.
        let (other, _) = DeviceStore::open(&base.join("other"))
            .unwrap()
            .load_or_create_identity()
            .unwrap();
        let ep3 = bind(*other.endpoint_secret()).await;
        assert_ne!(id1, ep3.id());

        std::fs::remove_dir_all(&base).ok();
    });
}

#[test]
fn transfers_between_persistent_identities_report_the_same_peer() {
    // Two devices transfer twice. Both runs must name the same peer device
    // id, which only holds if the identity persisted.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let base = workdir("transfer");
        let src = base.join("source.bin");
        std::fs::write(&src, vec![0x5au8; 300_000]).unwrap();

        let run = |attempt: u32| {
            let base = base.clone();
            let src = src.clone();
            async move {
                // Fresh stores each time, as a restarted process would have.
                let (sender_id, _) = DeviceStore::open(&base.join("alice"))
                    .unwrap()
                    .load_or_create_identity()
                    .unwrap();
                let (receiver_id, _) = DeviceStore::open(&base.join("bob"))
                    .unwrap()
                    .load_or_create_identity()
                    .unwrap();

                let sender_ep = Endpoint::builder(presets::N0)
                    .secret_key(iroh::SecretKey::from_bytes(&sender_id.endpoint_secret()))
                    .alpns(vec![ALPN.to_vec()])
                    .bind()
                    .await
                    .unwrap();
                let receiver_ep = Endpoint::builder(presets::N0)
                    .secret_key(iroh::SecretKey::from_bytes(&receiver_id.endpoint_secret()))
                    .alpns(vec![ALPN.to_vec()])
                    .bind()
                    .await
                    .unwrap();
                let addr = receiver_ep.addr();
                let dst = base.join(format!("received-{attempt}.bin"));

                let mut replay = ReplayCache::default();
                let recv = transfer::receive_file(
                    &receiver_ep,
                    &receiver_id,
                    &mut replay,
                    &dst,
                    Duration::from_secs(30),
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
                (sent.unwrap(), received.unwrap())
            }
        };

        let (sent1, recv1) = run(1).await;
        let (sent2, recv2) = run(2).await;

        assert_eq!(
            sent1.peer_device_id, sent2.peer_device_id,
            "the sender saw a different receiver on the second run"
        );
        assert_eq!(
            recv1.peer_device_id, recv2.peer_device_id,
            "the receiver saw a different sender on the second run"
        );
        assert_ne!(sent1.peer_device_id, recv1.peer_device_id);
        // Endpoint ids are stable too, which is what the binding needs.
        assert_eq!(sent1.peer_endpoint_id, sent2.peer_endpoint_id);
        assert_eq!(recv1.peer_endpoint_id, recv2.peer_endpoint_id);

        std::fs::remove_dir_all(&base).ok();
    });
}
