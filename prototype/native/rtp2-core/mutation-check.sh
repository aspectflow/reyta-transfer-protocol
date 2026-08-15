#!/usr/bin/env bash
#
# Copyright 2026 The Reyta Labs Authors.
# SPDX-License-Identifier: Apache-2.0
#
# Mutation check: deliberately weaken one security property at a time and
# confirm the test suite catches it. A mutation that survives means the tests
# do not actually pin that property.
#
# Usage: ./mutation-check.sh
set -uo pipefail
cd "$(dirname "$0")"

# Build parallelism. Deliberately below the core count so the machine stays
# usable while this runs; raise it with JOBS=8 ./mutation-check.sh.
JOBS="${JOBS:-3}"

# Per-run wall clock. A mutation may reintroduce a hang rather than a wrong
# answer: D-609 was exactly that: an overflow that turned a loop into an
# infinite one. Without a limit the suite never returns, the harness stops on
# that entry, and every mutation after it goes unchecked. Silently.
#
# A run that exceeds this counts as CAUGHT: the suite did not pass, and "did
# not terminate" is a failure like any other. macOS has no coreutils timeout,
# so this is done with a watchdog rather than by assuming one exists.
RUN_TIMEOUT="${RUN_TIMEOUT:-420}"

# Runs "$@", capturing output, killing it after RUN_TIMEOUT seconds.
# Sets RUN_OUT and returns the exit status; 124 means it was killed.
run_bounded() {
  local out_file rc pid waited
  out_file=$(mktemp)
  "$@" > "$out_file" 2>&1 &
  pid=$!
  waited=0
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$waited" -ge "$RUN_TIMEOUT" ]; then
      kill -9 "$pid" 2>/dev/null
      # Test binaries are children of cargo and outlive it when killed.
      pkill -9 -f "target/quick/deps/" 2>/dev/null
      wait "$pid" 2>/dev/null
      RUN_OUT=$(cat "$out_file"); rm -f "$out_file"
      return 124
    fi
    sleep 1
    waited=$((waited + 1))
  done
  wait "$pid"; rc=$?
  RUN_OUT=$(cat "$out_file"); rm -f "$out_file"
  return $rc
}

BACKUP=$(mktemp -d)
cp -R src "$BACKUP/src"
restore() { rm -rf src && cp -R "$BACKUP/src" src; }
trap 'restore; rm -rf "$BACKUP"' EXIT

# name | file | perl substitution
MUTATIONS=(
  "TH2 drops ClientHello|src/handshake.rs|s/let th2 = crypto::sha384\(&\[TH2_DOMAIN, &ch_bytes, &sh_full, &cf_bare\]\);/let th2 = crypto::sha384(\&[TH2_DOMAIN, \&sh_full, \&cf_bare]);/g"
  "ServerHello signature unchecked|src/handshake.rs|s/        sh\.cert\n            \.hybrid_verify\(&th1, signature\)\n            \.map_err\(\|_\| HandshakeError::InvalidSignature\)\?;/        let _ = (\&sh.cert, \&th1, signature);/s"
  "ClientFinish signature unchecked|src/handshake.rs|s/        client_cert\n            \.hybrid_verify\(&th2, signature\)\n            \.map_err\(\|_\| HandshakeError::InvalidSignature\)\?;/        let _ = (\&client_cert, \&th2, signature);/s"
  "finished_mac_A unchecked|src/handshake.rs|s/        if !crypto::ct_eq\(&mac_a, &expected_a\) \{\n            return Err\(HandshakeError::InvalidMac\);\n        \}/        let _ = (\&mac_a, \&expected_a);/s"
  "PQ branch dropped from combiner|src/handshake.rs|s/    for ss in \[ss_x, ss_pq_a, ss_pq_b\] \{/    for ss in [ss_x, ss_pq_a] {/"
  "replay cache disabled|src/handshake.rs|s/        if !replay\.check_and_insert\(&ch\.cert\.device_id, &ch\.nonce\) \{\n            return Err\(HandshakeError::Replay\);\n        \}/        let _ = replay;/s"
  "Ed25519 branch ignored in hybrid verify|src/identity.rs|s/        vk\.verify\(transcript_hash, &ed_sig\)\n            \.map_err\(\|_\| IdentityError\)\?;/        let _ = vk.verify(transcript_hash, \&ed_sig);/s"
  "ML-DSA branch ignored in hybrid verify|src/identity.rs|s/        pqc::mldsa_verify\(&self\.mldsa, transcript_hash, &sig\.mldsa\)\.map_err\(\|_\| IdentityError\)/        { let _ = pqc::mldsa_verify(\&self.mldsa, transcript_hash, \&sig.mldsa); Ok(()) }/s"
  "chunk AAD drops object_context_hash|src/object.rs|s/    aad\.extend_from_slice\(object_context_hash\);\n//s"
  "chunk AAD drops chunk_index|src/object.rs|s/    aad\.extend_from_slice\(&chunk_index\.to_be_bytes\(\)\);\n//s"
  "chunk nonce ignores index|src/keys.rs|s/        material\.extend_from_slice\(&index\.to_be_bytes\(\)\);\n//s"
  "Merkle proof direction unchecked|src/merkle.rs|s/        if step\.direction != \*expected \{\n            return Err\(ProofError::Malformed\);\n        \}/        let _ = expected;/s"
  "Merkle leaf drops index|src/merkle.rs|s/    h\.update\(&index\.to_be_bytes\(\)\);\n//s"
  "CBOR accepts non-canonical uint|src/cbor.rs|s/                if v < 24 \{\n                    return Err\(CborError::NonCanonical\);\n                \}/                \/\/ mutated/s"
  "envelope accepts unknown suite|src/keys.rs|s/    if suite_id != SUITE_ID as u64 \{\n        return Err\(KeyError\);\n    \}/    \/\/ mutated/s"
  "manifest commitment drops private hash|src/manifest.rs|s/        h\.update\(&self\.private_manifest_ciphertext_hash\);\n//s"
  "manifest commitment drops public body|src/manifest.rs|s/        h\.update\(&self\.encode\(\)\);\n//s"
  "manifest AAD drops recipient scope|src/manifest.rs|s/    aad\.extend_from_slice\(&recipient_scope\.hash\(\)\);\n//s"
  "manifest AAD drops transfer id|src/manifest.rs|s/    aad\.extend_from_slice\(transfer_id\);\n//s"
  "manifest accepts unknown critical field|src/manifest.rs|s/Some\(_\) => return Err\(ManifestError::UnknownCriticalField\),/Some(_) => {},/g"
  "manifest allows classical-only policy|src/manifest.rs|s/        if !self\.key_policy\.pqc_required \|\| self\.key_policy\.minimum_security_level == 0 \{\n            return Err\(ManifestError::InvalidValue\);\n        \}/        \/\/ mutated/s"
  "manifest skips duplicate object id check|src/manifest.rs|s/            if !seen\.insert\(object\.object_id\) \{\n                return Err\(ManifestError::InvalidValue\);\n            \}/            seen.insert(object.object_id);/s"
  "sealed manifest hash ignores nonce|src/manifest.rs|s/        h\.update\(&self\.nonce\);\n//s"
  "offer signature unchecked|src/offer.rs|s/        self\.sender_device\n            \.hybrid_verify\(&hash, &self\.signature\)\n            \.map_err\(\|_\| OfferError::InvalidSignature\)\?;/        let _ = (\&self.sender_device, \&hash, \&self.signature);/s"
  "offer binding drops providers|src/offer.rs|s/    \{\n        let inner = m\.nested\(1\);\n        inner\.array\(providers\.len\(\) as u64\);\n        for p in providers \{\n            let mut pm = MapWriter::begin\(inner, 2\);\n            pm\.uint\(0, p\.kind\);\n            pm\.bytes\(1, &p\.address\);\n            pm\.end\(\);\n        \}\n    \}/    { let inner = m.nested(1); inner.array(0); let _ = providers; }/s"
  "offer binding drops envelopes|src/offer.rs|s/        for env in key_envelopes \{\n            let mut em = MapWriter::begin\(inner, 3\);\n            em\.bytes\(0, &env\.recipient_device_id\);\n            em\.bytes\(1, &env\.nonce\);\n            em\.bytes\(2, &env\.ciphertext\);\n            em\.end\(\);\n        \}/        for _env in key_envelopes {}/s"
  "offer accepts bound-session mode|src/offer.rs|s/        if self\.auth_mode != AuthMode::StandaloneHybridSignature \{\n            return Err\(OfferError::UnsupportedAuthMode\);\n        \}/        \/\/ mutated/s"
  "offer skips scope check|src/offer.rs|s/        if &self\.recipient_scope != expected_scope \{\n            return Err\(OfferError::ScopeMismatch\);\n        \}/        \/\/ mutated/s"
  "offer skips expiry check|src/offer.rs|s/        if now >= public\.expires_at \{\n            return Err\(OfferError::Expired\);\n        \}/        let _ = now;/s"
  "ticket accepts non-canonical base64|src/offer.rs|s/        if unused_bits > 0 && \(n & \(\(1 << unused_bits\) - 1\)\) != 0 \{\n            return Err\(OfferError::Encoding\);\n        \}/        let _ = unused_bits;/s"
  "capability tag compared non-constant-time|src/capability.rs|s/        if !crypto::ct_eq\(&self\.tag, &expected\) \{\n            return Err\(CapabilityError::BadTag\);\n        \}/        let _ = expected;/s"
  "capability skips expiry|src/capability.rs|s/    if now >= body\.expires_at \{\n        return Err\(CapabilityError::Expired\);\n    \}/    \/\/ mutated/s"
  "capability skips operation check|src/capability.rs|s/    if body\.operations & operation == 0 \{\n        return Err\(CapabilityError::OperationNotPermitted\);\n    \}/    \/\/ mutated/s"
  "capability skips object scope|src/capability.rs|s/    if !body\n        \.object_ids\n        \.iter\(\)\n        \.any\(\|id\| crypto::ct_eq\(id, object_id\)\)\n    \{\n        return Err\(CapabilityError::WrongObject\);\n    \}/    \/\/ mutated/s"
  "capability tag loses domain separation|src/capability.rs|s/    message\.extend_from_slice\(TAG_DOMAIN\);\n//s"
  "hello ALPN claim unchecked|src/handshake.rs|s/        if ch\.alpn != crypto::ALPN \{\n            return Err\(HandshakeError::PolicyViolation\);\n        \}/        \/\/ mutated/s"
  "hello handshake mode unchecked|src/handshake.rs|s/        if ch\.handshake_mode != MODE_STANDALONE \{\n            return Err\(HandshakeError::PolicyViolation\);\n        \}/        \/\/ mutated/s"
  "server hello mode and ALPN unchecked|src/handshake.rs|s/        if sh\.handshake_mode != MODE_STANDALONE \|\| sh\.alpn != crypto::ALPN \{\n            return Err\(HandshakeError::PolicyViolation\);\n        \}/        \/\/ mutated/s"
  "hello ALPN dropped from transcript|src/handshake.rs|s/        m\.bytes\(3, &self\.alpn\);\n//s"
  "envelope expiry unchecked|src/keys.rs|s/    if now >= opened\.expires_at \{\n        return Err\(KeyError\);\n    \}/    \/\/ mutated/s"
  "CBOR accepts arbitrary simple values|src/cbor.rs|s/        if major == MAJOR_SIMPLE && value != SIMPLE_FALSE as u64 && value != SIMPLE_TRUE as u64 \{\n            return Err\(CborError::ForbiddenType\);\n        \}/        \/\/ mutated/s"
  "resume accepts a mismatched object|src/resume.rs|s/                Ok\(stored\) if stored\.identity\.matches\(&identity\) => \{/                Ok(stored) if true => {/s"
  "resume record checksum unchecked|src/resume.rs|s/        if !crate::crypto::ct_eq\(checksum, h\.finalize\(\)\.as_bytes\(\)\) \{\n            return Err\(ResumeError::Corrupt\);\n        \}/        \/\/ mutated/s"
  "bitmap trailing bits unchecked|src/bitmap.rs|s/            if last & trailing_mask != 0 \{\n                return Err\(BitmapError::TrailingBitsSet\);\n            \}/            \/\/ mutated/s"
  "RLE run total unchecked|src/bitmap.rs|s/        if index != chunk_count \{\n            return Err\(BitmapError::RunOverflow\);\n        \}/        \/\/ mutated/s"
  "range request overlap unchecked|src/scheduler.rs|s/            if i > 0 && start <= previous_end \{\n                return Err\(SchedulerError::UnsortedOrOverlapping\);\n            \}/            \/\/ mutated/s"
  "range request bounds unchecked|src/scheduler.rs|s/            if end > chunk_count \{\n                return Err\(SchedulerError::OutOfRange\);\n            \}/            \/\/ mutated/s"
  "identity record checksum unchecked|src/store.rs|s/    if !crypto::ct_eq\(checksum, h\.finalize\(\)\.as_bytes\(\)\) \{\n        return Err\(StoreError::Corrupt\);\n    \}/    \/\/ mutated/s"
  "identity record version unchecked|src/store.rs|s/    if version != RECORD_VERSION \{\n        return Err\(StoreError::VersionMismatch\);\n    \}/    \/\/ mutated/s"
  "identity file permissions unchecked|src/store.rs|s/    if meta\.mode\(\) & 0o077 != 0 \{/    if false \&\& meta.mode() \& 0o077 != 0 {/s"
  "identity store follows symlinks|src/store.rs|s/    if !meta\.file_type\(\)\.is_file\(\) \{\n        return Err\(StoreError::NotRegularFile\(path\.display\(\)\.to_string\(\)\)\);\n    \}/    \/\/ mutated/s"
  "protection downgrade accepted|src/store.rs|s/    if protection < minimum \{\n        return Err\(StoreError::ProtectionDowngrade\);\n    \}/    \/\/ mutated/s"
  "sealer AAD drops protection level|src/store.rs|s/    aad\.extend_from_slice\(&protection\.as_u64\(\)\.to_be_bytes\(\)\);\n//s"
  "identity write is not atomic|src/store.rs|s/    std::fs::rename\(&tmp, path\)\.map_err\(io_err\)\?;/    std::fs::copy(\&tmp, path).map_err(io_err)?;/s"
  "device id not derived from the seed|src/identity.rs|s/        let device_id = \*crypto::hkdf_expand::<32>\(&prk, &\[INFO_DEVICE_ID\]\);/        let device_id = os_random_array();/s"
  "identity derivations share one info string|src/identity.rs|s/const INFO_MLDSA: &\[u8\] = b\"RTP2 device mldsa65 v1\";/const INFO_MLDSA: \&[u8] = b\"RTP2 device ed25519 v1\";/s"
  "ML-DSA signing key not wiped|src/pqc.rs|s/        self\.signing\.as_ref_mut\(\)\.zeroize\(\);/        let _ = \&mut self.signing;/s"
  "control AAD drops frame type|src/control.rs|s/    aad\[29\] = frame_type;\n//s"
  "control AAD drops request id|src/control.rs|s/    aad\[31\.\.39\]\.copy_from_slice\(&request_id\.to_be_bytes\(\)\);\n//s"
  "control nonce ignores the counter|src/control.rs|s/    material\[9\.\.17\]\.copy_from_slice\(&counter\.to_be_bytes\(\)\);\n//s"
  "control nonce ignores the direction|src/control.rs|s/    material\[0\] = direction\.byte\(\);\n//s"
  "control counter replay unchecked|src/control.rs|s/        if candidate\.is_none\(\) && counter < self\.receive_watermark \{\n            return Err\(ControlError::Replay\);\n        \}/        \/\/ mutated/s"
  "control stale epoch accepted|src/control.rs|s/        if epoch < self\.keys\.epoch \{\n            return Err\(ControlError::StaleEpoch\);\n        \}/        \/\/ mutated/s"
  "control epoch chain does not advance|src/control.rs|s/    crypto::hkdf_extract\(&salt, current\)/    { let _ = salt; Zeroizing::new(*current) }/s"
  "resumption secret is reusable|src/store.rs|s/        self\.write_resumption_entries\(&entries\)\?;/        \/\/ mutated/s"
  "resumption expiry unchecked|src/store.rs|s/        if now >= candidate\.expires_at\n            \|\| !crypto::ct_eq\(&candidate\.peer_device_id, peer_device_id\)/        if !crypto::ct_eq(\&candidate.peer_device_id, peer_device_id)/s"
  "resumption peer binding unchecked|src/store.rs|s/            \|\| !crypto::ct_eq\(&candidate\.peer_device_id, peer_device_id\)\n//s"
  "resumption lifetime not clamped|src/store.rs|s/        stored\.expires_at = stored\.expires_at\.min\(\n            stored\n                \.created_at\n                \.saturating_add\(RESUMPTION_MAX_LIFETIME_SECS\),\n        \);/        \/\/ mutated/s"
  "resumption keys ignore the accept message|src/handshake.rs|s/    let th_r = crypto::sha384\(&\[RESUME_TH_DOMAIN, hello_bytes, accept_bytes\]\);/    let th_r = crypto::sha384(\&[RESUME_TH_DOMAIN, hello_bytes]); let _ = accept_bytes;/s"
  "AEAD sealer ignores the AAD|src/store.rs|s/                        aad,\n                    \},/                        aad: \&[],\n                    },/g"
  "keystore sealer does not encrypt|src/keystore.rs|s/        self\.inner\.seal\(plaintext, aad\)/        { let _ = aad; Ok(plaintext.to_vec()) }/s"
  "keystore sealer understates its protection|src/keystore.rs|s/impl SecretSealer for KeystoreSealer \{\n    fn protection\(&self\) -> Protection \{\n(.*?)Protection::PlatformKeystore/impl SecretSealer for KeystoreSealer {\n    fn protection(\&self) -> Protection {\n\$1Protection::Plaintext/s"
  "wrapping key is not random|src/keystore.rs|s/        let fresh = Zeroizing::new\(crate::crypto::os_random_array::<WRAPPING_KEY_LEN>\(\)\);/        let fresh = Zeroizing::new([0u8; WRAPPING_KEY_LEN]);/s"
  "keystore item length unchecked|src/keystore.rs|s/            if len != WRAPPING_KEY_LEN as CFIndex \|\| ptr\.is_null\(\) \{\n                return Err\(KeystoreError::MalformedKey\);\n            \}/            if ptr.is_null() { return Err(KeystoreError::MalformedKey); }/s"
  "proof step direction coerced instead of refused|src/transfer.rs|s/            _ => return Err\(TransferError::Protocol\(\"bad proof direction\"\)\),/            _ => Direction::Right,/s"
  "merkle depth checked as a maximum not exactly|src/merkle.rs|s/    if siblings\.len\(\) != expected_dirs\.len\(\) \{/    if siblings.len() > expected_dirs.len() {/s"
  "merkle path split overflows on a huge leaf_count|src/merkle.rs|s/    while k <= \(leaf_count - 1\) \/ 2 \{/    while k * 2 < leaf_count {/s"
  "chunk count ceiling removed|src/object.rs|s/        if chunk_count > MAX_CHUNK_COUNT \{\n            return Err\(ObjectError\);\n        \}/        \/\/ mutated/s"
  # Deliberately absent: a mutation forcing the streamed digest on a resumed
  # transfer. It used to target a `have.set_count() == 0` guard that turned out
  # to decide nothing: the order check and the `next == chunk_count` check
  # already cover the resumed case: so the guard was removed rather than
  # wrapped in a mutation that can never fail. The two checks that do decide
  # are covered by "streamed digest is never fed" and by
  # the_streamed_digest_equals_the_reread_digest.
  "streamed digest is never fed|src/transfer.rs|s/                        hasher\.update\(&plaintext\);\n//s"
  "route policy admits everything|src/route.rs|s/                \| \(RoutePolicy::DirectOnly, Route::Direct\(_\)\)/                | (RoutePolicy::DirectOnly, _)/s"
  "route policy admits an unclassified path|src/route.rs|s/                \| \(\n                    RoutePolicy::LoopbackOnly,\n                    Route::Direct\(AddressClass::Loopback\)\n                \)/                | (_, Route::Unknown)\n                | (\n                    RoutePolicy::LoopbackOnly,\n                    Route::Direct(AddressClass::Loopback)\n                )/s"
  "private addresses classified as loopback|src/route.rs|s/                if v4\.is_loopback\(\) \{/                if v4.is_loopback() || v4.is_private() {/s"
  "relay path reported as direct|src/route.rs|s/            iroh::TransportAddr::Relay\(_\) => Route::Relay,/            iroh::TransportAddr::Relay(_) => Route::Unknown,/s"
  # This one was real, not hypothetical: it is what the first between-device
  # test hit, and it made a transfer over a tunnel report direct/public.
  "carrier address reported as public|src/route.rs|s/                \} else if is_shared_address_space\(v4\) \{\n                    AddressClass::Shared\n//s"
  "shared address range off by one octet|src/route.rs|s/    a == 100 && \(64\.\.=127\)\.contains\(&b\)/    a == 100 \&\& (63..=128).contains(\&b)/s"
  "route grace never waits for an upgrade|src/transfer.rs|s/    if policy\.admits\(initial\) \{\n        return initial;\n    \}/    return initial;/s"
  "route grace waits out the full deadline|src/transfer.rs|s/        if policy\.admits\(route\) \{\n            return route;\n        \}\n        last = route;/        last = route;/s"
  "route grace delays a path it already admits|src/transfer.rs|s/    if policy\.admits\(initial\) \{\n        return initial;\n    \}/    \/\/ mutated/s"
  "route grace reports the path it started with, not the one it gave up on|src/transfer.rs|s/        last = route;\n    \}\n    last/        last = route;\n    }\n    let _ = last; initial/s"
  # The route watch. Every entry here is a property the first between-device
  # test showed we did not actually have.
  "route switch mid-transfer goes unreported|src/transfer.rs|s/        if route != self\.last \{\n            self\.last = route;/        if false \{\n            self.last = route;/s"
  "route watch republishes an unchanged path|src/transfer.rs|s/        if route != self\.last \{/        if true \{/s"
  "policy stops being enforced once bytes flow|src/transfer.rs|s/        if self\.strikes >= ROUTE_WATCH_STRIKES \{\n            return Err\(TransferError::RouteRefused\(route\)\);\n        \}/        \/\/ mutated/s"
  "one blip tears down a healthy transfer|src/transfer.rs|s/const ROUTE_WATCH_STRIKES: u8 = 2;/const ROUTE_WATCH_STRIKES: u8 = 1;/s"
  "route strikes never reset after recovery|src/transfer.rs|s/            self\.strikes = 0;\n            return Ok\(\(\)\);/            return Ok(());/s"
  "route watch looks on every chunk|src/transfer.rs|s/        if now < self\.next_check \{\n            return Ok\(\(\)\);\n        \}/        \/\/ mutated/s"
  # NOT COVERED: "the report names the path the transfer ended on, not the one
  # it opened on". Catching it needs a path that changes during a live
  # transfer, and the chunk loops can only be driven through a real QUIC
  # connection — there is no seam that lets a test move a transfer along while
  # the route changes underneath it. A mutation for it is written and always
  # survives, so it is not listed: a gate that always fails teaches nothing.
  # Closing it means giving the chunk pipeline a seam.
  "route grace config ignored|src/lib.rs|s/    Duration::from_millis\(u64::from\(ms\)\)/    route::DEFAULT_ROUTE_GRACE/s"
  # Durability ordering. The bug these pin was live: the fsync sat behind a
  # condition in the caller that could never be true.
  "resume commits the bitmap before the data is flushed|src/resume.rs|s/        sync_data\(\)\.await\.map_err\(io_err\)\?;\n        self\.checkpoint\(\)/        self.checkpoint()?;\n        sync_data().await.map_err(io_err)?;\n        Ok(())/s"
  "resume commits even when the flush fails|src/resume.rs|s/        sync_data\(\)\.await\.map_err\(io_err\)\?;/        let _ = sync_data().await;/s"
  "resume never flushes at all|src/resume.rs|s/        sync_data\(\)\.await\.map_err\(io_err\)\?;\n//s"
  "route grace zero means no wait|src/lib.rs|s/    if ms == 0 \{\n        return route::DEFAULT_ROUTE_GRACE;\n    \}/    \/\/ mutated/s"
  "route checked after the first byte|src/transfer.rs|s/    if !admission\.policy\.admits\(route\) \{\n        return Err\(TransferError::RouteRefused\(route\)\);\n    \}/    \/\/ mutated/s"
  "ciphertext cache serves the wrong chunk|src/transfer.rs|s/        self\.entries\.get\(index as usize\)\?\.as_deref\(\)/        let _ = index; self.entries.first()?.as_deref()/s"
  "ciphertext cache budget ignored|src/transfer.rs|s/        if ciphertext\.len\(\) > self\.budget_remaining \{\n            return;\n        \}/        \/\/ mutated/s"
  "ciphertext cache keeps a truncated chunk|src/transfer.rs|s/        \*slot = Some\(ciphertext\.to_vec\(\)\);/        *slot = Some(ciphertext[..ciphertext.len().saturating_sub(1)].to_vec());/s"
  "event queue is unbounded|src/events.rs|s/        if inner\.queue\.len\(\) >= MAX_EVENTS \{\n            inner\.evict_one\(\);\n        \}/        \/\/ mutated/s"
  "overflow evicts terminal events first|src/events.rs|s/        let victim = self\.queue\.iter\(\)\.position\(\|e\| !e\.is_terminal\(\)\);/        let victim: Option<usize> = if self.queue.is_empty() { None } else { Some(0) };/s"
  "dropped events are not counted|src/events.rs|s/        self\.unreported_drops = self\.unreported_drops\.saturating_add\(1\);\n//s"
  "progress coalescing ignores the role|src/events.rs|s/            \} => Some\(\(\*transfer_id, \*role\)\),/            } => Some((*transfer_id, ProgressRole::Receiving)),/s"
  "coalescing is counted as a drop|src/events.rs|s/            inner\.queue\.pop_back\(\);\n        \}/            inner.queue.pop_back();\n            inner.unreported_drops += 1;\n        }/s"
  # Deliberately absent: the CFData type check in keystore.rs::find. No input
  # reaches it: kSecReturnData on a generic-password item always yields
  # CFData: so the mutation survives every possible test. Leaving it out is
  # the honest accounting; the check itself stays as a guard for a future
  # query that also returns attributes. See the comment at that line.
  "keystore availability probed by reading|src/keystore.rs|s/            match probe\.delete\(\"com\.reyta\.rtp2\.entitlement-probe\", \"probe\"\) \{/            match probe.find(\"com.reyta.rtp2.entitlement-probe\", \"probe\") {/s"
)

pass=0
survived=0
echo "Running ${#MUTATIONS[@]} mutations with -j $JOBS (lib suite first, integration only if it passes)..."
echo

for entry in "${MUTATIONS[@]}"; do
  IFS='|' read -r name file subst <<< "$entry"

  # A malformed entry used to hang the whole run: with an empty $file, perl
  # reads stdin and waits forever, silently, after the last line of output.
  # An unescaped double quote inside one of these strings is enough to do it,
  # because it ends the bash string early and word-splits the remainder into
  # extra array elements. Fail loudly instead.
  if [ -z "$name" ] || [ -z "$file" ] || [ -z "$subst" ]; then
    printf '  \033[31mMALFORMED\033[0m entry: %s\n' "$entry"
    survived=$((survived + 1))
    continue
  fi
  if [ ! -f "$file" ]; then
    printf '  \033[31mMALFORMED\033[0m %s names a missing file: %s\n' "$name" "$file"
    survived=$((survived + 1))
    continue
  fi

  restore
  before=$(md5 -q "$file" 2>/dev/null || md5sum "$file" | cut -d' ' -f1)
  perl -0pi -e "$subst" "$file"
  after=$(md5 -q "$file" 2>/dev/null || md5sum "$file" | cut -d' ' -f1)

  if [ "$before" = "$after" ]; then
    # A pattern that no longer matches means the property went UNCHECKED this
    # run. The README has always said "a SKIP is not a pass"; until now the
    # harness only printed it and moved on, so a `cargo fmt` that reflowed a
    # matched line could silently retire a mutation and still finish green.
    # Same failure shape as D-612: an instrument that quietly stops measuring.
    printf '  \033[31mSTALE\033[0m  %-46s (pattern did not match: fix it)\n' "$name"
    survived=$((survived + 1))
    continue
  fi

  # Two stages. The lib suite is one binary and holds most of the tests, so a
  # mutation it catches costs one small build instead of relinking every
  # integration binary. Only a mutation that survives the lib suite pays for
  # the full run.
  run_bounded cargo test --profile quick -j "$JOBS" --lib
  lib_rc=$?
  lib_out="$RUN_OUT"

  if [ "$lib_rc" -eq 124 ]; then
    printf '  \033[32mCAUGHT\033[0m  %-46s (lib suite hung, killed after %ss)\n' \
      "$name" "$RUN_TIMEOUT"
    pass=$((pass + 1))
    continue
  fi

  if echo "$lib_out" | grep -q "^error\[E"; then
    printf '  \033[31mSTALE\033[0m  %-46s (did not compile)\n' "$name"
    survived=$((survived + 1))
    continue
  fi

  if [ "$lib_rc" -ne 0 ]; then
    failed=$(echo "$lib_out" | grep -c "^---- .* stdout ----")
    printf '  \033[32mCAUGHT\033[0m  %-46s (%s lib test(s))\n' "$name" "$failed"
    pass=$((pass + 1))
    continue
  fi

  run_bounded cargo test --profile quick -j "$JOBS" --tests
  int_rc=$?
  int_out="$RUN_OUT"

  if [ "$int_rc" -eq 124 ]; then
    printf '  \033[32mCAUGHT\033[0m  %-46s (integration suite hung, killed after %ss)\n' \
      "$name" "$RUN_TIMEOUT"
    pass=$((pass + 1))
    continue
  fi
  if echo "$int_out" | grep -q "^error\[E"; then
    printf '  \033[31mSTALE\033[0m  %-46s (tests did not compile)\n' "$name"
    survived=$((survived + 1))
    continue
  fi
  if [ "$int_rc" -ne 0 ]; then
    failed=$(echo "$int_out" | grep -c "^---- .* stdout ----")
    printf '  \033[32mCAUGHT\033[0m  %-46s (%s integration test(s))\n' "$name" "$failed"
    pass=$((pass + 1))
  else
    printf '  \033[31mSURVIVED\033[0m  %-46s\n' "$name"
    survived=$((survived + 1))
  fi
done

restore
echo
echo "caught: $pass   survived: $survived"
[ "$survived" -eq 0 ] || exit 1
