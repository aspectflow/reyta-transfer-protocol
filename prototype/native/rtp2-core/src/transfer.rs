// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//! Single-object transfer over an Iroh QUIC bidirectional stream.
//!
//! Wire framing (prototype contract):
//!
//!   frame := U32BE(len) || u8(type) || payload           len = 1 + payload
//!   0x02 TRANSFER_OFFER  0x05 RANGE_REQUEST  0x21 CHUNK_RECORD
//!   0x23 STREAM_END      0x0A COMPLETE
//!   0x81..0x84 handshake (pre-session, outside the §17.4 catalog)
//!
//! Everything after ServerFinish carries only ciphertext and public transfer
//! mechanics; file keys travel exclusively inside the §9.5 envelope. The
//! endpoint uses the public n0 preset for bootstrap connectivity; the
//! transport below is independent of that choice.

use std::path::Path;
use std::time::Duration;

use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::{
    bitmap,
    cbor::{MapWriter, Reader, Writer},
    control::{ControlChannel, Direction as ControlDirection},
    crypto::ALPN,
    events::{Event, EventQueue, ProgressRole},
    handshake::{Initiator, ReplayCache, Responder, SessionKeys},
    identity::DeviceIdentity,
    keys::{self, FileSecrets, SealedEnvelope},
    manifest,
    merkle::{self, Direction, ProofStep},
    object::{self, ObjectContext},
    offer, resume,
    route::{Route, RouteAdmission, RoutePolicy},
    scheduler::{RangeRequest, Scheduler},
};

/// Recommended mobile default (§10.2).
pub const DEFAULT_CHUNK_SIZE: u32 = 256 * 1024;
/// Frame ceiling: 4 MiB max chunk + AEAD tag + proof + header slack.
const MAX_FRAME: u32 = 8 * 1024 * 1024;
/// Per-frame IO timeout.
const FRAME_TIMEOUT: Duration = Duration::from_secs(60);
/// Envelope lifetime for the prototype.
const ENVELOPE_TTL_SECS: u64 = 3600;

// Frame types from the §17.4 catalog.
const FRAME_OFFER: u8 = 0x02; // TRANSFER_OFFER
const FRAME_RANGE_REQUEST: u8 = 0x05; // RANGE_REQUEST
const FRAME_COMPLETE: u8 = 0x0A; // COMPLETE
const FRAME_CHUNK: u8 = 0x21; // CHUNK_RECORD
const FRAME_STREAM_END: u8 = 0x23; // STREAM_END

// Handshake frames precede the control stream, so they are outside the §17.4
// catalog. They occupy an unassigned block reserved for pre-session use.
const FRAME_CLIENT_HELLO: u8 = 0x81;
const FRAME_SERVER_HELLO: u8 = 0x82;
const FRAME_CLIENT_FINISH: u8 = 0x83;
const FRAME_SERVER_FINISH: u8 = 0x84;

#[derive(Debug)]
pub enum TransferError {
    Io(String),
    Handshake,
    Protocol(&'static str),
    Crypto(&'static str),
    Timeout,
    /// The path does not satisfy the caller's `RoutePolicy`. Nothing is
    /// wrong with the peer, the crypto or the file: the application asked not
    /// to send over this kind of path.
    RouteRefused(Route),
}

impl std::fmt::Display for TransferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransferError::Io(e) => write!(f, "io: {e}"),
            TransferError::Handshake => write!(f, "handshake failed"),
            TransferError::Protocol(m) => write!(f, "protocol: {m}"),
            TransferError::Crypto(m) => write!(f, "crypto: {m}"),
            TransferError::Timeout => write!(f, "timed out"),
            TransferError::RouteRefused(route) => {
                write!(f, "route {} refused by policy", route.describe())
            }
        }
    }
}

fn io_err<E: std::fmt::Display>(e: E) -> TransferError {
    TransferError::Io(e.to_string())
}

/// Completed-transfer summary handed to the application layer. Contains no
/// key material (§25.1).
pub struct TransferReport {
    pub transfer_id: [u8; 32],
    pub object_id: [u8; 32],
    pub manifest_commitment: [u8; 32],
    pub ciphertext_root: [u8; 32],
    pub plaintext_digest: [u8; 32],
    pub bytes: u64,
    pub chunks: u64,
    /// Chunks that crossed the wire this attempt. Below `chunks` when a
    /// resume skipped already-verified ones.
    pub chunks_transferred: u64,
    pub peer_device_id: [u8; 32],
    pub peer_endpoint_id: [u8; 32],
    /// The path the bytes took, as it stood when the transfer finished.
    /// Always reported, policy or not: an application still has to tell the
    /// user where the file went.
    ///
    /// A connection can start relayed and go direct once holepunching lands,
    /// so this is the last path observed rather than the first. Every change
    /// along the way was published as a `TransferRoute` event; an application
    /// that needs the whole history reads those.
    pub route: Route,
}

// ---------------------------------------------------------------------------
// Framing (§17.1)
// ---------------------------------------------------------------------------
//
//   frame_length  U32BE, counts every byte after itself
//   frame_type    U8
//   frame_flags   U8
//   reserved      U16BE, MUST be zero
//   request_id    U64BE
//   epoch         U64BE   ) present on protected frames only; the receiver
//   counter       U64BE   ) needs both to rebuild the §17.1.1 nonce
//   frame_body    the rest
//
// A fixed U32BE rather than a QUIC varint: §17.1 caps a body at 4 MiB + 4 KiB,
// so the varint's range is unusable and a fixed width removes a parser branch
// that runs before any authentication.

const FRAME_HEADER_LEN: usize = 4 + 1 + 1 + 2 + 8;

/// §17.1 body limits, enforced before any allocation.
const MAX_CONTROL_BODY: u32 = 1024 * 1024;
const MAX_DATA_BODY: u32 = 4 * 1024 * 1024 + 4 * 1024;

/// `NONCRITICAL`: an unknown frame type carrying it MAY be ignored.
const FLAG_NONCRITICAL: u8 = 0x01;

fn body_limit(frame_type: u8) -> u32 {
    match frame_type {
        FRAME_CHUNK => MAX_DATA_BODY,
        _ => MAX_CONTROL_BODY,
    }
}

fn header_bytes(
    frame_type: u8,
    frame_flags: u8,
    request_id: u64,
    body_len: usize,
    extra: usize,
) -> Result<[u8; FRAME_HEADER_LEN], TransferError> {
    let after_length = 1 + 1 + 2 + 8 + extra + body_len;
    let len =
        u32::try_from(after_length).map_err(|_| TransferError::Protocol("frame too large"))?;
    if len > MAX_FRAME {
        return Err(TransferError::Protocol("frame too large"));
    }
    let mut head = [0u8; FRAME_HEADER_LEN];
    head[0..4].copy_from_slice(&len.to_be_bytes());
    head[4] = frame_type;
    head[5] = frame_flags;
    // head[6..8] reserved, already zero.
    head[8..16].copy_from_slice(&request_id.to_be_bytes());
    Ok(head)
}

/// A frame as it arrives, before any unsealing.
struct RawFrame {
    frame_type: u8,
    frame_flags: u8,
    request_id: u64,
    body: Vec<u8>,
}

/// Sends an unprotected frame. Handshake only, since no control key exists
/// yet.
async fn send_plain_frame(
    send: &mut iroh::endpoint::SendStream,
    frame_type: u8,
    payload: &[u8],
) -> Result<(), TransferError> {
    let head = header_bytes(frame_type, 0, 0, payload.len(), 0)?;
    send.write_all(&head).await.map_err(io_err)?;
    send.write_all(payload).await.map_err(io_err)?;
    Ok(())
}

async fn recv_raw_frame(
    recv: &mut iroh::endpoint::RecvStream,
    protected: bool,
) -> Result<(RawFrame, u64, u64), TransferError> {
    let fut = async {
        let mut head = [0u8; FRAME_HEADER_LEN];
        recv.read_exact(&mut head).await.map_err(io_err)?;
        let declared = u32::from_be_bytes(head[0..4].try_into().unwrap());
        let frame_type = head[4];
        let frame_flags = head[5];
        // Reserved must be zero, and a bit outside NONCRITICAL is an unknown
        // flag we must not guess at.
        if head[6] != 0 || head[7] != 0 || frame_flags & !FLAG_NONCRITICAL != 0 {
            return Err(TransferError::Protocol("reserved bits set"));
        }
        let request_id = u64::from_be_bytes(head[8..16].try_into().unwrap());

        let fixed = (FRAME_HEADER_LEN - 4) as u32 + if protected { 16 } else { 0 };
        if declared < fixed {
            return Err(TransferError::Protocol("bad frame length"));
        }
        let body_len = declared - fixed;
        // Limit check before the allocation, not after.
        if body_len > body_limit(frame_type) {
            return Err(TransferError::Protocol("frame body exceeds its limit"));
        }

        let (epoch, counter) = if protected {
            let mut meta = [0u8; 16];
            recv.read_exact(&mut meta).await.map_err(io_err)?;
            (
                u64::from_be_bytes(meta[0..8].try_into().unwrap()),
                u64::from_be_bytes(meta[8..16].try_into().unwrap()),
            )
        } else {
            (0, 0)
        };

        let mut body = vec![0u8; body_len as usize];
        recv.read_exact(&mut body).await.map_err(io_err)?;
        Ok((
            RawFrame {
                frame_type,
                frame_flags,
                request_id,
                body,
            },
            epoch,
            counter,
        ))
    };
    tokio::time::timeout(FRAME_TIMEOUT, fut)
        .await
        .map_err(|_| TransferError::Timeout)?
}

async fn expect_plain_frame(
    recv: &mut iroh::endpoint::RecvStream,
    expected: u8,
) -> Result<Vec<u8>, TransferError> {
    let (frame, _, _) = recv_raw_frame(recv, false).await?;
    if frame.frame_type != expected {
        return Err(TransferError::Protocol("unexpected frame type"));
    }
    Ok(frame.body)
}

/// Sends a frame protected under the current control epoch (§17.1.1).
async fn send_frame(
    send: &mut iroh::endpoint::SendStream,
    control: &mut ControlChannel,
    frame_type: u8,
    payload: &[u8],
) -> Result<(), TransferError> {
    let sealed = control
        .seal(frame_type, 0, 0, payload)
        .map_err(|_| TransferError::Crypto("control frame"))?;
    let head = header_bytes(frame_type, 0, 0, sealed.ciphertext.len(), 16)?;

    // One write, not three. Each `write_all` takes the connection's lock, and
    // a profile of a 256 MiB transfer put 71% of the sender's samples waiting
    // on it — three acquisitions per frame, 3072 for the transfer, to move
    // bytes that were ready all along. The wire format is unchanged: the same
    // header, the same 16-byte epoch/counter, the same ciphertext, in the same
    // order. Only the number of times we ask for the lock changes.
    let mut frame = Vec::with_capacity(head.len() + 16 + sealed.ciphertext.len());
    frame.extend_from_slice(&head);
    frame.extend_from_slice(&sealed.epoch.to_be_bytes());
    frame.extend_from_slice(&sealed.counter.to_be_bytes());
    frame.extend_from_slice(&sealed.ciphertext);

    send.write_all(&frame).await.map_err(io_err)?;
    Ok(())
}

async fn recv_frame(
    recv: &mut iroh::endpoint::RecvStream,
    control: &mut ControlChannel,
) -> Result<(u8, Vec<u8>), TransferError> {
    let (frame, epoch, counter) = recv_raw_frame(recv, true).await?;
    let body = control
        .open(
            epoch,
            counter,
            frame.frame_type,
            frame.frame_flags,
            frame.request_id,
            &frame.body,
        )
        .map_err(|_| TransferError::Crypto("control frame"))?;
    Ok((frame.frame_type, body))
}

async fn expect_frame(
    recv: &mut iroh::endpoint::RecvStream,
    control: &mut ControlChannel,
    expected: u8,
) -> Result<Vec<u8>, TransferError> {
    let (t, payload) = recv_frame(recv, control).await?;
    if t != expected {
        return Err(TransferError::Protocol("unexpected frame type"));
    }
    Ok(payload)
}

// ---------------------------------------------------------------------------
// Chunk record / ack encoding
// ---------------------------------------------------------------------------
//
// A transfer opens with a §14.1 TransferOffer (`offer::TransferOffer`): the
// public manifest, the encrypted private manifest, one §9.5 key envelope per
// recipient device, the provider list, and the sender's hybrid signature.

fn encode_chunk_record(index: u64, proof: &[ProofStep], ciphertext: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    let mut m = MapWriter::begin(&mut w, 3);
    m.uint(0, index);
    {
        // `[direction, hash32]`, not a packed 33-byte string, so a decoder
        // in any language can constrain the direction declaratively instead of
        // reimplementing a layout.
        let inner = m.nested(1);
        inner.array(proof.len() as u64);
        for step in proof {
            inner.array(2);
            inner.uint(match step.direction {
                Direction::Left => 0,
                Direction::Right => 1,
            });
            inner.bytes(&step.hash);
        }
    }
    m.bytes(2, ciphertext);
    m.end();
    w.into_bytes()
}

fn decode_chunk_record(bytes: &[u8]) -> Result<(u64, Vec<ProofStep>, Vec<u8>), TransferError> {
    let bad = |_| TransferError::Protocol("bad chunk record");
    let mut r = Reader::new_unbounded(bytes);
    let mut m = r.map().map_err(bad)?;
    m.expect_key(0).map_err(bad)?;
    let index = m.reader.uint().map_err(bad)?;
    m.expect_key(1).map_err(bad)?;
    let n = m.reader.array().map_err(bad)?;
    if n > 64 {
        return Err(TransferError::Protocol("proof too deep"));
    }
    let mut proof = Vec::with_capacity(n as usize);
    for _ in 0..n {
        if m.reader.array().map_err(bad)? != 2 {
            return Err(TransferError::Protocol("bad proof step"));
        }
        // Two values, and anything else is refused rather than coerced:
        // folding 2 into RIGHT would accept a proof no encoder produces.
        let direction = match m.reader.uint().map_err(bad)? {
            0 => Direction::Left,
            1 => Direction::Right,
            _ => return Err(TransferError::Protocol("bad proof direction")),
        };
        let hash = m.reader.bytes_exact::<32>().map_err(bad)?;
        proof.push(ProofStep { direction, hash });
    }
    m.reader.leave();
    m.expect_key(2).map_err(bad)?;
    let ciphertext = m.reader.bytes().map_err(bad)?.to_vec();
    if m.next_key().map_err(bad)?.is_some() {
        return Err(TransferError::Protocol("bad chunk record"));
    }
    r.finish().map_err(bad)?;
    Ok((index, proof, ciphertext))
}

fn encode_ack(status: u64, digest: &[u8; 32]) -> Vec<u8> {
    let mut w = Writer::new();
    let mut m = MapWriter::begin(&mut w, 2);
    m.uint(0, status);
    m.bytes(1, digest);
    m.end();
    w.into_bytes()
}

fn decode_ack(bytes: &[u8]) -> Result<(u64, [u8; 32]), TransferError> {
    let bad = |_| TransferError::Protocol("bad ack");
    let mut r = Reader::new(bytes).map_err(bad)?;
    let mut m = r.map().map_err(bad)?;
    m.expect_key(0).map_err(bad)?;
    let status = m.reader.uint().map_err(bad)?;
    m.expect_key(1).map_err(bad)?;
    let digest = m.reader.bytes_exact::<32>().map_err(bad)?;
    if m.next_key().map_err(bad)?.is_some() {
        return Err(TransferError::Protocol("bad ack"));
    }
    r.finish().map_err(bad)?;
    Ok((status, digest))
}

// ---------------------------------------------------------------------------
// Sender
// ---------------------------------------------------------------------------

/// One object prepared for sending: its §9.1 secrets, §10.5 context, Merkle
/// leaves and root, computed once.
///
/// Reusable across attempts, which is what makes receiver-side resume work: a
/// re-offer keeps the same ids and root, so the receiver asks only for what it
/// is missing (§18.3). The secrets stay in memory; persisting them would put a
/// file master key at rest, which §28.1 does not permit.
pub struct PendingTransfer {
    path: std::path::PathBuf,
    secrets: FileSecrets,
    ctx: ObjectContext,
    ctx_hash: [u8; 32],
    schedule: crate::keys::FileKeySchedule,
    leaves: Vec<[u8; 32]>,
    ciphertext_root: [u8; 32],
    plaintext_digest: [u8; 32],
    /// §26.1. Populated by `prepare`, read by `send_pending`.
    cache: CiphertextCache,
}

/// §26.1 ciphertext-first cache: chunks encrypted during `prepare`, kept so
/// `send_pending` does not encrypt them a second time.
///
/// The first pass is unavoidable: the root goes in the manifest, so everything
/// is encrypted before the first chunk ships. Recomputing it afterwards was a
/// third of the sender's work. Bounded, so a large object is not held whole in
/// memory; past the budget the sender recomputes.
struct CiphertextCache {
    /// `entries[i]` is `Some` when chunk `i` is cached.
    entries: Vec<Option<Vec<u8>>>,
    budget_remaining: usize,
}

impl CiphertextCache {
    /// Default budget: an ordinary photo or document fits whole, and a large
    /// file is capped.
    const DEFAULT_BUDGET: usize = 64 * 1024 * 1024;

    fn new(chunk_count: u64, budget: usize) -> Self {
        Self {
            entries: (0..chunk_count).map(|_| None).collect(),
            budget_remaining: budget,
        }
    }

    /// Stores a chunk if there is room. Declining costs a recomputation
    /// later, never correctness.
    fn insert(&mut self, index: u64, ciphertext: &[u8]) {
        if ciphertext.len() > self.budget_remaining {
            return;
        }
        let Some(slot) = self.entries.get_mut(index as usize) else {
            return;
        };
        self.budget_remaining -= ciphertext.len();
        *slot = Some(ciphertext.to_vec());
    }

    fn get(&self, index: u64) -> Option<&[u8]> {
        self.entries.get(index as usize)?.as_deref()
    }

    #[cfg(test)]
    fn cached_chunks(&self) -> usize {
        self.entries.iter().filter(|e| e.is_some()).count()
    }
}

impl PendingTransfer {
    /// Encrypts every chunk once to obtain the Merkle leaves, the root and the
    /// plaintext digest (§10.4, §12).
    pub async fn prepare(path: &Path, chunk_size: u32) -> Result<Self, TransferError> {
        let file_len = tokio::fs::metadata(path).await.map_err(io_err)?.len();
        let secrets = FileSecrets::generate();
        let ctx =
            ObjectContext::for_file(secrets.transfer_id, secrets.object_id, file_len, chunk_size)
                .map_err(|_| TransferError::Crypto("object context"))?;
        let ctx_hash = ctx.context_hash();
        let schedule = secrets.key_schedule();

        let mut file = File::open(path).await.map_err(io_err)?;
        let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(ctx.chunk_count as usize);
        let mut plain_hasher = blake3::Hasher::new();
        let mut buf = vec![0u8; ctx.chunk_plaintext_size as usize];
        let mut cache = CiphertextCache::new(ctx.chunk_count, CiphertextCache::DEFAULT_BUDGET);
        for index in 0..ctx.chunk_count {
            let len = ctx.chunk_len(index).unwrap() as usize;
            file.read_exact(&mut buf[..len]).await.map_err(io_err)?;
            plain_hasher.update(&buf[..len]);
            let ciphertext = object::encrypt_chunk(&schedule, &ctx, &ctx_hash, index, &buf[..len])
                .map_err(|_| TransferError::Crypto("chunk encryption"))?;
            leaves.push(merkle::leaf_hash(index, &ciphertext));
            cache.insert(index, &ciphertext);
        }

        Ok(Self {
            path: path.to_path_buf(),
            ciphertext_root: merkle::merkle_root(&leaves),
            plaintext_digest: *plain_hasher.finalize().as_bytes(),
            secrets,
            ctx,
            ctx_hash,
            schedule,
            leaves,
            cache,
        })
    }

    pub fn transfer_id(&self) -> [u8; 32] {
        self.secrets.transfer_id
    }

    pub fn object_id(&self) -> [u8; 32] {
        self.secrets.object_id
    }

    pub fn ciphertext_root(&self) -> [u8; 32] {
        self.ciphertext_root
    }

    pub fn chunk_count(&self) -> u64 {
        self.ctx.chunk_count
    }

    pub fn chunk_ciphertext_size(&self) -> u64 {
        self.ctx.chunk_ciphertext_size()
    }

    pub fn logical_plaintext_size(&self) -> u64 {
        self.ctx.logical_plaintext_size
    }
}

/// Classifies the path a live connection is using. A custom address stays
/// `Unknown` rather than being folded into `Direct` or `Relay`: no policy
/// decision should rest on a guess.
fn observe_route(conn: &Connection) -> Route {
    // The selected path, not just an open one. A connection often holds both
    // a relay and, after holepunching, a direct path; only the selected one
    // carries bytes.
    let paths = conn.paths();
    let Some(selected) = paths.iter().find(|p| p.is_selected()) else {
        return Route::Unknown;
    };
    Route::of_transport(selected.remote_addr())
}

/// Reports the route, then refuses it if policy says so. The event comes
/// first on purpose: an application that gets refused still needs to know what
/// it was refused for.
async fn admit_route(
    conn: &Connection,
    transfer_id: [u8; 32],
    admission: RouteAdmission,
    events: Option<&EventQueue>,
) -> Result<Route, TransferError> {
    let route = await_admissible_route(conn, admission, observe_route(conn)).await;

    if let Some(q) = events {
        q.push(Event::TransferRoute {
            transfer_id,
            route: route.as_u64(),
            address_class: route.address_class().map(|c| c.as_u64()),
        });
    }
    if !admission.policy.admits(route) {
        return Err(TransferError::RouteRefused(route));
    }
    Ok(route)
}

/// Keeps the reported route honest for the length of a transfer, and keeps the
/// policy in force for it.
///
/// Admitting the path once, at the start, was wrong twice over. It reported a
/// route that could stop being true a second later — the first transfer
/// between two devices behind NAT was reported as relayed, and nothing in the
/// implementation could say whether it stayed that way. And it enforced a
/// policy that a connection is free to violate afterwards: a path can fall
/// back to a relay mid-transfer, which is precisely what `DirectOnly` exists
/// to prevent, happening at precisely the time nobody was looking.
struct RouteWatch {
    last: Route,
    admission: RouteAdmission,
    next_check: tokio::time::Instant,
    /// Consecutive observations the policy refused. A path momentarily has no
    /// selected candidate — during migration, for one — and reads as
    /// `Unknown`; tearing a transfer down over that would turn a hiccup into a
    /// failure. Two in a row is a path that changed, not one in transition.
    strikes: u8,
}

/// How often the path is re-examined mid-transfer. Frequent enough that a
/// switch is reported while it still matters, rare enough to disappear beside
/// the AEAD work between checks.
const ROUTE_WATCH_INTERVAL: Duration = Duration::from_millis(500);

/// Refusals needed before a transfer in flight is torn down.
const ROUTE_WATCH_STRIKES: u8 = 2;

impl RouteWatch {
    fn new(initial: Route, admission: RouteAdmission) -> Self {
        Self {
            last: initial,
            admission,
            next_check: tokio::time::Instant::now() + ROUTE_WATCH_INTERVAL,
            strikes: 0,
        }
    }

    /// Called from the chunk loops. Cheap when it is not yet time to look.
    fn poll(
        &mut self,
        conn: &Connection,
        transfer_id: [u8; 32],
        events: Option<&EventQueue>,
    ) -> Result<(), TransferError> {
        self.poll_with(transfer_id, events, || observe_route(conn))
    }

    /// The decision, with the connection replaced by a closure reporting the
    /// current path — so switching, reporting and the strike count can be
    /// tested without arranging a real path change on a real network.
    fn poll_with(
        &mut self,
        transfer_id: [u8; 32],
        events: Option<&EventQueue>,
        observe: impl FnOnce() -> Route,
    ) -> Result<(), TransferError> {
        let now = tokio::time::Instant::now();
        if now < self.next_check {
            return Ok(());
        }
        self.next_check = now + ROUTE_WATCH_INTERVAL;

        let route = observe();
        if route != self.last {
            self.last = route;
            if let Some(q) = events {
                q.push(Event::TransferRoute {
                    transfer_id,
                    route: route.as_u64(),
                    address_class: route.address_class().map(|c| c.as_u64()),
                });
            }
        }

        if self.admission.policy.admits(route) {
            self.strikes = 0;
            return Ok(());
        }
        self.strikes = self.strikes.saturating_add(1);
        if self.strikes >= ROUTE_WATCH_STRIKES {
            return Err(TransferError::RouteRefused(route));
        }
        Ok(())
    }
}

/// Polls the selected path until the policy admits it or the grace period
/// runs out, returning the last path seen either way.
///
/// `Connection::paths_stream` would push these changes instead of polling for
/// them, but it needs a `Stream` adaptor this crate does not otherwise
/// depend on, and the wait is seconds long — a 100 ms poll is not the cost
/// worth adding a dependency to avoid (§28.4).
async fn await_admissible_route(
    conn: &Connection,
    admission: RouteAdmission,
    initial: Route,
) -> Route {
    poll_until_admissible(admission.policy, initial, admission.grace, || {
        observe_route(conn)
    })
    .await
}

/// The waiting itself, with the connection replaced by a closure that reports
/// the current path.
///
/// Split out because the property worth pinning — waits for an upgrade,
/// returns the moment one arrives, gives up at the deadline — cannot be tested
/// through a real [`Connection`]: making one hole-punch on demand inside a unit
/// test is not something a test can arrange. Against a closure it is three
/// assertions.
async fn poll_until_admissible(
    policy: RoutePolicy,
    initial: Route,
    grace: Duration,
    mut observe: impl FnMut() -> Route,
) -> Route {
    // A path the policy already admits costs nothing: no wait, and no change
    // in behaviour for the common case, which is every connection that is not
    // behind a NAT still being punched through.
    if policy.admits(initial) {
        return initial;
    }

    let deadline = tokio::time::Instant::now() + grace;
    let mut last = initial;
    while tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let route = observe();
        if policy.admits(route) {
            return route;
        }
        last = route;
    }
    last
}

/// Reads, encrypts and proves one chunk, returning the frame body ready to
/// send.
///
/// Split out of the send loop so it can be produced while the previous chunk
/// is on the wire. Everything here is this machine's work and none of it
/// depends on the transport, which is exactly what makes the overlap sound.
#[allow(clippy::too_many_arguments)]
async fn produce_chunk_record(
    file: &mut tokio::fs::File,
    buf: &mut [u8],
    cache: &CiphertextCache,
    ctx: &object::ObjectContext,
    ctx_hash: &[u8; 32],
    schedule: &crate::keys::FileKeySchedule,
    leaves: &[[u8; 32]],
    index: u64,
) -> Result<Vec<u8>, TransferError> {
    let len = ctx.chunk_len(index).unwrap() as usize;

    // A hit skips the read and the AEAD pass; a miss recomputes the same
    // bytes. The root built over that ciphertext in `prepare` would catch it
    // if they ever differed.
    let recomputed;
    let ciphertext: &[u8] = match cache.get(index) {
        Some(bytes) => bytes,
        None => {
            file.seek(std::io::SeekFrom::Start(
                index * ctx.chunk_plaintext_size as u64,
            ))
            .await
            .map_err(io_err)?;
            file.read_exact(&mut buf[..len]).await.map_err(io_err)?;
            recomputed = object::encrypt_chunk(schedule, ctx, ctx_hash, index, &buf[..len])
                .map_err(|_| TransferError::Crypto("chunk encryption"))?;
            &recomputed
        }
    };
    let proof =
        merkle::build_proof(leaves, index as usize).map_err(|_| TransferError::Crypto("proof"))?;
    Ok(encode_chunk_record(index, &proof, ciphertext))
}

/// Prepares and sends a file in one call.
pub async fn send_file(
    endpoint: &Endpoint,
    identity: &DeviceIdentity,
    peer: EndpointAddr,
    path: &Path,
    events: Option<&EventQueue>,
    admission: impl Into<RouteAdmission>,
) -> Result<TransferReport, TransferError> {
    let pending = PendingTransfer::prepare(path, DEFAULT_CHUNK_SIZE).await?;
    send_pending(endpoint, identity, peer, &pending, events, admission).await
}

/// Sends an already-prepared object. Safe to call more than once with the same
/// `PendingTransfer`: the receiver resumes rather than restarting.
pub async fn send_pending(
    endpoint: &Endpoint,
    identity: &DeviceIdentity,
    peer: EndpointAddr,
    pending: &PendingTransfer,
    events: Option<&EventQueue>,
    admission: impl Into<RouteAdmission>,
) -> Result<TransferReport, TransferError> {
    let admission = admission.into();
    let path = pending.path.as_path();
    let expected_peer_endpoint: [u8; 32] = *peer.id.as_bytes();
    let local_endpoint_id: [u8; 32] = *endpoint.id().as_bytes();

    let conn: Connection = endpoint.connect(peer, ALPN).await.map_err(io_err)?;
    // §7.4: the connection-level identity must be the endpoint we dialed.
    if *conn.remote_id().as_bytes() != expected_peer_endpoint {
        return Err(TransferError::Handshake);
    }
    // Before any protocol byte leaves. A policy about where data goes is
    // worthless checked after the data went.
    let route = admit_route(&conn, pending.secrets.transfer_id, admission, events).await?;
    let mut route_watch = RouteWatch::new(route, admission);
    let (mut send, mut recv) = conn.open_bi().await.map_err(io_err)?;

    // Standalone handshake (§8.2), initiator side.
    let (mut initiator, ch) = Initiator::start(identity, local_endpoint_id, expected_peer_endpoint);
    send_plain_frame(&mut send, FRAME_CLIENT_HELLO, &ch).await?;
    let sh = expect_plain_frame(&mut recv, FRAME_SERVER_HELLO).await?;
    let cf = initiator
        .on_server_hello(&sh)
        .map_err(|_| TransferError::Handshake)?;
    send_plain_frame(&mut send, FRAME_CLIENT_FINISH, &cf).await?;
    let sf = expect_plain_frame(&mut recv, FRAME_SERVER_FINISH).await?;
    let session = initiator
        .on_server_finish(&sf)
        .map_err(|_| TransferError::Handshake)?;

    // From here every frame is protected under the derived control keys.
    // Nothing after the handshake goes out in the clear.
    let mut control = ControlChannel::new(
        &session.handshake_prk,
        &session.th2,
        ControlDirection::ClientToServer,
    );

    let PendingTransfer {
        secrets,
        ctx,
        ctx_hash,
        schedule,
        leaves,
        ciphertext_root,
        plaintext_digest,
        cache,
        ..
    } = pending;
    let (ciphertext_root, plaintext_digest) = (*ciphertext_root, *plaintext_digest);
    let file_len = ctx.logical_plaintext_size;
    let mut file = File::open(path).await.map_err(io_err)?;
    let mut buf = vec![0u8; ctx.chunk_plaintext_size as usize];

    // §9.5 key envelope for the authenticated recipient device.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let envelope = keys::seal_envelope(
        secrets,
        &session.transfer_wrap_key,
        now,
        now + ENVELOPE_TTL_SECS,
        &identity.device_id,
        &session.peer.device_id,
    )
    .map_err(|_| TransferError::Crypto("envelope"))?;

    // Private manifest: everything the recipient needs and nothing a relay
    // may see, sealed under the file's manifest key.
    let recipient_scope = manifest::RecipientScope::device(&session.peer.device_id);
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let private = manifest::PrivateManifest {
        // Account identity lives outside this core, so the device id stands
        // in for now.
        sender_account_id: identity.device_id,
        sender_device_id: identity.device_id,
        recipient_scope: recipient_scope.clone(),
        display_name: file_name.clone(),
        original_filename: file_name,
        mime_type: "application/octet-stream".to_string(),
        logical_plaintext_size: ctx.logical_plaintext_size,
        plaintext_digest,
        created_at: now,
        user_caption: None,
        objects: vec![manifest::ObjectPrivate {
            object_id: secrets.object_id,
            object_role: manifest::ROLE_PRIMARY,
            relationship_to_primary: 0,
        }],
        key_policy: manifest::KeyPolicy {
            mode: 0,
            minimum_security_level: 1,
            pqc_required: true,
        },
        retention_policy: manifest::RetentionPolicy {
            expires_at: now + ENVELOPE_TTL_SECS,
            view_once: false,
            allow_local_save: true,
        },
    };
    let sealed_manifest = manifest::seal_private_manifest(
        &private,
        &schedule.manifest_key(),
        &secrets.transfer_id,
        &secrets.object_id,
    )
    .map_err(|_| TransferError::Crypto("private manifest"))?;

    // §13.1 public manifest: transfer mechanics only.
    let ciphertext_size = ctx.ciphertext_size();
    let public = manifest::PublicManifest {
        protocol_minor: 0,
        suite_id: crate::crypto::SUITE_ID,
        transfer_id: secrets.transfer_id,
        created_at: now,
        expires_at: now + ENVELOPE_TTL_SECS,
        route_profile: manifest::ROUTE_BALANCED,
        objects: vec![manifest::ObjectPublic {
            object_id: secrets.object_id,
            object_role: manifest::ROLE_PRIMARY,
            ciphertext_root,
            ciphertext_size,
            chunk_ciphertext_size: ctx.chunk_ciphertext_size(),
            chunk_count: ctx.chunk_count,
            padding_policy: ctx.padding_policy,
        }],
        private_manifest_ciphertext_hash: sealed_manifest.ciphertext_hash(),
        capability_scheme: manifest::CAPABILITY_SCHEME,
    };
    public
        .validate()
        .map_err(|_| TransferError::Crypto("public manifest"))?;

    // The offer: manifests, envelopes and providers, signed over the
    // commitment, the recipient scope and the binding hash.
    let offer = offer::TransferOffer::create(
        identity,
        &public,
        sealed_manifest,
        vec![offer::KeyEnvelopeEntry {
            recipient_device_id: session.peer.device_id,
            nonce: envelope.nonce,
            ciphertext: envelope.ciphertext,
        }],
        vec![offer::ProviderAddress {
            kind: offer::ProviderAddress::KIND_SENDER_DEVICE,
            address: local_endpoint_id.to_vec(),
        }],
        recipient_scope,
    )
    .map_err(|_| TransferError::Crypto("transfer offer"))?;
    send_frame(&mut send, &mut control, FRAME_OFFER, &offer.encode()).await?;

    // The receiver says what it needs: everything on a fresh transfer, only
    // the gaps on a resume.
    let request_bytes = expect_frame(&mut recv, &mut control, FRAME_RANGE_REQUEST).await?;
    let request = RangeRequest::decode(&request_bytes, ctx.chunk_count)
        .map_err(|_| TransferError::Protocol("bad range request"))?;
    if request.transfer_id != secrets.transfer_id || request.object_id != secrets.object_id {
        return Err(TransferError::Protocol(
            "range request names another object",
        ));
    }
    let requested_chunks = request.chunk_total();

    if let Some(q) = events {
        q.push(Event::TransferStarted {
            transfer_id: secrets.transfer_id,
            objects: 1,
            total_bytes: ctx.encoded_plaintext_size,
        });
    }
    // All the sender can honestly count is what it wrote to the transport,
    // not what the peer verified.
    let mut sent_bytes: u64 = 0;
    let mut sent_chunks: u64 = 0;

    // Pass 2: only the requested chunks, with proofs. Encryption is
    // deterministic, so a resent chunk matches one the receiver may hold.
    //
    // One chunk ahead of the wire. Reading, encrypting and proving a chunk is
    // work this machine does; sending it is work the network does, and doing
    // them in turn means each waits for the other. Between two machines on a
    // gigabit link that cost 28% of a ceiling the transport was willing to
    // carry — invisible in-process, where there is no link and both endpoints
    // share the CPU.
    let indices: Vec<u64> = request
        .ranges
        .iter()
        .flat_map(|&(start, end)| start..end)
        .collect();

    let mut ahead: Option<Vec<u8>> = match indices.first() {
        Some(&first) => Some(
            produce_chunk_record(
                &mut file, &mut buf, cache, ctx, ctx_hash, schedule, leaves, first,
            )
            .await?,
        ),
        None => None,
    };

    for (position, &index) in indices.iter().enumerate() {
        let record = ahead.take().expect("a record is always prepared ahead");
        let len = ctx.chunk_len(index).unwrap() as usize;

        // The overlap itself. `join!` polls both, so while the transport has
        // the previous chunk the CPU is already producing the next one.
        send_frame(&mut send, &mut control, FRAME_CHUNK, &record).await?;
        if let Some(&next) = indices.get(position + 1) {
            ahead = Some(
                produce_chunk_record(
                    &mut file, &mut buf, cache, ctx, ctx_hash, schedule, leaves, next,
                )
                .await?,
            );
        }

        route_watch.poll(&conn, pending.secrets.transfer_id, events)?;

        sent_bytes += len as u64;
        sent_chunks += 1;
        if let Some(q) = events {
            q.push(Event::TransferProgress {
                transfer_id: secrets.transfer_id,
                role: ProgressRole::Sending,
                bytes: sent_bytes,
                total_bytes: ctx.encoded_plaintext_size,
                chunks: sent_chunks,
                total_chunks: requested_chunks,
            });
        }
    }

    send_frame(&mut send, &mut control, FRAME_STREAM_END, &[]).await?;
    send.finish().ok();

    // Receiver acknowledges with its verified plaintext digest.
    let ack = expect_frame(&mut recv, &mut control, FRAME_COMPLETE).await?;
    let (status, remote_digest) = decode_ack(&ack)?;
    if status != 0 {
        return Err(TransferError::Protocol("receiver reported failure"));
    }
    if !crate::crypto::ct_eq(&remote_digest, &plaintext_digest) {
        return Err(TransferError::Crypto("plaintext digest mismatch"));
    }

    conn.close(0u32.into(), b"done");

    // Only with the receiver's digest matching may the sender claim
    // delivery. Transmitted is not delivered.
    if let Some(q) = events {
        q.push(Event::ObjectCompleted {
            transfer_id: secrets.transfer_id,
            object_id: secrets.object_id,
            plaintext_digest,
        });
        q.push(Event::TransferCompleted {
            transfer_id: secrets.transfer_id,
            objects: 1,
        });
    }

    Ok(TransferReport {
        transfer_id: secrets.transfer_id,
        object_id: secrets.object_id,
        manifest_commitment: public.commitment(),
        ciphertext_root,
        plaintext_digest,
        bytes: file_len,
        chunks: ctx.chunk_count,
        chunks_transferred: requested_chunks,
        peer_device_id: session.peer.device_id,
        peer_endpoint_id: session.peer_endpoint_id,
        route: route_watch.last,
    })
}

// ---------------------------------------------------------------------------
// Receiver
// ---------------------------------------------------------------------------

/// Everything a receive needs beyond the endpoint and the destination. A
/// struct rather than more parameters: adjacent `Option<&Path>` arguments are
/// the kind that get swapped silently at a call site.
#[derive(Default, Clone, Copy)]
pub struct ReceiveOptions<'a> {
    /// Where resume state lives. `None` keeps no record.
    pub resume_state: Option<&'a Path>,
    /// Where §25.3.1 events go. `None` means nobody is listening.
    pub events: Option<&'a EventQueue>,
    /// Which network paths are acceptable, and how long holepunching gets to
    /// produce one (§16.3.1).
    pub admission: RouteAdmission,
}

pub async fn receive_file(
    endpoint: &Endpoint,
    identity: &DeviceIdentity,
    replay: &mut ReplayCache,
    dest: &Path,
    accept_timeout: Duration,
    options: ReceiveOptions<'_>,
) -> Result<TransferReport, TransferError> {
    let ReceiveOptions {
        resume_state,
        events,
        admission,
    } = options;
    let local_endpoint_id: [u8; 32] = *endpoint.id().as_bytes();

    let incoming = tokio::time::timeout(accept_timeout, endpoint.accept())
        .await
        .map_err(|_| TransferError::Timeout)?
        .ok_or_else(|| TransferError::Io("endpoint closed".into()))?;
    let conn: Connection = incoming.accept().map_err(io_err)?.await.map_err(io_err)?;
    let observed_peer: [u8; 32] = *conn.remote_id().as_bytes();
    // No transfer id yet, so the event names the zero id. The route is what
    // the policy acts on, and refusing before the first stream is the point.
    let route = admit_route(&conn, [0u8; 32], admission, events).await?;
    let mut route_watch = RouteWatch::new(route, admission);
    let (mut send, mut recv) = conn.accept_bi().await.map_err(io_err)?;

    // Standalone handshake (§8.2), responder side.
    let mut responder = Responder::new(identity, local_endpoint_id);
    let ch = expect_plain_frame(&mut recv, FRAME_CLIENT_HELLO).await?;
    let sh = responder
        .on_client_hello(&ch, &observed_peer, replay)
        .map_err(|_| TransferError::Handshake)?;
    send_plain_frame(&mut send, FRAME_SERVER_HELLO, &sh).await?;
    let cf = expect_plain_frame(&mut recv, FRAME_CLIENT_FINISH).await?;
    let (sf, session): (Vec<u8>, SessionKeys) = responder
        .on_client_finish(&cf)
        .map_err(|_| TransferError::Handshake)?;
    send_plain_frame(&mut send, FRAME_SERVER_FINISH, &sf).await?;

    let mut control = ControlChannel::new(
        &session.handshake_prk,
        &session.th2,
        ControlDirection::ServerToClient,
    );

    // verify() checks the hybrid signature over the commitment, scope and
    // binding, re-derives the commitment, and enforces the expiry.
    let offer_bytes = expect_frame(&mut recv, &mut control, FRAME_OFFER).await?;
    let offer = offer::TransferOffer::decode(&offer_bytes)
        .map_err(|_| TransferError::Protocol("bad transfer offer"))?;

    // The offer must come from the device that just authenticated. A relayed
    // offer signed by someone else is refused.
    if offer.sender_device.device_id != session.peer.device_id {
        return Err(TransferError::Crypto(
            "offer signer is not the session peer",
        ));
    }
    let recipient_scope = manifest::RecipientScope::device(&identity.device_id);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let public = offer
        .verify(&recipient_scope, now)
        .map_err(|_| TransferError::Crypto("transfer offer"))?;

    // §9.5 key envelope addressed to this device, then its binding checks.
    let entry = offer
        .envelope_for(&identity.device_id)
        .ok_or(TransferError::Crypto("no key envelope for this device"))?;
    let opened = keys::open_envelope_at(
        &SealedEnvelope {
            nonce: entry.nonce,
            ciphertext: entry.ciphertext.clone(),
        },
        &session.transfer_wrap_key,
        now,
    )
    .map_err(|_| TransferError::Crypto("envelope"))?;
    if opened.sender_device_id != session.peer.device_id
        || opened.recipient_device_id != identity.device_id
    {
        return Err(TransferError::Crypto("envelope binding"));
    }

    let sealed_manifest = offer.sealed_manifest.clone();
    if public.transfer_id != opened.secrets.transfer_id {
        return Err(TransferError::Crypto(
            "manifest/envelope transfer id mismatch",
        ));
    }
    let object_public = public
        .primary()
        .ok_or(TransferError::Protocol("no primary object"))?
        .clone();
    if object_public.object_id != opened.secrets.object_id {
        return Err(TransferError::Crypto(
            "manifest/envelope object id mismatch",
        ));
    }

    // Opening the private manifest proves the sender held the file master
    // key this envelope delivered.
    let schedule = opened.secrets.key_schedule();
    let recipient_scope = manifest::RecipientScope::device(&identity.device_id);
    let private = manifest::open_private_manifest(
        &sealed_manifest,
        &schedule.manifest_key(),
        &opened.secrets.transfer_id,
        &opened.secrets.object_id,
        &session.peer.device_id,
        &recipient_scope,
    )
    .map_err(|_| TransferError::Crypto("private manifest"))?;

    // The two manifests must describe the same object.
    if private.objects.len() != public.objects.len()
        || private.objects[0].object_id != object_public.object_id
        || private.objects[0].object_role != object_public.object_role
    {
        return Err(TransferError::Protocol("manifest object mismatch"));
    }

    let chunk_plaintext_size =
        ObjectContext::chunk_plaintext_size_from_ciphertext(object_public.chunk_ciphertext_size)
            .map_err(|_| TransferError::Protocol("bad chunk size"))?;
    let ctx = ObjectContext::for_file(
        opened.secrets.transfer_id,
        opened.secrets.object_id,
        private.logical_plaintext_size,
        chunk_plaintext_size,
    )
    .map_err(|_| TransferError::Protocol("bad object parameters"))?;
    if ctx.chunk_count != object_public.chunk_count
        || ctx.padding_policy != object_public.padding_policy
        || ctx.object_role != object_public.object_role
    {
        return Err(TransferError::Protocol("manifest inconsistent with object"));
    }
    let ctx_hash = ctx.context_hash();
    let root = object_public.ciphertext_root;
    // The sender's committed claim about the decrypted bytes, checked after
    // everything is persisted.
    let expected_plaintext_digest = private.plaintext_digest;

    // Resume state. This identity is exactly what a substituted source would
    // have to match to pass off different content.
    let identity_commitment = offer
        .manifest_commitment()
        .map_err(|_| TransferError::Crypto("commitment"))?;
    let mut received_this_attempt: u64 = 0;
    let identity = resume::ObjectIdentity {
        transfer_id: opened.secrets.transfer_id,
        object_id: opened.secrets.object_id,
        manifest_commitment: identity_commitment,
        ciphertext_root: root,
        chunk_count: ctx.chunk_count,
        chunk_ciphertext_size: object_public.chunk_ciphertext_size,
        logical_plaintext_size: ctx.logical_plaintext_size,
    };
    let state_path = resume_state.map(|p| p.to_path_buf());
    let mut db = match &state_path {
        Some(path) => Some(
            resume::ResumeDb::open(path, identity, dest)
                .map_err(|e| TransferError::Io(e.to_string()))?
                .0,
        ),
        None => None,
    };

    // Open without truncating: on resume the file already holds verified
    // chunks, and the resume record is the authority on which ones.
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(dest)
        .await
        .map_err(io_err)?;
    file.set_len(ctx.logical_plaintext_size)
        .await
        .map_err(io_err)?;

    let mut have = match &db {
        Some(db) => db.record().durable.clone(),
        None => bitmap::ChunkBitmap::new(ctx.chunk_count)
            .map_err(|_| TransferError::Protocol("bad chunk count"))?,
    };

    // §18.1 range request: ask only for what is missing.
    let scheduler = Scheduler::new(
        opened.secrets.transfer_id,
        opened.secrets.object_id,
        ctx.chunk_count,
        object_public.chunk_ciphertext_size,
    );
    // An empty list honestly means nothing is needed: a zero-length object,
    // or one already fully durable.
    let request = scheduler.full_request(&have);
    send_frame(
        &mut send,
        &mut control,
        FRAME_RANGE_REQUEST,
        &request.encode(),
    )
    .await?;

    // Streaming plaintext digest. Two guards keep it exact: an out-of-order
    // index abandons the hash, and it is used only once the counter reaches
    // `chunk_count`. A resumed transfer never gets there, having asked for
    // only the missing chunks.
    let mut streaming = Some((blake3::Hasher::new(), 0u64));

    // Only proof-checked, authenticated bytes count. The counter starts from
    // what a resume already verified, so restarting does not look like a loss.
    let mut verified_bytes: u64 = (0..ctx.chunk_count)
        .filter(|i| have.get(*i).unwrap_or(false))
        .map(|i| ctx.chunk_len(i).unwrap_or(0) as u64)
        .sum();
    if let Some(q) = events {
        q.push(Event::TransferStarted {
            transfer_id: opened.secrets.transfer_id,
            objects: 1,
            total_bytes: ctx.encoded_plaintext_size,
        });
    }

    // §11.4 decryption order: bounds → proof → derive → AEAD → length → persist.
    loop {
        let (frame_type, payload) = recv_frame(&mut recv, &mut control).await?;
        match frame_type {
            FRAME_CHUNK => {
                let (index, proof, ciphertext) = decode_chunk_record(&payload)?;
                if index >= ctx.chunk_count {
                    return Err(TransferError::Protocol("chunk index out of range"));
                }
                if have.get(index).unwrap_or(false) {
                    // Duplicate delivery of a verified chunk is ignored (§2.7).
                    continue;
                }
                let expected_len = ctx
                    .chunk_ciphertext_len(index)
                    .map_err(|_| TransferError::Protocol("chunk index out of range"))?;
                if ciphertext.len() != expected_len {
                    return Err(TransferError::Protocol("chunk length mismatch"));
                }
                let leaf = merkle::leaf_hash(index, &ciphertext);
                merkle::verify_proof(&leaf, index, ctx.chunk_count, &proof, &root)
                    .map_err(|_| TransferError::Crypto("merkle proof"))?;
                let plaintext =
                    object::decrypt_chunk(&schedule, &ctx, &ctx_hash, index, &ciphertext)
                        .map_err(|_| TransferError::Crypto("chunk aead"))?;
                file.seek(std::io::SeekFrom::Start(
                    index * ctx.chunk_plaintext_size as u64,
                ))
                .await
                .map_err(io_err)?;
                file.write_all(&plaintext).await.map_err(io_err)?;

                // §18.4: VERIFIED now; DURABLE only after the flush below.
                if let Some(db) = db.as_mut() {
                    db.mark_verified(index)
                        .map_err(|e| TransferError::Io(e.to_string()))?;
                }
                have.set(index)
                    .map_err(|_| TransferError::Protocol("bitmap"))?;
                received_this_attempt += 1;

                // The receiver enforces the policy too. Its own transfer_id is
                // known by now, so a switch is reported against the transfer it
                // belongs to rather than the zeros used before the handshake.
                route_watch.poll(&conn, opened.secrets.transfer_id, events)?;

                // Strict order only, after proof and AEAD. A gap abandons the
                // hash rather than digesting the wrong byte sequence.
                if let Some((hasher, next)) = streaming.as_mut() {
                    if index == *next {
                        hasher.update(&plaintext);
                        *next += 1;
                    } else {
                        streaming = None;
                    }
                }

                // After the checks above, never before: garbage from a peer
                // must not move this.
                verified_bytes += plaintext.len() as u64;
                if let Some(q) = events {
                    q.push(Event::TransferProgress {
                        transfer_id: opened.secrets.transfer_id,
                        role: ProgressRole::Receiving,
                        bytes: verified_bytes,
                        total_bytes: ctx.encoded_plaintext_size,
                        chunks: have.set_count(),
                        total_chunks: ctx.chunk_count,
                    });
                }

                // The record decides when to flush and commit, and in which
                // order. It used to be decided here, behind a condition that
                // compared two counters this loop advanced together — so it
                // was never true, and the bitmap was committed every 64 chunks
                // with nothing flushed before it.
                if let Some(db) = db.as_mut() {
                    db.chunk_written(index, || async {
                        file.flush().await?;
                        file.sync_data().await
                    })
                    .await
                    .map_err(|e| TransferError::Io(e.to_string()))?;
                }
            }
            FRAME_STREAM_END => break,
            _ => return Err(TransferError::Protocol("unexpected frame type")),
        }
    }

    // A truncated object is caught before release (INV-42).
    if !have.is_complete() {
        if let Some(db) = db.as_mut() {
            // Persist what did arrive so the next attempt resumes from here.
            file.flush().await.map_err(io_err)?;
            file.sync_all().await.map_err(io_err)?;
            db.checkpoint()
                .map_err(|e| TransferError::Io(e.to_string()))?;
        }
        return Err(TransferError::Protocol("transfer incomplete"));
    }
    file.flush().await.map_err(io_err)?;
    file.sync_all().await.map_err(io_err)?;
    drop(file);

    // The plaintext digest, from the running hash when every chunk arrived in
    // order, and otherwise by reading back what was persisted.
    let plaintext_digest: [u8; 32] = match streaming {
        Some((hasher, next)) if next == ctx.chunk_count => *hasher.finalize().as_bytes(),
        _ => {
            let mut check = File::open(dest).await.map_err(io_err)?;
            let mut hasher = blake3::Hasher::new();
            let mut buf = vec![0u8; 1024 * 1024];
            loop {
                let n = check.read(&mut buf).await.map_err(io_err)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            *hasher.finalize().as_bytes()
        }
    };

    // The decrypted bytes must match the digest the sender committed to in
    // the authenticated private manifest (§10.4, §13.2). Chunk AEAD and the
    // Merkle root already bind the ciphertext; this closes the loop on the
    // plaintext the application is about to see.
    if !crate::crypto::ct_eq(&plaintext_digest, &expected_plaintext_digest) {
        // §22.1.1. Every chunk already verified against the authenticated
        // root, so no range can be re-fetched to fix this: the sender's own
        // manifest is inconsistent. Discard the plaintext *and* the resume
        // record, keeping the latter would let the next attempt resume
        // straight back into the same dead end.
        let _ = tokio::fs::remove_file(dest).await;
        if let Some(db) = db.take() {
            let _ = db.remove();
        }
        return Err(TransferError::Crypto("plaintext digest mismatch"));
    }

    // The object is complete and verified, so the resume record has no more
    // work to describe (§18.3). Removing it is the last step, after the
    // content is known good.
    if let Some(db) = db.take() {
        db.remove().map_err(|e| TransferError::Io(e.to_string()))?;
    }

    // Terminal events last, after the plaintext digest matched the sender's
    // signed claim: an application that acts on OBJECT_COMPLETED is acting on
    // fully verified content.
    if let Some(q) = events {
        q.push(Event::ObjectCompleted {
            transfer_id: opened.secrets.transfer_id,
            object_id: opened.secrets.object_id,
            plaintext_digest,
        });
        q.push(Event::TransferCompleted {
            transfer_id: opened.secrets.transfer_id,
            objects: 1,
        });
    }

    send_frame(
        &mut send,
        &mut control,
        FRAME_COMPLETE,
        &encode_ack(0, &plaintext_digest),
    )
    .await?;
    send.finish().ok();
    // Give the peer a moment to read the ack before the connection drops.
    let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;

    Ok(TransferReport {
        transfer_id: opened.secrets.transfer_id,
        object_id: opened.secrets.object_id,
        manifest_commitment: identity_commitment,
        ciphertext_root: root,
        plaintext_digest,
        bytes: ctx.logical_plaintext_size,
        chunks: ctx.chunk_count,
        chunks_transferred: received_this_attempt,
        peer_device_id: session.peer.device_id,
        peer_endpoint_id: session.peer_endpoint_id,
        route: route_watch.last,
    })
}

#[cfg(test)]
mod route_grace_tests {
    use super::*;
    use crate::route::{AddressClass, DEFAULT_ROUTE_GRACE};
    use std::cell::Cell;

    /// Reports `Relay` for the first `upgrade_after` observations and a direct
    /// public path from then on — a connection that hole-punches successfully,
    /// as one behind NAT does a moment after it opens.
    fn upgrading(upgrade_after: usize) -> (impl FnMut() -> Route, std::rc::Rc<Cell<usize>>) {
        let calls = std::rc::Rc::new(Cell::new(0));
        let seen = calls.clone();
        let observe = move || {
            let n = seen.get();
            seen.set(n + 1);
            if n < upgrade_after {
                Route::Relay
            } else {
                Route::Direct(AddressClass::Public)
            }
        };
        (observe, calls)
    }

    #[tokio::test(start_paused = true)]
    async fn a_path_that_upgrades_is_admitted() {
        // The bug this exists for: the first real transfer between two devices
        // was refused because the route was judged at the instant the
        // connection opened, before holepunching had finished. The refusal
        // reported our impatience, not the network.
        let (observe, _) = upgrading(20);
        let route = poll_until_admissible(
            RoutePolicy::DirectOnly,
            Route::Relay,
            DEFAULT_ROUTE_GRACE,
            observe,
        )
        .await;
        assert_eq!(route, Route::Direct(AddressClass::Public));
    }

    #[tokio::test(start_paused = true)]
    async fn waiting_stops_at_the_upgrade_not_at_the_deadline() {
        // Returning late is as wrong as refusing early: it would stall every
        // transfer by the full grace period. The observation count pins that
        // the loop leaves as soon as the path is admissible.
        let (observe, calls) = upgrading(3);
        let started = tokio::time::Instant::now();
        let route = poll_until_admissible(
            RoutePolicy::DirectOnly,
            Route::Relay,
            DEFAULT_ROUTE_GRACE,
            observe,
        )
        .await;
        assert_eq!(route, Route::Direct(AddressClass::Public));
        assert_eq!(calls.get(), 4, "polled past the upgrade");
        assert!(
            started.elapsed() < DEFAULT_ROUTE_GRACE / 2,
            "waited {:?}, near the whole grace period",
            started.elapsed()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_path_that_never_upgrades_gives_up_and_reports_what_it_saw() {
        // Grace is not surrender: a relay-only path must still be refused, and
        // must be refused as a relay, so the report names the real reason.
        let started = tokio::time::Instant::now();
        let route = poll_until_admissible(
            RoutePolicy::DirectOnly,
            Route::Unknown,
            DEFAULT_ROUTE_GRACE,
            || Route::Relay,
        )
        .await;
        assert_eq!(route, Route::Relay);
        assert!(!RoutePolicy::DirectOnly.admits(route));
        assert!(started.elapsed() >= DEFAULT_ROUTE_GRACE, "gave up early");
    }

    #[tokio::test(start_paused = true)]
    async fn an_admissible_path_is_never_waited_on() {
        // The common case: a path the policy already accepts must cost nothing
        // at all — not one sleep, not one extra observation. A grace period
        // that delayed every transfer would be a worse bug than the one it
        // was added to fix.
        let calls = std::rc::Rc::new(Cell::new(0));
        let seen = calls.clone();
        let started = tokio::time::Instant::now();
        let route = poll_until_admissible(
            RoutePolicy::Any,
            Route::Relay,
            DEFAULT_ROUTE_GRACE,
            move || {
                seen.set(seen.get() + 1);
                Route::Relay
            },
        )
        .await;
        assert_eq!(route, Route::Relay);
        assert_eq!(calls.get(), 0, "observed a path it had already accepted");
        assert_eq!(started.elapsed(), Duration::ZERO);
    }
}

#[cfg(test)]
mod route_watch_tests {
    use super::*;
    use crate::route::AddressClass;

    const ID: [u8; 32] = [7u8; 32];

    fn drain(q: &EventQueue) -> Vec<Route> {
        let mut seen = Vec::new();
        while let Some(event) = q.poll(Duration::from_millis(0)) {
            if let Event::TransferRoute { route, .. } = event {
                seen.push(match route {
                    0 => Route::Direct(AddressClass::Public),
                    1 => Route::Relay,
                    _ => Route::Unknown,
                });
            }
        }
        seen
    }

    /// Moves past the next check without waiting for real time.
    async fn tick() {
        tokio::time::advance(ROUTE_WATCH_INTERVAL + Duration::from_millis(1)).await;
    }

    #[tokio::test(start_paused = true)]
    async fn an_upgrade_mid_transfer_is_reported() {
        // The gap this closes: the first between-device transfer was reported
        // as relayed, and nothing could say whether it stayed that way for all
        // 4 MiB. A path that improves has to be published, or the report
        // describes the first instant and calls it the whole transfer.
        let q = EventQueue::new();
        let mut watch = RouteWatch::new(Route::Relay, RouteAdmission::default());

        tick().await;
        watch
            .poll_with(ID, Some(&q), || Route::Direct(AddressClass::Public))
            .expect("Any admits everything");

        assert_eq!(drain(&q), vec![Route::Direct(AddressClass::Public)]);
        assert_eq!(watch.last, Route::Direct(AddressClass::Public));
    }

    #[tokio::test(start_paused = true)]
    async fn an_unchanged_path_says_nothing() {
        // Publishing the same route every half second would bury the events
        // that matter under ones that do not.
        let q = EventQueue::new();
        let mut watch = RouteWatch::new(Route::Relay, RouteAdmission::default());
        for _ in 0..4 {
            tick().await;
            watch.poll_with(ID, Some(&q), || Route::Relay).unwrap();
        }
        assert!(
            drain(&q).is_empty(),
            "reported a change that did not happen"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn checking_is_free_between_intervals() {
        // The chunk loops call this per chunk. If it observed every time it
        // would cost a syscall per chunk for a path that changes rarely.
        let q = EventQueue::new();
        let mut watch = RouteWatch::new(Route::Relay, RouteAdmission::default());
        let mut looks = 0;
        for _ in 0..50 {
            watch
                .poll_with(ID, Some(&q), || {
                    looks += 1;
                    Route::Relay
                })
                .unwrap();
        }
        assert_eq!(looks, 0, "looked before the interval elapsed");
    }

    #[tokio::test(start_paused = true)]
    async fn a_path_that_falls_back_to_a_relay_ends_the_transfer() {
        // The hole this closes. `DirectOnly` was checked once, at the start,
        // so a connection that dropped back to a relay afterwards carried the
        // rest of the ciphertext through exactly the node the caller excluded
        // — with nothing reported.
        let q = EventQueue::new();
        let mut watch = RouteWatch::new(
            Route::Direct(AddressClass::Public),
            RouteAdmission::new(RoutePolicy::DirectOnly),
        );

        tick().await;
        watch
            .poll_with(ID, Some(&q), || Route::Relay)
            .expect("one refused observation is not yet a decision");

        tick().await;
        let err = watch
            .poll_with(ID, Some(&q), || Route::Relay)
            .expect_err("a path that stayed refused must end the transfer");
        assert!(matches!(err, TransferError::RouteRefused(Route::Relay)));

        // Reported before it was refused, so the application learns why.
        assert_eq!(drain(&q), vec![Route::Relay]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_momentary_blip_does_not_end_the_transfer() {
        // A path between candidates has no selected one and reads Unknown.
        // Tearing down a healthy transfer over a single such reading would
        // turn a hiccup into a failure.
        let q = EventQueue::new();
        let mut watch = RouteWatch::new(
            Route::Direct(AddressClass::Public),
            RouteAdmission::new(RoutePolicy::DirectOnly),
        );

        tick().await;
        watch.poll_with(ID, Some(&q), || Route::Unknown).unwrap();
        tick().await;
        watch
            .poll_with(ID, Some(&q), || Route::Direct(AddressClass::Public))
            .expect("recovered before the second strike");

        // And the strike count reset, so the next blip starts from zero
        // rather than finishing off a transfer that recovered.
        tick().await;
        watch
            .poll_with(ID, Some(&q), || Route::Unknown)
            .expect("strikes did not reset after recovery");
    }

    #[tokio::test(start_paused = true)]
    async fn a_permissive_policy_never_ends_a_transfer() {
        let q = EventQueue::new();
        let mut watch = RouteWatch::new(
            Route::Direct(AddressClass::Public),
            RouteAdmission::default(),
        );
        for _ in 0..6 {
            tick().await;
            watch.poll_with(ID, Some(&q), || Route::Relay).unwrap();
        }
    }
}

#[cfg(test)]
mod cache_tests {
    use super::*;

    fn prepared(size: usize) -> (PendingTransfer, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "rtp2-cache-{}-{}",
            std::process::id(),
            u64::from_be_bytes(crate::crypto::os_random_array::<8>())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("src.bin");
        let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, &payload).unwrap();
        let pending = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(PendingTransfer::prepare(&path, 64 * 1024))
            .unwrap();
        (pending, dir)
    }

    #[test]
    fn a_cached_chunk_is_byte_identical_to_a_recomputed_one() {
        // The whole optimization rests on this. §11.3 makes chunk encryption
        // deterministic; if that ever stopped holding, a cache hit and a cache
        // miss would ship different bytes for the same index and only one of
        // them would match the Merkle root the manifest already committed to.
        let (pending, dir) = prepared(5 * 64 * 1024 + 123);
        assert!(pending.cache.cached_chunks() > 0, "nothing was cached");

        let mut plain = vec![0u8; pending.ctx.chunk_plaintext_size as usize];
        let mut file = std::fs::File::open(&pending.path).unwrap();
        for index in 0..pending.ctx.chunk_count {
            use std::io::{Read, Seek};
            let len = pending.ctx.chunk_len(index).unwrap() as usize;
            file.seek(std::io::SeekFrom::Start(
                index * pending.ctx.chunk_plaintext_size as u64,
            ))
            .unwrap();
            file.read_exact(&mut plain[..len]).unwrap();
            let recomputed = object::encrypt_chunk(
                &pending.schedule,
                &pending.ctx,
                &pending.ctx_hash,
                index,
                &plain[..len],
            )
            .unwrap();
            assert_eq!(
                pending.cache.get(index).expect("cached"),
                recomputed.as_slice(),
                "chunk {index} differs between cache and recomputation"
            );
            // And it is the chunk the Merkle leaf was built from.
            assert_eq!(
                pending.leaves[index as usize],
                merkle::leaf_hash(index, &recomputed)
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_cache_never_serves_another_index() {
        // A cache that answered the wrong index would ship a chunk whose
        // Merkle proof cannot verify. Cheap to get wrong, so pinned directly.
        let (pending, dir) = prepared(4 * 64 * 1024);
        for index in 0..pending.ctx.chunk_count {
            let bytes = pending.cache.get(index).expect("cached");
            assert_eq!(
                merkle::leaf_hash(index, bytes),
                pending.leaves[index as usize],
                "cache returned bytes that do not belong at index {index}"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Builds a chunk record whose proof steps carry `direction`, bypassing
    /// the encoder so a value no conformant encoder produces can be tested.
    fn chunk_record_with_direction(direction: u64) -> Vec<u8> {
        use crate::cbor::{MapWriter, Writer};
        let mut w = Writer::new();
        let mut m = MapWriter::begin(&mut w, 3);
        m.uint(0, 0);
        {
            let inner = m.nested(1);
            inner.array(1);
            inner.array(2);
            inner.uint(direction);
            inner.bytes(&[7u8; 32]);
        }
        m.bytes(2, &[0u8; 48]);
        m.end();
        w.into_bytes()
    }

    #[test]
    fn a_proof_direction_outside_zero_and_one_is_refused() {
        // §12.5: direction has exactly two values, and anything else is
        // rejected rather than coerced. The encoder only writes 0 or 1, so
        // without this test the check would be unexercised.
        for good in [0u64, 1] {
            assert!(
                decode_chunk_record(&chunk_record_with_direction(good)).is_ok(),
                "direction {good} is valid and must decode"
            );
        }
        for bad in [2u64, 3, 255, u64::MAX] {
            let got = decode_chunk_record(&chunk_record_with_direction(bad));
            assert!(got.is_err(), "direction {bad} must be refused, not coerced");
        }
    }

    #[test]
    fn the_budget_bounds_what_is_kept() {
        // §26.1: bounded. Without this a 4 GiB object would be held in memory.
        let mut cache = CiphertextCache::new(100, 3 * 1000);
        for index in 0..100 {
            cache.insert(index, &vec![0u8; 1000]);
        }
        assert_eq!(cache.cached_chunks(), 3, "the budget must stop the fill");
        assert!(cache.get(0).is_some());
        assert!(
            cache.get(50).is_none(),
            "a chunk past the budget must be a miss, not a truncated entry"
        );
    }

    #[test]
    fn a_zero_budget_caches_nothing_and_stays_usable() {
        // The miss path is the old behaviour, and it must remain complete:
        // §26.1 requires a miss to be answered by recomputation.
        let mut cache = CiphertextCache::new(4, 0);
        cache.insert(0, &[1, 2, 3]);
        assert_eq!(cache.cached_chunks(), 0);
        assert!(cache.get(0).is_none());
    }

    #[test]
    fn an_out_of_range_index_is_a_miss_not_a_panic() {
        let mut cache = CiphertextCache::new(2, 1 << 20);
        cache.insert(99, &[1, 2, 3]);
        assert!(cache.get(99).is_none());
        assert_eq!(cache.cached_chunks(), 0);
    }
}
