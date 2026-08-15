// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//! RTP/2 native core.
//!
//! The core owns the endpoint, the Tokio runtime, every key, all cipher and
//! hash work, and zeroization. No key material crosses the C ABI: the
//! application drives transfers through opaque handles and gets public
//! reports back.
//!
//! ABI version 6, see include/rtp2.h. `rtp2_runtime_new` checks the caller's
//! compiled-in version and struct size before anything else.

// Every exported function null- and bounds-checks its pointers first. The
// contracts are in include/rtp2.h.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

pub mod bitmap;
pub mod capability;
pub mod cbor;
pub mod control;
pub mod crypto;
pub mod events;
pub mod handshake;
pub mod identity;
pub mod keys;
pub mod keystore;
pub mod manifest;
pub mod merkle;
pub mod object;
pub mod offer;
pub mod pqc;
pub mod resume;
pub mod route;
pub mod scheduler;
pub mod store;
pub mod transfer;

use std::{
    collections::HashMap,
    ffi::{CStr, c_char},
    fs::File,
    io::Read,
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
    ptr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use blake3::Hasher;
use iroh::{Endpoint, EndpointAddr, endpoint::presets};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use tokio::runtime::{Builder, Runtime};

use crate::{crypto::ALPN, handshake::ReplayCache, identity::DeviceIdentity};

pub const ABI_VERSION: u32 = 6;

const OK: i32 = 0;
const ERR_INVALID_ARGUMENT: i32 = -1;
const ERR_NOT_FOUND: i32 = -2;
const ERR_INTERNAL: i32 = -3;
const ERR_CRYPTO: i32 = -4;
const ERR_IO: i32 = -5;
const ERR_ABI_MISMATCH: i32 = -6;
const ERR_TIMEOUT: i32 = -7;
/// The keystore was asked for and could not be used. Separate from
/// `ERR_CRYPTO` because the fix differs: this is the environment, not a bad
/// record.
const ERR_KEYSTORE: i32 = -8;
/// The connection's path was excluded by the caller's route policy (§16.3.1).
/// Nothing is wrong with the peer, the data or the cryptography.
const ERR_ROUTE_REFUSED: i32 = -9;

/// Values for `Rtp2RuntimeConfig::key_protection`, mirroring `store::Protection`.
const KEY_PROTECTION_PLAINTEXT: u32 = 0;
const KEY_PROTECTION_PLATFORM_KEYSTORE: u32 = 1;
const KEY_PROTECTION_HARDWARE_KEYSTORE: u32 = 2;

#[repr(C)]
pub struct Rtp2Buffer {
    pub ptr: *mut u8,
    pub len: usize,
    pub cap: usize,
}

impl Default for Rtp2Buffer {
    fn default() -> Self {
        Self {
            ptr: ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }
}

/// Mirrors `rtp2_runtime_config_t` in rtp2.h.
#[repr(C)]
pub struct Rtp2RuntimeConfig {
    pub abi_version: u32,
    pub struct_size: u32,
    pub json_config: *const c_char,
    /// Directory holding this device's persistent identity (§7.2). NULL means
    /// an ephemeral identity that exists only for this process.
    pub state_dir_utf8: *const c_char,
    /// How the seed is protected at rest: 0 plaintext, 1 platform keystore.
    /// Only meaningful with `state_dir_utf8`.
    pub key_protection: u32,
    /// Padding, so the pointers below align on every target and the struct
    /// has no hole a caller could leave uninitialized.
    pub reserved: u32,
    /// Keystore item coordinates. NULL selects
    /// `keystore::DEFAULT_SERVICE` / `keystore::DEFAULT_ACCOUNT`.
    pub keystore_service_utf8: *const c_char,
    pub keystore_account_utf8: *const c_char,
    /// Route policy for every transfer on this runtime (§16.3.1):
    /// 0 any, 1 direct-only, 2 loopback-only. Runtime-wide rather than
    /// per-transfer because the ABI has no transfer options struct yet.
    pub route_policy: u32,
    /// How long, in milliseconds, a path the policy refuses is given to become
    /// one it admits — the time holepunching gets to finish. 0 selects
    /// `route::DEFAULT_ROUTE_GRACE`.
    ///
    /// This was a constant in the core until a transfer between two devices
    /// behind carrier NAT spent the whole of it and was refused. How long to
    /// wait for a direct path is the same kind of decision as demanding one,
    /// and belongs to whoever made that demand.
    pub route_grace_ms: u32,
}

struct RuntimeState {
    runtime: Runtime,
    /// Device identity lives and dies inside the core (§25.1).
    identity: DeviceIdentity,
    /// Only when a state directory was given. Holds the paths prekeys and
    /// resumption secrets will use.
    #[allow(dead_code)]
    store: Option<store::DeviceStore>,
    /// What actually protects the seed, e.g. `"plaintext"`. Reported through
    /// `rtp2_key_protection`, so an application can check its posture instead
    /// of assuming its config was honoured.
    key_protection: String,
    /// §16.3.1. Applied to every transfer this runtime drives.
    route_policy: route::RoutePolicy,
    /// How long holepunching gets before a refused path is refused for good.
    route_grace: Duration,
    /// On the runtime, not a transfer handle, so freeing a transfer cannot
    /// take its terminal event with it.
    events: events::EventQueue,
    last_error: Mutex<String>,
}

impl RuntimeState {
    fn set_error(&self, message: impl Into<String>) {
        *self.last_error.lock() = message.into();
    }
}

struct EndpointState {
    endpoint: Endpoint,
    runtime: Arc<RuntimeState>,
    replay: Mutex<ReplayCache>,
}

enum HandleValue {
    Runtime(Arc<RuntimeState>),
    Endpoint(Arc<EndpointState>),
}

// Strictly increasing and never reused, so a stale handle cannot alias a
// newer object.
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);
static HANDLES: Lazy<Mutex<HashMap<u64, HandleValue>>> = Lazy::new(|| Mutex::new(HashMap::new()));

fn insert_handle(value: HandleValue) -> u64 {
    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    HANDLES.lock().insert(handle, value);
    handle
}

fn runtime(handle: u64) -> Option<Arc<RuntimeState>> {
    match HANDLES.lock().get(&handle) {
        Some(HandleValue::Runtime(value)) => Some(Arc::clone(value)),
        _ => None,
    }
}

fn endpoint(handle: u64) -> Option<Arc<EndpointState>> {
    match HANDLES.lock().get(&handle) {
        Some(HandleValue::Endpoint(value)) => Some(Arc::clone(value)),
        _ => None,
    }
}

/// On success the caller owns the buffer and must free it exactly once. On
/// any error, out-parameters are untouched and own nothing.
fn into_buffer(mut bytes: Vec<u8>) -> Rtp2Buffer {
    let out = Rtp2Buffer {
        ptr: bytes.as_mut_ptr(),
        len: bytes.len(),
        cap: bytes.capacity(),
    };
    std::mem::forget(bytes);
    out
}

/// Turns the ABI's milliseconds into a grace period.
///
/// Zero keeps the meaning this field had while it was reserved — a caller
/// built against the previous header zeroed it — so it selects the default
/// rather than "do not wait". Asking for no wait is expressible as 1 ms.
fn route_grace_from_config(ms: u32) -> Duration {
    if ms == 0 {
        return route::DEFAULT_ROUTE_GRACE;
    }
    Duration::from_millis(u64::from(ms))
}

fn ffi_guard(f: impl FnOnce() -> i32) -> i32 {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(code) => code,
        Err(_) => ERR_INTERNAL,
    }
}

fn c_path<'a>(path_utf8: *const c_char) -> Result<&'a str, i32> {
    if path_utf8.is_null() {
        return Err(ERR_INVALID_ARGUMENT);
    }
    unsafe { CStr::from_ptr(path_utf8) }
        .to_str()
        .map_err(|_| ERR_INVALID_ARGUMENT)
}

/// Like `c_path`, but NULL means "not supplied" rather than an error.
fn optional_c_str<'a>(value: *const c_char) -> Result<Option<&'a str>, i32> {
    if value.is_null() {
        return Ok(None);
    }
    c_path(value).map(Some)
}

fn report_json(report: &transfer::TransferReport) -> Vec<u8> {
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    serde_json::to_vec(&serde_json::json!({
        "transfer_id": hex(&report.transfer_id),
        "object_id": hex(&report.object_id),
        "ciphertext_root": hex(&report.ciphertext_root),
        "plaintext_digest": hex(&report.plaintext_digest),
        "bytes": report.bytes,
        "chunks": report.chunks,
        "chunks_transferred": report.chunks_transferred,
        "manifest_commitment": hex(&report.manifest_commitment),
        "peer_device_id": hex(&report.peer_device_id),
        "peer_endpoint_id": hex(&report.peer_endpoint_id),
        "route": report.route.describe(),
    }))
    .expect("report serialization is infallible")
}

// ---------------------------------------------------------------------------
// Runtime
// ---------------------------------------------------------------------------

/// # Safety
/// `config` must point to a valid `rtp2_runtime_config_t`; `out_runtime` must
/// be a valid writable pointer.
#[unsafe(no_mangle)]
pub extern "C" fn rtp2_runtime_new(config: *const Rtp2RuntimeConfig, out_runtime: *mut u64) -> i32 {
    ffi_guard(|| {
        if config.is_null() || out_runtime.is_null() {
            return ERR_INVALID_ARGUMENT;
        }
        let config = unsafe { &*config };
        // An ABI mismatch has to be an explicit error, not memory corruption
        // found later.
        if config.abi_version != ABI_VERSION
            || (config.struct_size as usize) < std::mem::size_of::<Rtp2RuntimeConfig>()
        {
            return ERR_ABI_MISMATCH;
        }

        // Reserved means reserved. Refusing non-zero now keeps the field
        // usable later without another ABI bump.
        if config.reserved != 0 {
            return ERR_INVALID_ARGUMENT;
        }
        let Some(route_policy) = route::RoutePolicy::from_u64(config.route_policy as u64) else {
            return ERR_INVALID_ARGUMENT;
        };
        let route_grace = route_grace_from_config(config.route_grace_ms);

        let protection = match config.key_protection {
            KEY_PROTECTION_PLAINTEXT => store::Protection::Plaintext,
            KEY_PROTECTION_PLATFORM_KEYSTORE => store::Protection::PlatformKeystore,
            KEY_PROTECTION_HARDWARE_KEYSTORE => store::Protection::HardwareKeystore,
            _ => return ERR_INVALID_ARGUMENT,
        };

        // A state directory makes the identity persistent; NULL keeps it
        // per-process.
        let (identity, store, key_protection) = if config.state_dir_utf8.is_null() {
            // An ephemeral identity is never written, so asking to protect
            // it at rest is a config error, not a no-op: the caller thinks it
            // is getting a durable sealed device.
            if protection > store::Protection::Plaintext {
                return ERR_INVALID_ARGUMENT;
            }
            (DeviceIdentity::generate(), None, "ephemeral".to_string())
        } else {
            let dir = match c_path(config.state_dir_utf8) {
                Ok(value) => value,
                Err(code) => return code,
            };
            let store = match store::DeviceStore::open(Path::new(dir)) {
                Ok(value) => value,
                Err(e) => return store_error_code(&e),
            };

            // Item coordinates are shared by both keystore levels.
            let service = match optional_c_str(config.keystore_service_utf8) {
                Ok(Some(value)) => value,
                Ok(None) => keystore::DEFAULT_SERVICE,
                Err(code) => return code,
            };
            let account = match optional_c_str(config.keystore_account_utf8) {
                Ok(Some(value)) => value,
                Ok(None) => keystore::DEFAULT_ACCOUNT,
                Err(code) => return code,
            };

            // Neither level falls back to a weaker one. A caller that asked
            // for protection it cannot have is told, and no seed is written in
            // the clear behind its back.
            let (store, description) = match protection {
                store::Protection::Plaintext => (store, "plaintext".to_string()),
                store::Protection::PlatformKeystore => {
                    let sealer = match keystore::KeystoreSealer::open(service, account) {
                        Ok(value) => value,
                        Err(_) => return ERR_KEYSTORE,
                    };
                    let description = format!("platform-keystore/{}", sealer.describe());
                    (
                        store.with_sealer(Box::new(sealer), store::Protection::PlatformKeystore),
                        description,
                    )
                }
                store::Protection::HardwareKeystore => {
                    // `DeviceStore::open` already made the directory 0700,
                    // which the wrapped vault key relies on.
                    let sealer =
                        match keystore::HardwareSealer::open(Path::new(dir), service, account) {
                            Ok(value) => value,
                            Err(_) => return ERR_KEYSTORE,
                        };
                    let description = format!("hardware-keystore/{}", sealer.describe());
                    (
                        store.with_sealer(Box::new(sealer), store::Protection::HardwareKeystore),
                        description,
                    )
                }
            };

            match store.load_or_create_identity() {
                Ok((identity, _loaded)) => (identity, Some(store), description),
                Err(e) => return store_error_code(&e),
            }
        };

        let runtime = match Builder::new_multi_thread().enable_all().build() {
            Ok(value) => value,
            Err(_) => return ERR_INTERNAL,
        };

        let handle = insert_handle(HandleValue::Runtime(Arc::new(RuntimeState {
            runtime,
            identity,
            store,
            key_protection,
            route_policy,
            route_grace,
            events: events::EventQueue::new(),
            last_error: Mutex::new(String::new()),
        })));
        unsafe { *out_runtime = handle };
        OK
    })
}

/// `rtp2_runtime_new` fails before a handle exists, so there is no
/// `rtp2_last_error` to read: only the return code, mapped in rtp2.h.
fn store_error_code(err: &store::StoreError) -> i32 {
    match err {
        store::StoreError::Io(_)
        | store::StoreError::UnsafePath(_)
        | store::StoreError::NotRegularFile(_) => ERR_IO,
        store::StoreError::Corrupt
        | store::StoreError::VersionMismatch
        | store::StoreError::ProtectionDowngrade
        | store::StoreError::Seal => ERR_CRYPTO,
    }
}

/// Writes this device's 32-byte id. Public data, not key material: it is here
/// so an application can tell whether the identity survived a restart.
#[unsafe(no_mangle)]
pub extern "C" fn rtp2_device_id(runtime_handle: u64, out_device_id: *mut u8) -> i32 {
    ffi_guard(|| {
        if out_device_id.is_null() {
            return ERR_INVALID_ARGUMENT;
        }
        let Some(rt) = runtime(runtime_handle) else {
            return ERR_NOT_FOUND;
        };
        unsafe {
            ptr::copy_nonoverlapping(rt.identity.device_id.as_ptr(), out_device_id, 32);
        }
        OK
    })
}

/// Writes what actually protects this device's seed at rest, as UTF-8.
///
/// One of `"ephemeral"`, `"plaintext"`, or `"platform-keystore/<backend>"`.
/// The *observed* posture, not the requested one, so an application that must
/// not run with a plaintext seed asserts on this rather than on its config.
#[unsafe(no_mangle)]
pub extern "C" fn rtp2_key_protection(runtime_handle: u64, out_utf8: *mut Rtp2Buffer) -> i32 {
    ffi_guard(|| {
        if out_utf8.is_null() {
            return ERR_INVALID_ARGUMENT;
        }
        let Some(rt) = runtime(runtime_handle) else {
            return ERR_NOT_FOUND;
        };
        unsafe { *out_utf8 = into_buffer(rt.key_protection.clone().into_bytes()) };
        OK
    })
}

/// Removes a wrapping key from the keystore. This retires a device rather
/// than rotating it: every record under that key, identity included, becomes
/// permanently unopenable. No runtime handle, so it still works once the
/// keystore and the state directory have drifted apart.
///
/// `out_removed` is 1 if something was removed, 0 if there was nothing. Both
/// are success.
#[unsafe(no_mangle)]
pub extern "C" fn rtp2_keystore_forget(
    service_utf8: *const c_char,
    account_utf8: *const c_char,
    out_removed: *mut i32,
) -> i32 {
    ffi_guard(|| {
        let service = match optional_c_str(service_utf8) {
            Ok(Some(value)) => value,
            Ok(None) => keystore::DEFAULT_SERVICE,
            Err(code) => return code,
        };
        let account = match optional_c_str(account_utf8) {
            Ok(Some(value)) => value,
            Ok(None) => keystore::DEFAULT_ACCOUNT,
            Err(code) => return code,
        };
        let Ok(store) = keystore::Keystore::platform_default() else {
            return ERR_KEYSTORE;
        };
        match store.forget(service, account) {
            Ok(removed) => {
                if !out_removed.is_null() {
                    unsafe { *out_removed = i32::from(removed) };
                }
                OK
            }
            Err(_) => ERR_KEYSTORE,
        }
    })
}

/// Next event for this runtime, as deterministic RTP-CBOR.
///
/// `RTP2_ERR_TIMEOUT` when nothing arrived within `timeout_ms`; zero polls
/// without blocking. The queue is bounded, so an application that stops
/// calling this loses events but never stalls a transfer.
#[unsafe(no_mangle)]
pub extern "C" fn rtp2_poll_event(
    runtime_handle: u64,
    timeout_ms: u32,
    out_event_cbor: *mut Rtp2Buffer,
) -> i32 {
    ffi_guard(|| {
        if out_event_cbor.is_null() {
            return ERR_INVALID_ARGUMENT;
        }
        let Some(rt) = runtime(runtime_handle) else {
            return ERR_NOT_FOUND;
        };
        match rt.events.poll(Duration::from_millis(timeout_ms as u64)) {
            Some(event) => {
                unsafe { *out_event_cbor = into_buffer(event.encode()) };
                OK
            }
            // Out-parameters stay untouched on every error return.
            None => ERR_TIMEOUT,
        }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn rtp2_runtime_free(handle: u64) -> i32 {
    ffi_guard(|| {
        if HANDLES.lock().remove(&handle).is_some() {
            OK
        } else {
            ERR_NOT_FOUND
        }
    })
}

/// Returns the UTF-8 description of the most recent error on this runtime.
#[unsafe(no_mangle)]
pub extern "C" fn rtp2_last_error(runtime_handle: u64, out_utf8: *mut Rtp2Buffer) -> i32 {
    ffi_guard(|| {
        if out_utf8.is_null() {
            return ERR_INVALID_ARGUMENT;
        }
        let Some(rt) = runtime(runtime_handle) else {
            return ERR_NOT_FOUND;
        };
        let message = rt.last_error.lock().clone();
        unsafe { *out_utf8 = into_buffer(message.into_bytes()) };
        OK
    })
}

// ---------------------------------------------------------------------------
// Endpoint
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn rtp2_endpoint_start(runtime_handle: u64, out_endpoint: *mut u64) -> i32 {
    ffi_guard(|| {
        if out_endpoint.is_null() {
            return ERR_INVALID_ARGUMENT;
        }
        let Some(rt) = runtime(runtime_handle) else {
            return ERR_NOT_FOUND;
        };

        // Public n0 preset for bootstrap connectivity, and an ALPN that keeps
        // inbound connections to RTP/2. The endpoint key comes from the device
        // seed, so a persistent identity keeps a stable Endpoint ID and a
        // certificate can be matched against the observed peer.
        let endpoint_secret = rt.identity.endpoint_secret();
        let bound = rt.runtime.block_on({
            let builder = Endpoint::builder(presets::N0)
                .secret_key(iroh::SecretKey::from_bytes(&endpoint_secret))
                .alpns(vec![ALPN.to_vec()]);
            // A loopback-only endpoint has to bind to loopback. Binding
            // everywhere yields no 127.0.0.1 candidate at all, so the policy
            // would refuse every path it could offer.
            match rt.route_policy {
                route::RoutePolicy::LoopbackOnly => builder
                    .bind_addr("127.0.0.1:0")
                    .expect("literal address")
                    .bind(),
                _ => builder.bind(),
            }
        });
        let endpoint = match bound {
            Ok(value) => value,
            Err(e) => {
                rt.set_error(format!("endpoint bind failed: {e}"));
                return ERR_INTERNAL;
            }
        };

        let handle = insert_handle(HandleValue::Endpoint(Arc::new(EndpointState {
            endpoint,
            runtime: Arc::clone(&rt),
            replay: Mutex::new(ReplayCache::default()),
        })));
        unsafe { *out_endpoint = handle };
        OK
    })
}

/// Writes the endpoint's `EndpointAddr` as CBOR. Opaque to the application:
/// pass it unchanged to `rtp2_send_file` on the dialing side.
#[unsafe(no_mangle)]
pub extern "C" fn rtp2_endpoint_address(endpoint_handle: u64, out_cbor: *mut Rtp2Buffer) -> i32 {
    ffi_guard(|| {
        if out_cbor.is_null() {
            return ERR_INVALID_ARGUMENT;
        }
        let Some(ep) = endpoint(endpoint_handle) else {
            return ERR_NOT_FOUND;
        };

        // Advertise only what the policy accepts, so a peer is never handed
        // an address admission would refuse.
        let mut addr = ep.endpoint.addr();
        let policy = ep.runtime.route_policy;
        addr.addrs.retain(|a| policy.advertises(a));

        let mut bytes = Vec::new();
        if ciborium::into_writer(&addr, &mut bytes).is_err() {
            ep.runtime
                .set_error("endpoint address serialization failed");
            return ERR_INTERNAL;
        }
        unsafe { *out_cbor = into_buffer(bytes) };
        OK
    })
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn rtp2_blake3_hash_file(path_utf8: *const c_char, out_hash: *mut u8) -> i32 {
    ffi_guard(|| {
        if out_hash.is_null() {
            return ERR_INVALID_ARGUMENT;
        }
        let path = match c_path(path_utf8) {
            Ok(value) => value,
            Err(code) => return code,
        };

        let mut file = match File::open(path) {
            Ok(value) => value,
            Err(_) => return ERR_IO,
        };

        let mut hasher = Hasher::new();
        let mut buffer = vec![0_u8; 1024 * 1024];
        loop {
            let count = match file.read(&mut buffer) {
                Ok(value) => value,
                Err(_) => return ERR_IO,
            };
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }

        let digest = hasher.finalize();
        unsafe {
            ptr::copy_nonoverlapping(digest.as_bytes().as_ptr(), out_hash, 32);
        }
        OK
    })
}

// ---------------------------------------------------------------------------
// Transfers
// ---------------------------------------------------------------------------

/// Maps a failure to the §23.2 protocol code an event carries. Not
/// `transfer_error_code`, which maps to the ABI's own return codes: the
/// detailed reason stays local.
fn spec_error_code(err: &transfer::TransferError) -> u64 {
    match err {
        transfer::TransferError::Handshake => 0x0006, // HANDSHAKE_FAILED
        // One generic code for every cryptographic failure: saying which
        // check tripped turns each one into an oracle. This event is local, so
        // a specific code would be allowed, but a single mapping means the
        // local value can never be forwarded by mistake.
        transfer::TransferError::Crypto(_) => 0x0018, // CRYPTO_FAILURE
        transfer::TransferError::Io(_) | transfer::TransferError::Timeout => 0x0016, // TRANSPORT_FAILURE
        transfer::TransferError::Protocol(_) => 0x0017, // MALFORMED_FRAME
        // POLICY_REJECTED: the application excluded the path, not the peer.
        transfer::TransferError::RouteRefused(_) => 0x0014,
    }
}

fn transfer_error_code(err: &transfer::TransferError) -> i32 {
    match err {
        transfer::TransferError::Io(_) => ERR_IO,
        transfer::TransferError::Timeout => ERR_TIMEOUT,
        transfer::TransferError::Handshake | transfer::TransferError::Crypto(_) => ERR_CRYPTO,
        transfer::TransferError::Protocol(_) => ERR_INTERNAL,
        // Its own code, because retrying will not help until the policy or
        // the network changes. Without it an application retries forever.
        transfer::TransferError::RouteRefused(_) => ERR_ROUTE_REFUSED,
    }
}

/// Sends a file to the peer named by `addr_cbor`, blocking until the receiver
/// has verified every chunk and acknowledged the plaintext digest. On success
/// writes a JSON report, owned by the caller, holding no key material.
#[unsafe(no_mangle)]
pub extern "C" fn rtp2_send_file(
    endpoint_handle: u64,
    addr_cbor: *const u8,
    addr_cbor_len: usize,
    path_utf8: *const c_char,
    out_report_json: *mut Rtp2Buffer,
) -> i32 {
    ffi_guard(|| {
        if addr_cbor.is_null() || addr_cbor_len == 0 || out_report_json.is_null() {
            return ERR_INVALID_ARGUMENT;
        }
        let path = match c_path(path_utf8) {
            Ok(value) => value,
            Err(code) => return code,
        };
        let Some(ep) = endpoint(endpoint_handle) else {
            return ERR_NOT_FOUND;
        };

        let addr_bytes = unsafe { std::slice::from_raw_parts(addr_cbor, addr_cbor_len) };
        let addr: EndpointAddr = match ciborium::from_reader(addr_bytes) {
            Ok(value) => value,
            Err(_) => {
                ep.runtime.set_error("invalid endpoint address blob");
                return ERR_INVALID_ARGUMENT;
            }
        };

        let result = ep.runtime.runtime.block_on(transfer::send_file(
            &ep.endpoint,
            &ep.runtime.identity,
            addr,
            Path::new(path),
            Some(&ep.runtime.events),
            route::RouteAdmission {
                policy: ep.runtime.route_policy,
                grace: ep.runtime.route_grace,
            },
        ));
        match result {
            Ok(report) => {
                unsafe { *out_report_json = into_buffer(report_json(&report)) };
                OK
            }
            Err(err) => {
                ep.runtime.set_error(format!("send failed: {err}"));
                ep.runtime.events.push(events::Event::TransferFailed {
                    // A failure before the offer has no transfer id, and
                    // inventing one would name a transfer that never was.
                    transfer_id: [0u8; 32],
                    code: spec_error_code(&err),
                });
                transfer_error_code(&err)
            }
        }
    })
}

/// Waits up to `accept_timeout_ms` for one inbound transfer, verifies and
/// decrypts it to `dest_path_utf8`, then acknowledges the sender. Writes a
/// JSON report, owned by the caller, holding no key material.
#[unsafe(no_mangle)]
pub extern "C" fn rtp2_receive_file(
    endpoint_handle: u64,
    dest_path_utf8: *const c_char,
    accept_timeout_ms: u32,
    out_report_json: *mut Rtp2Buffer,
) -> i32 {
    rtp2_receive_file_resumable(
        endpoint_handle,
        dest_path_utf8,
        accept_timeout_ms,
        core::ptr::null(),
        out_report_json,
    )
}

/// [`rtp2_receive_file`] with resume state in `state_path_utf8`, so an
/// interrupted transfer continues instead of starting over. The state is used
/// only when it describes exactly the object on offer; anything else means the
/// bytes on disk belong elsewhere and the transfer restarts. NULL disables it.
#[unsafe(no_mangle)]
pub extern "C" fn rtp2_receive_file_resumable(
    endpoint_handle: u64,
    dest_path_utf8: *const c_char,
    accept_timeout_ms: u32,
    state_path_utf8: *const c_char,
    out_report_json: *mut Rtp2Buffer,
) -> i32 {
    ffi_guard(|| {
        if out_report_json.is_null() {
            return ERR_INVALID_ARGUMENT;
        }
        let dest = match c_path(dest_path_utf8) {
            Ok(value) => value,
            Err(code) => return code,
        };
        let state = if state_path_utf8.is_null() {
            None
        } else {
            match c_path(state_path_utf8) {
                Ok(value) => Some(value),
                Err(code) => return code,
            }
        };
        let Some(ep) = endpoint(endpoint_handle) else {
            return ERR_NOT_FOUND;
        };

        let timeout = Duration::from_millis(accept_timeout_ms as u64);
        let mut replay = ep.replay.lock();
        let result = ep.runtime.runtime.block_on(transfer::receive_file(
            &ep.endpoint,
            &ep.runtime.identity,
            &mut replay,
            Path::new(dest),
            timeout,
            transfer::ReceiveOptions {
                resume_state: state.map(Path::new),
                events: Some(&ep.runtime.events),
                admission: route::RouteAdmission {
                    policy: ep.runtime.route_policy,
                    grace: ep.runtime.route_grace,
                },
            },
        ));
        match result {
            Ok(report) => {
                unsafe { *out_report_json = into_buffer(report_json(&report)) };
                OK
            }
            Err(err) => {
                ep.runtime.set_error(format!("receive failed: {err}"));
                ep.runtime.events.push(events::Event::TransferFailed {
                    transfer_id: [0u8; 32],
                    code: spec_error_code(&err),
                });
                transfer_error_code(&err)
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Buffers
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn rtp2_buffer_free(buffer: Rtp2Buffer) {
    if buffer.ptr.is_null() {
        return;
    }
    unsafe {
        drop(Vec::from_raw_parts(buffer.ptr, buffer.len, buffer.cap));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_configured_route_grace_is_the_one_used() {
        // Zero is not "no wait": callers compiled against the header where
        // this field was reserved pass zero, and silently giving them a
        // zero-length grace period would reintroduce the refusal that judging
        // a path at the first instant caused.
        assert_eq!(route_grace_from_config(0), route::DEFAULT_ROUTE_GRACE);

        // Anything else is honoured exactly, including the smallest value —
        // which is how a caller asks for no wait at all.
        assert_eq!(route_grace_from_config(1), Duration::from_millis(1));
        assert_eq!(route_grace_from_config(45_000), Duration::from_secs(45));
        assert_eq!(
            route_grace_from_config(u32::MAX),
            Duration::from_millis(u64::from(u32::MAX))
        );

        // And a configured value is never silently the default.
        let default_ms = route::DEFAULT_ROUTE_GRACE.as_millis() as u32;
        assert_ne!(
            route_grace_from_config(default_ms + 1),
            route::DEFAULT_ROUTE_GRACE
        );
    }

    /// Two endpoints in one process move a file over real QUIC, running the
    /// whole handshake, envelope and Merkle pipeline.
    #[test]
    fn loopback_transfer() {
        let rt = Builder::new_multi_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let sender_id = DeviceIdentity::generate();
            let receiver_id = DeviceIdentity::generate();

            let sender_ep = Endpoint::builder(presets::N0)
                .alpns(vec![ALPN.to_vec()])
                .bind()
                .await
                .unwrap();
            let receiver_ep = Endpoint::builder(presets::N0)
                .alpns(vec![ALPN.to_vec()])
                .bind()
                .await
                .unwrap();
            let receiver_addr = receiver_ep.addr();

            let dir = std::env::temp_dir().join(format!("rtp2-loopback-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let src = dir.join("src.bin");
            let dst = dir.join("dst.bin");
            // Several chunks plus a short tail.
            let payload: Vec<u8> = (0..(3 * DEFAULT_TEST_CHUNK + 12345))
                .map(|i| (i % 251) as u8)
                .collect();
            std::fs::write(&src, &payload).unwrap();

            let mut replay = ReplayCache::default();
            let events = events::EventQueue::new();
            let recv_task = transfer::receive_file(
                &receiver_ep,
                &receiver_id,
                &mut replay,
                &dst,
                Duration::from_secs(30),
                transfer::ReceiveOptions {
                    events: Some(&events),
                    ..Default::default()
                },
            );
            let send_task = transfer::send_file(
                &sender_ep,
                &sender_id,
                receiver_addr,
                &src,
                Some(&events),
                route::RoutePolicy::Any,
            );

            let (sent, received) = tokio::join!(send_task, recv_task);
            let sent = sent.expect("send side");
            let received = received.expect("receive side");

            assert_eq!(sent.plaintext_digest, received.plaintext_digest);
            assert_eq!(sent.ciphertext_root, received.ciphertext_root);
            assert_eq!(std::fs::read(&dst).unwrap(), payload);

            std::fs::remove_dir_all(&dir).ok();
        });
    }

    const DEFAULT_TEST_CHUNK: usize = transfer::DEFAULT_CHUNK_SIZE as usize;
}
