/*
 * Copyright 2026 The Reyta Labs Authors.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef REYTA_RTP2_H
#define REYTA_RTP2_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * RTP/2 native core: versioned C ABI (§25).
 *
 * ABI compatibility rule: rtp2_runtime_new fails with RTP2_ERR_ABI_MISMATCH
 * unless the caller passes exactly RTP2_ABI_VERSION and a config struct at
 * least as large as the version it was compiled against. Any change to
 * struct layouts or function signatures bumps RTP2_ABI_VERSION.
 *
 * Buffer ownership: on success, out rtp2_buffer_t values are owned by the
 * caller and MUST be released with rtp2_buffer_free exactly once. On any
 * error return, out-parameters are untouched and own nothing.
 *
 * Key material NEVER crosses this ABI (§25.1). Handles are opaque, never
 * reused, and safe to probe after free (calls fail with RTP2_ERR_NOT_FOUND).
 */

#define RTP2_ABI_VERSION 6u

#define RTP2_OK                    0
#define RTP2_ERR_INVALID_ARGUMENT (-1)
#define RTP2_ERR_NOT_FOUND        (-2)
#define RTP2_ERR_INTERNAL         (-3)
#define RTP2_ERR_CRYPTO           (-4)
#define RTP2_ERR_IO               (-5)
#define RTP2_ERR_ABI_MISMATCH     (-6)
#define RTP2_ERR_TIMEOUT          (-7)
/*
 * The platform keystore was requested and could not be used: no backend on
 * this OS, a binary not entitled to reach it, or a keychain that refused.
 * Separate from RTP2_ERR_CRYPTO because the remedy is environmental, not a
 * bad record, and because the core NEVER answers this by writing the seed
 * in the clear instead.
 */
#define RTP2_ERR_KEYSTORE         (-8)
/*
 * The connection's path was excluded by the caller's route policy (§16.3.1).
 * Nothing is wrong with the peer, the data or the cryptography: the
 * application asked not to send over this kind of path. Distinct from every
 * transport code because retrying will not help until the policy or the
 * network changes.
 */
#define RTP2_ERR_ROUTE_REFUSED    (-9)

/* Values for rtp2_runtime_config_t::route_policy (§16.3.1). */
#define RTP2_ROUTE_ANY           0u
#define RTP2_ROUTE_DIRECT_ONLY   1u
#define RTP2_ROUTE_LOOPBACK_ONLY 2u

/* Values for rtp2_runtime_config_t::key_protection (§28.1). */
#define RTP2_KEY_PROTECTION_PLAINTEXT         0u
#define RTP2_KEY_PROTECTION_PLATFORM_KEYSTORE 1u
#define RTP2_KEY_PROTECTION_HARDWARE_KEYSTORE 2u

typedef uint64_t rtp2_handle_t;

typedef struct rtp2_buffer {
    uint8_t *ptr;
    size_t len;
    size_t cap;
} rtp2_buffer_t;

typedef struct rtp2_runtime_config {
    uint32_t abi_version;    /* must be RTP2_ABI_VERSION */
    uint32_t struct_size;    /* must be sizeof(rtp2_runtime_config_t) */
    const char *json_config; /* optional, may be NULL */
    /*
     * Directory holding this device's persistent identity (§7.2) and, later,
     * its prekey batch (§8.3) and resumption secrets (§8.4). NULL means an
     * ephemeral identity that exists only for the life of this process.
     *
     * Created with mode 0700 if absent. A directory or record readable by
     * group or other, or a record that is not a regular file, is refused.
     *
     * rtp2_runtime_new fails before a runtime handle exists, so these errors
     * have no rtp2_last_error text. The mapping is:
     *   RTP2_ERR_IO       unreadable, unwritable, or unsafe path
     *   RTP2_ERR_CRYPTO   corrupt record, wrong version, or unsealing failed
     *   RTP2_ERR_KEYSTORE the requested platform keystore was unusable
     * A corrupt identity record is NEVER replaced with a fresh identity.
     */
    const char *state_dir_utf8;

    /*
     * How the device seed is protected at rest (§28.1).
     *
     * RTP2_KEY_PROTECTION_PLAINTEXT (0) is the prototype default: the seed
     * sits in a 0600 file, readable by anything that can read the file.
     *
     * RTP2_KEY_PROTECTION_PLATFORM_KEYSTORE (1) wraps it under a key held by
     * the platform keystore, so the file holds only ciphertext. This is the
     * level that works on the widest set of machines: it needs no code
     * signing and no entitlement, and its APIs predate Sonoma by years.
     *
     * RTP2_KEY_PROTECTION_HARDWARE_KEYSTORE (2) wraps it under a key that
     * cannot leave the security processor, so a copied disk or keychain is
     * useless off that machine. On macOS this needs a PROVISIONED, ENTITLED,
     * SIGNED app bundle: a bare CLI binary cannot create a Secure Enclave key
     * whatever it is signed with. Measured statuses are recorded in
     * src/keystore.rs. Use it from the shipping app, not from tools.
     *
     * If the requested level cannot be used, rtp2_runtime_new returns
     * RTP2_ERR_KEYSTORE: it never silently writes a plaintext seed, and
     * never silently drops from level 2 to level 1.
     *
     * Only meaningful with state_dir_utf8: asking to protect an identity that
     * is never written is RTP2_ERR_INVALID_ARGUMENT, not a no-op.
     *
     * Losing the keystore item makes an existing record unopenable, and that
     * is RTP2_ERR_CRYPTO, never a fresh identity: a new device id would break
     * every peer's trust-on-first-use pin.
     */
    uint32_t key_protection;
    uint32_t reserved; /* must be 0 */

    /*
     * Keystore item coordinates. NULL selects "com.reyta.rtp2" and
     * "device-identity". Two runtimes naming the same pair share one wrapping
     * key; naming different pairs keeps them separate.
     */
    const char *keystore_service_utf8;
    const char *keystore_account_utf8;

    /*
     * Which network paths this runtime's transfers may use (§16.3.1).
     *
     * RTP2_ROUTE_ANY (0) accepts any path and still reports which one was
     * used, in the TRANSFER_ROUTE event and in the transfer report.
     *
     * RTP2_ROUTE_DIRECT_ONLY (1) refuses a relayed path: the transfer fails
     * with RTP2_ERR_ROUTE_REFUSED rather than sending ciphertext through a
     * node the application does not operate. This is what §1.3's
     * PRIVATE_RELAY and STEALTH_TRANSFER profiles need in order to mean
     * anything.
     *
     * RTP2_ROUTE_LOOPBACK_ONLY (2) refuses anything that leaves the machine.
     *
     * A path the implementation cannot classify satisfies only
     * RTP2_ROUTE_ANY: a policy whose point is to keep bytes off other
     * people's machines must not be satisfied by a guess.
     *
     * The check happens before any protocol byte is sent. Runtime-wide for
     * now; §1.3 makes the route profile a property of the transfer, so a
     * future ABI moves it to a per-transfer options struct.
     */
    uint32_t route_policy;
    uint32_t reserved2; /* must be 0 */
} rtp2_runtime_config_t;

/* Runtime: owns the Tokio executor and this device's identity keys. */
int32_t rtp2_runtime_new(
    const rtp2_runtime_config_t *config,
    rtp2_handle_t *out_runtime);

int32_t rtp2_runtime_free(rtp2_handle_t runtime);

/* This device's 32-byte device id (§7.2). Public data, not key material. */
int32_t rtp2_device_id(
    rtp2_handle_t runtime,
    uint8_t out_device_id[32]);

/*
 * What actually protects this device's seed at rest: "ephemeral",
 * "plaintext", or "platform-keystore/<backend>". The observed posture, not
 * the requested one: assert on this rather than on the config you passed.
 * Public data, not key material.
 */
int32_t rtp2_key_protection(
    rtp2_handle_t runtime,
    rtp2_buffer_t *out_utf8);

/*
 * Takes the next event for this runtime as deterministic RTP-CBOR matching the
 * `event` rule in rtp2.cddl (§25.3.1).
 *
 * Returns RTP2_ERR_TIMEOUT when nothing arrived within timeout_ms; a zero
 * timeout polls without blocking. The queue is bounded: an application that
 * stops polling loses events: reported through EVENTS_DROPPED, but never
 * stalls a transfer or grows the process.
 *
 * Events carry identifiers, counters and §23.2 codes only. No key material,
 * plaintext, capability token, ticket text or file path ever appears in one.
 *
 * TRANSFER_PROGRESS carries the role it was measured in: receiving counts
 * verified bytes, sending counts transmitted bytes. Sending-role progress is
 * NOT delivery confirmation: only TRANSFER_COMPLETED is.
 */
int32_t rtp2_poll_event(
    rtp2_handle_t runtime,
    uint32_t timeout_ms,
    rtp2_buffer_t *out_event_cbor);

/* UTF-8 description of the most recent error on this runtime. */
int32_t rtp2_last_error(
    rtp2_handle_t runtime,
    rtp2_buffer_t *out_utf8);

/*
 * Removes a wrapping key from the platform keystore. NULL selects the default
 * service and account.
 *
 * This RETIRES a device: every record sealed under that key, including the
 * device identity, becomes permanently unopenable. It takes no runtime handle
 * so it stays callable once the keystore and the state directory have drifted
 * apart and no runtime can be built.
 *
 * out_removed (may be NULL) is 1 when an item was removed and 0 when there
 * was nothing to remove. Both return RTP2_OK.
 */
int32_t rtp2_keystore_forget(
    const char *service_utf8,
    const char *account_utf8,
    int32_t *out_removed);

/* Endpoint: an Iroh endpoint accepting ALPN "reyta-transfer/2". */
int32_t rtp2_endpoint_start(
    rtp2_handle_t runtime,
    rtp2_handle_t *out_endpoint);

/* Current EndpointAddr as an opaque CBOR blob; pass to rtp2_send_file. */
int32_t rtp2_endpoint_address(
    rtp2_handle_t endpoint,
    rtp2_buffer_t *out_cbor);

/* Streaming BLAKE3-256 of a file. out_hash must hold 32 bytes. */
int32_t rtp2_blake3_hash_file(
    const char *path_utf8,
    uint8_t out_hash[32]);

/*
 * Sends one file to the peer named by addr_cbor. Runs the full hybrid
 * handshake (X25519 + ML-KEM-768, Ed25519 + ML-DSA-65), delivers the file
 * key in a sealed envelope, streams encrypted chunks with Merkle proofs and
 * blocks until the receiver acknowledges the verified plaintext digest.
 * On success out_report_json holds a UTF-8 JSON report (no key material).
 */
int32_t rtp2_send_file(
    rtp2_handle_t endpoint,
    const uint8_t *addr_cbor,
    size_t addr_cbor_len,
    const char *path_utf8,
    rtp2_buffer_t *out_report_json);

/*
 * Waits up to accept_timeout_ms for one inbound transfer and writes the
 * verified plaintext to dest_path_utf8. Every chunk is proof-checked and
 * AEAD-authenticated before it is persisted.
 */
int32_t rtp2_receive_file(
    rtp2_handle_t endpoint,
    const char *dest_path_utf8,
    uint32_t accept_timeout_ms,
    rtp2_buffer_t *out_report_json);

/*
 * As rtp2_receive_file, but keeps resume state in state_path_utf8 so an
 * interrupted transfer continues where it stopped. The state file is used
 * only if it describes exactly the object on offer; otherwise the transfer
 * restarts. Pass NULL to disable resume.
 */
int32_t rtp2_receive_file_resumable(
    rtp2_handle_t endpoint,
    const char *dest_path_utf8,
    uint32_t accept_timeout_ms,
    const char *state_path_utf8,
    rtp2_buffer_t *out_report_json);

void rtp2_buffer_free(rtp2_buffer_t buffer);

#ifdef __cplusplus
}
#endif
#endif
