// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build cgo

// Package rtp2 wraps the versioned RTP/2 native-core C ABI (v5).
//
// Ownership split (§25.1), all cryptography, keys and transport live in the
// Rust core. This layer holds opaque handles and receives only public data:
// address blobs, transfer reports, digests.
package rtp2

/*
#cgo CFLAGS: -I${SRCDIR}/../native/rtp2-core/include
#cgo linux LDFLAGS: -L${SRCDIR}/../native/rtp2-core/target/release -lrtp2_core -ldl -lpthread -lm
#cgo darwin LDFLAGS: -L${SRCDIR}/../native/rtp2-core/target/release -lrtp2_core -framework Security -framework SystemConfiguration -framework CoreFoundation -framework CoreWLAN
#include <stdlib.h>
#include "rtp2.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

type Runtime struct {
	handle C.rtp2_handle_t
}

type Endpoint struct {
	handle  C.rtp2_handle_t
	runtime *Runtime
}

// KeyProtection selects how the device seed is protected at rest (§28.1).
type KeyProtection uint32

const (
	// KeyProtectionPlaintext leaves the seed in a 0600 file. Prototype
	// default: whoever can read the file is the device.
	KeyProtectionPlaintext KeyProtection = C.RTP2_KEY_PROTECTION_PLAINTEXT
	// KeyProtectionPlatformKeystore wraps the seed under a key held by the
	// platform keystore, so the file holds only ciphertext. If the keystore
	// cannot be used, NewRuntimeWithOptions fails: it never falls back to a
	// plaintext seed.
	KeyProtectionPlatformKeystore KeyProtection = C.RTP2_KEY_PROTECTION_PLATFORM_KEYSTORE
	// KeyProtectionHardwareKeystore wraps the seed under a key that cannot
	// leave the security processor. On macOS this requires a provisioned,
	// entitled, signed app bundle: a plain CLI binary cannot create a Secure
	// Enclave key however it is signed. Prefer KeyProtectionPlatformKeystore
	// for tools and for the widest device coverage.
	KeyProtectionHardwareKeystore KeyProtection = C.RTP2_KEY_PROTECTION_HARDWARE_KEYSTORE
)

// RoutePolicy selects which network paths a runtime's transfers may use
// (§16.3.1).
type RoutePolicy uint32

const (
	// RouteAny accepts any path. The route is still reported.
	RouteAny RoutePolicy = C.RTP2_ROUTE_ANY
	// RouteDirectOnly refuses a relayed path: the transfer fails rather than
	// sending ciphertext through a node the application does not operate.
	RouteDirectOnly RoutePolicy = C.RTP2_ROUTE_DIRECT_ONLY
	// RouteLoopbackOnly refuses anything that leaves the machine.
	RouteLoopbackOnly RoutePolicy = C.RTP2_ROUTE_LOOPBACK_ONLY
)

// NativeError carries the numeric code the core returned, so a caller can
// branch on the reason instead of matching on message text.
type NativeError struct {
	Op     string
	Code   int32
	Detail string
}

func (e *NativeError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("%s failed with native code %d: %s", e.Op, e.Code, e.Detail)
	}
	return fmt.Sprintf("%s failed with native code %d", e.Op, e.Code)
}

// IsRouteRefused reports whether err is a route-policy refusal (§16.3.1)
// rather than a transport or cryptographic failure. Retrying will not help
// until either the policy or the network changes, so a caller that cannot
// tell the difference will retry a path that will always be refused.
func IsRouteRefused(err error) bool {
	var native *NativeError
	return errors.As(err, &native) && native.Code == int32(C.RTP2_ERR_ROUTE_REFUSED)
}

// RuntimeOptions configures a native runtime.
type RuntimeOptions struct {
	// StateDir holds this device's persistent identity (§7.2). Empty means an
	// ephemeral identity, unique to this process.
	//
	// The directory is created with mode 0700 if absent. A world- or
	// group-readable directory or identity record is refused, and a corrupt
	// record is an error rather than a reason to mint a new identity.
	StateDir string

	// KeyProtection selects the at-rest protection for the seed. Only
	// meaningful with StateDir: asking to protect an identity that is never
	// written is an error, not a no-op.
	//
	// Losing the keystore item makes an existing record unopenable. That is
	// an error and never a fresh identity: a new device id would break every
	// peer's trust-on-first-use pin.
	KeyProtection KeyProtection

	// KeystoreService and KeystoreAccount name the keystore item. Empty
	// selects "com.reyta.rtp2" and "device-identity". Two runtimes naming the
	// same pair share one wrapping key.
	KeystoreService string
	KeystoreAccount string

	// RoutePolicy restricts which paths transfers may use. The zero value is
	// RouteAny, which accepts anything and still reports the route.
	RoutePolicy RoutePolicy
}

// NewRuntime creates a runtime with an ephemeral device identity.
func NewRuntime() (*Runtime, error) {
	return NewRuntimeWithOptions(RuntimeOptions{})
}

// NewRuntimeWithOptions creates the native runtime, verifying ABI
// compatibility first.
func NewRuntimeWithOptions(opts RuntimeOptions) (*Runtime, error) {
	cfg := C.rtp2_runtime_config_t{
		abi_version:    C.RTP2_ABI_VERSION,
		struct_size:    C.uint32_t(unsafe.Sizeof(C.rtp2_runtime_config_t{})),
		json_config:    nil,
		key_protection: C.uint32_t(opts.KeyProtection),
		route_policy:   C.uint32_t(opts.RoutePolicy),
	}
	if opts.StateDir != "" {
		cStateDir := C.CString(opts.StateDir)
		defer C.free(unsafe.Pointer(cStateDir))
		cfg.state_dir_utf8 = cStateDir
	}
	if opts.KeystoreService != "" {
		cService := C.CString(opts.KeystoreService)
		defer C.free(unsafe.Pointer(cService))
		cfg.keystore_service_utf8 = cService
	}
	if opts.KeystoreAccount != "" {
		cAccount := C.CString(opts.KeystoreAccount)
		defer C.free(unsafe.Pointer(cAccount))
		cfg.keystore_account_utf8 = cAccount
	}

	var handle C.rtp2_handle_t
	if code := int32(C.rtp2_runtime_new(&cfg, &handle)); code != 0 {
		return nil, nativeError("rtp2_runtime_new", code, nil)
	}
	return &Runtime{handle: handle}, nil
}

// DeviceID returns this device's public 32-byte identifier (§7.2). With a
// StateDir it is stable across restarts.
func (r *Runtime) DeviceID() ([32]byte, error) {
	var out [32]byte
	if r == nil || r.handle == 0 {
		return out, errors.New("rtp2: runtime is closed")
	}
	code := int32(C.rtp2_device_id(r.handle, (*C.uint8_t)(unsafe.Pointer(&out[0]))))
	if code != 0 {
		return [32]byte{}, nativeError("rtp2_device_id", code, r)
	}
	return out, nil
}

func (r *Runtime) Close() error {
	if r == nil || r.handle == 0 {
		return nil
	}
	code := int32(C.rtp2_runtime_free(r.handle))
	r.handle = 0
	if code != 0 {
		return nativeError("rtp2_runtime_free", code, nil)
	}
	return nil
}

// KeyProtectionInfo reports what actually protects this device's seed at
// rest: "ephemeral", "plaintext", or "platform-keystore/<backend>".
//
// This is the observed posture, not the requested one. A build that must not
// run with a plaintext seed should assert on this.
func (r *Runtime) KeyProtectionInfo() (string, error) {
	if r == nil || r.handle == 0 {
		return "", errors.New("rtp2: runtime is closed")
	}
	var out C.rtp2_buffer_t
	if code := int32(C.rtp2_key_protection(r.handle, &out)); code != 0 {
		return "", nativeError("rtp2_key_protection", code, r)
	}
	defer C.rtp2_buffer_free(out)
	return string(goBytes(out)), nil
}

// KeystoreForget removes a wrapping key from the platform keystore. Empty
// strings select the default service and account.
//
// This retires a device: every record sealed under that key, including the
// device identity, becomes permanently unopenable. The bool reports whether
// there was anything to remove.
func KeystoreForget(service, account string) (bool, error) {
	var cService, cAccount *C.char
	if service != "" {
		cService = C.CString(service)
		defer C.free(unsafe.Pointer(cService))
	}
	if account != "" {
		cAccount = C.CString(account)
		defer C.free(unsafe.Pointer(cAccount))
	}
	var removed C.int32_t
	if code := int32(C.rtp2_keystore_forget(cService, cAccount, &removed)); code != 0 {
		return false, nativeError("rtp2_keystore_forget", code, nil)
	}
	return removed != 0, nil
}

// PollEvent returns the next event as RTP-CBOR, or nil when nothing arrived
// within timeout. A zero timeout polls without blocking.
//
// The queue is bounded. An application that stops polling loses events: the
// loss is reported as an EventsDropped event, but never stalls a transfer.
func (r *Runtime) PollEvent(timeoutMS uint32) ([]byte, error) {
	if r == nil || r.handle == 0 {
		return nil, errors.New("rtp2: runtime is closed")
	}
	var out C.rtp2_buffer_t
	code := int32(C.rtp2_poll_event(r.handle, C.uint32_t(timeoutMS), &out))
	if code == C.RTP2_ERR_TIMEOUT {
		return nil, nil
	}
	if code != 0 {
		return nil, nativeError("rtp2_poll_event", code, r)
	}
	defer C.rtp2_buffer_free(out)
	return goBytes(out), nil
}

// LastError returns the native description of the most recent failure.
func (r *Runtime) LastError() string {
	if r == nil || r.handle == 0 {
		return ""
	}
	var out C.rtp2_buffer_t
	if code := int32(C.rtp2_last_error(r.handle, &out)); code != 0 {
		return ""
	}
	defer C.rtp2_buffer_free(out)
	return string(goBytes(out))
}

func (r *Runtime) StartEndpoint() (*Endpoint, error) {
	if r == nil || r.handle == 0 {
		return nil, errors.New("rtp2: runtime is closed")
	}
	var handle C.rtp2_handle_t
	if code := int32(C.rtp2_endpoint_start(r.handle, &handle)); code != 0 {
		return nil, nativeError("rtp2_endpoint_start", code, r)
	}
	return &Endpoint{handle: handle, runtime: r}, nil
}

// AddressBlob returns the endpoint address as an opaque CBOR blob. Share it
// with the sending side and pass it unchanged to SendFile.
func (e *Endpoint) AddressBlob() ([]byte, error) {
	if e == nil || e.handle == 0 {
		return nil, errors.New("rtp2: endpoint is closed")
	}
	var out C.rtp2_buffer_t
	if code := int32(C.rtp2_endpoint_address(e.handle, &out)); code != 0 {
		return nil, nativeError("rtp2_endpoint_address", code, e.runtime)
	}
	defer C.rtp2_buffer_free(out)
	return goBytes(out), nil
}

// SendFile transfers path to the peer identified by addrBlob. It blocks until
// the receiver has verified every chunk and acknowledged the plaintext
// digest, then returns the native JSON transfer report.
func (e *Endpoint) SendFile(addrBlob []byte, path string) ([]byte, error) {
	if e == nil || e.handle == 0 {
		return nil, errors.New("rtp2: endpoint is closed")
	}
	if len(addrBlob) == 0 {
		return nil, errors.New("rtp2: empty address blob")
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	var out C.rtp2_buffer_t
	code := int32(C.rtp2_send_file(
		e.handle,
		(*C.uint8_t)(unsafe.Pointer(&addrBlob[0])),
		C.size_t(len(addrBlob)),
		cPath,
		&out,
	))
	if code != 0 {
		return nil, nativeError("rtp2_send_file", code, e.runtime)
	}
	defer C.rtp2_buffer_free(out)
	return goBytes(out), nil
}

// ReceiveFile waits up to timeoutMS for one inbound transfer and writes the
// verified plaintext to destPath, returning the native JSON transfer report.
func (e *Endpoint) ReceiveFile(destPath string, timeoutMS uint32) ([]byte, error) {
	return e.ReceiveFileResumable(destPath, timeoutMS, "")
}

// ReceiveFileResumable is ReceiveFile with resume state kept in statePath, so
// an interrupted transfer continues instead of starting over. An empty
// statePath disables resume.
//
// The state is used only when it describes exactly the object being offered;
// a different ciphertext root or chunk size means the bytes already on disk
// belong to something else and the transfer restarts. Losing progress is
// always safe, reusing a mismatched record never is.
func (e *Endpoint) ReceiveFileResumable(destPath string, timeoutMS uint32, statePath string) ([]byte, error) {
	if e == nil || e.handle == 0 {
		return nil, errors.New("rtp2: endpoint is closed")
	}
	cPath := C.CString(destPath)
	defer C.free(unsafe.Pointer(cPath))

	var cState *C.char
	if statePath != "" {
		cState = C.CString(statePath)
		defer C.free(unsafe.Pointer(cState))
	}

	var out C.rtp2_buffer_t
	code := int32(C.rtp2_receive_file_resumable(
		e.handle, cPath, C.uint32_t(timeoutMS), cState, &out))
	if code != 0 {
		return nil, nativeError("rtp2_receive_file", code, e.runtime)
	}
	defer C.rtp2_buffer_free(out)
	return goBytes(out), nil
}

// HashFile computes the streaming BLAKE3-256 digest of a file.
func HashFile(path string) ([32]byte, error) {
	var result [32]byte
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	code := int32(C.rtp2_blake3_hash_file(
		cPath,
		(*C.uint8_t)(unsafe.Pointer(&result[0])),
	))
	if code != 0 {
		return [32]byte{}, nativeError("rtp2_blake3_hash_file", code, nil)
	}
	return result, nil
}

func goBytes(buf C.rtp2_buffer_t) []byte {
	if buf.ptr == nil || buf.len == 0 {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(buf.ptr), C.int(buf.len))
}

func nativeError(op string, code int32, rt *Runtime) error {
	detail := ""
	if rt != nil {
		detail = rt.LastError()
	}
	return &NativeError{Op: op, Code: code, Detail: detail}
}
