// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build cgo

package rtp2_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aspectflow/reyta-transfer-protocol/prototype/rtp2"
)

type report struct {
	TransferID      string `json:"transfer_id"`
	ObjectID        string `json:"object_id"`
	CiphertextRoot  string `json:"ciphertext_root"`
	PlaintextDigest string `json:"plaintext_digest"`
	Bytes           uint64 `json:"bytes"`
	Chunks          uint64 `json:"chunks"`
	PeerDeviceID    string `json:"peer_device_id"`
	PeerEndpointID  string `json:"peer_endpoint_id"`
	Route           string `json:"route"`
}

func parseReport(t *testing.T, raw []byte) report {
	t.Helper()
	var r report
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("report is not valid JSON: %v (%s)", err, raw)
	}
	return r
}

func newRuntime(t *testing.T) *rtp2.Runtime {
	t.Helper()
	rt, err := rtp2.NewRuntime()
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })
	return rt
}

func writeRandom(t *testing.T, path string, size int) []byte {
	t.Helper()
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return data
}

// TestABIHandshakeAndTransfer drives a complete transfer through the C ABI:
// two runtimes (two device identities), two Iroh endpoints, real QUIC.
func TestABIHandshakeAndTransfer(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.bin")
	dst := filepath.Join(dir, "dst.bin")
	// Multiple chunks plus a short tail (chunk size is 256 KiB).
	payload := writeRandom(t, src, 3*256*1024+7777)

	senderRT := newRuntime(t)
	receiverRT := newRuntime(t)

	sender, err := senderRT.StartEndpoint()
	if err != nil {
		t.Fatalf("sender endpoint: %v", err)
	}
	receiver, err := receiverRT.StartEndpoint()
	if err != nil {
		t.Fatalf("receiver endpoint: %v", err)
	}

	addr, err := receiver.AddressBlob()
	if err != nil {
		t.Fatalf("AddressBlob: %v", err)
	}
	if len(addr) == 0 {
		t.Fatal("empty address blob")
	}

	recvCh := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		raw, err := receiver.ReceiveFile(dst, 60_000)
		if err != nil {
			errCh <- err
			return
		}
		recvCh <- raw
	}()

	sendRaw, err := sender.SendFile(addr, src)
	if err != nil {
		t.Fatalf("SendFile: %v", err)
	}

	var recvRaw []byte
	select {
	case recvRaw = <-recvCh:
	case err := <-errCh:
		t.Fatalf("ReceiveFile: %v", err)
	case <-time.After(90 * time.Second):
		t.Fatal("receive timed out")
	}

	sendRep := parseReport(t, sendRaw)
	recvRep := parseReport(t, recvRaw)

	if sendRep.PlaintextDigest != recvRep.PlaintextDigest {
		t.Errorf("digest mismatch: send %s recv %s", sendRep.PlaintextDigest, recvRep.PlaintextDigest)
	}
	if sendRep.CiphertextRoot != recvRep.CiphertextRoot {
		t.Errorf("ciphertext root mismatch")
	}
	if sendRep.TransferID != recvRep.TransferID || sendRep.ObjectID != recvRep.ObjectID {
		t.Errorf("transfer/object id mismatch")
	}
	if sendRep.Bytes != uint64(len(payload)) || recvRep.Bytes != uint64(len(payload)) {
		t.Errorf("byte count mismatch: %d/%d want %d", sendRep.Bytes, recvRep.Bytes, len(payload))
	}
	if sendRep.Chunks != 4 {
		t.Errorf("chunks = %d, want 4", sendRep.Chunks)
	}

	// Each side authenticated the OTHER device, and they are different.
	if sendRep.PeerDeviceID == recvRep.PeerDeviceID {
		t.Error("both sides report the same peer device id")
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("received file differs from source (%d vs %d bytes)", len(got), len(payload))
	}

	// The report must independently agree with a locally computed digest.
	digest, err := rtp2.HashFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(digest[:]) != recvRep.PlaintextDigest {
		t.Errorf("report digest %s does not match local hash %x", recvRep.PlaintextDigest, digest)
	}
}

// TestNoKeyMaterialInReports is the ABI-level check for INV-10: nothing the
// application layer can observe may contain key material. The reports are the
// only data crossing the boundary, so they must carry public values only.
func TestNoKeyMaterialInReports(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.bin")
	dst := filepath.Join(dir, "dst.bin")
	writeRandom(t, src, 64*1024)

	senderRT := newRuntime(t)
	receiverRT := newRuntime(t)
	sender, err := senderRT.StartEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := receiverRT.StartEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	addr, err := receiver.AddressBlob()
	if err != nil {
		t.Fatal(err)
	}

	recvCh := make(chan []byte, 1)
	go func() {
		raw, err := receiver.ReceiveFile(dst, 60_000)
		if err != nil {
			recvCh <- nil
			return
		}
		recvCh <- raw
	}()
	sendRaw, err := sender.SendFile(addr, src)
	if err != nil {
		t.Fatal(err)
	}
	recvRaw := <-recvCh
	if recvRaw == nil {
		t.Fatal("receive failed")
	}

	// The report schema is closed: only these keys may appear. A future
	// change that leaks a key would have to add a field, and this fails.
	allowed := map[string]bool{
		"transfer_id": true, "object_id": true, "ciphertext_root": true,
		"plaintext_digest": true, "bytes": true, "chunks": true,
		"peer_device_id": true, "peer_endpoint_id": true,
		"chunks_transferred": true, "manifest_commitment": true,
		"route": true,
	}
	// `route` is the one field carrying words rather than hex, and its
	// vocabulary is closed (§16.3.1). It is checked against that set and then
	// removed before the substring scan below, so "direct/private" cannot mask
	// a real leak of the word "private" from another field, and a route value
	// outside the set still fails.
	routes := map[string]bool{
		"direct/loopback": true, "direct/private": true, "direct/public": true,
		"relay": true, "unknown": true,
	}
	for _, raw := range [][]byte{sendRaw, recvRaw} {
		var generic map[string]any
		if err := json.Unmarshal(raw, &generic); err != nil {
			t.Fatal(err)
		}
		for key := range generic {
			if !allowed[key] {
				t.Errorf("unexpected field %q in transfer report: %s", key, raw)
			}
		}
		route, _ := generic["route"].(string)
		if !routes[route] {
			t.Errorf("route %q is outside the closed §16.3.1 set: %s", route, raw)
		}
		delete(generic, "route")
		scrubbed, err := json.Marshal(generic)
		if err != nil {
			t.Fatal(err)
		}
		for _, suspicious := range []string{"key", "secret", "seed", "nonce", "private", "master"} {
			if bytes.Contains(bytes.ToLower(scrubbed), []byte(suspicious)) {
				t.Errorf("report mentions %q: %s", suspicious, scrubbed)
			}
		}
	}
}

// TestIdentityPersistsAcrossRuntimes is the ABI-level proof that §7.2 device
// identity survives a restart: two runtimes over the same state directory are
// the same device, and a different directory is a different device.
func TestIdentityPersistsAcrossRuntimes(t *testing.T) {
	dir := t.TempDir()
	stateA := filepath.Join(dir, "a")
	stateB := filepath.Join(dir, "b")

	first, err := rtp2.NewRuntimeWithOptions(rtp2.RuntimeOptions{StateDir: stateA})
	if err != nil {
		t.Fatalf("first runtime: %v", err)
	}
	idA1, err := first.DeviceID()
	if err != nil {
		t.Fatal(err)
	}
	if idA1 == ([32]byte{}) {
		t.Fatal("device id is all zeros")
	}
	first.Close()

	second, err := rtp2.NewRuntimeWithOptions(rtp2.RuntimeOptions{StateDir: stateA})
	if err != nil {
		t.Fatalf("second runtime: %v", err)
	}
	defer second.Close()
	idA2, err := second.DeviceID()
	if err != nil {
		t.Fatal(err)
	}
	if idA1 != idA2 {
		t.Errorf("identity changed across restart: %x -> %x", idA1, idA2)
	}

	other, err := rtp2.NewRuntimeWithOptions(rtp2.RuntimeOptions{StateDir: stateB})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	idB, err := other.DeviceID()
	if err != nil {
		t.Fatal(err)
	}
	if idA1 == idB {
		t.Error("two state directories produced the same device id")
	}
}

// TestEphemeralIdentityWhenNoStateDir pins the opposite: with no state
// directory each runtime is a fresh device.
func TestEphemeralIdentityWhenNoStateDir(t *testing.T) {
	a := newRuntime(t)
	b := newRuntime(t)
	idA, err := a.DeviceID()
	if err != nil {
		t.Fatal(err)
	}
	idB, err := b.DeviceID()
	if err != nil {
		t.Fatal(err)
	}
	if idA == idB {
		t.Error("two ephemeral runtimes share a device id")
	}
}

// keystoreCoordinates returns a service/account pair unique to this run, and
// removes the item afterwards.
//
// Uniqueness is not tidiness. A `go test` binary is unsigned, so the core
// falls back to the file-based login keychain, where an item's ACL trusts the
// binary that created it. Reusing a fixed name would mean the next build's
// binary reading an item created by the previous one, which raises a system
// authorization prompt and hangs the suite with no output. A fresh name per
// run, created and read by one binary and deleted in-process, never prompts.
// requireKeystore skips a test on a platform with no keystore backend. The
// absence is itself asserted, by TestKeystoreRefusesWhereItDoesNotExist, so
// skipping here does not leave the case unchecked: a build that silently
// downgraded to a plaintext seed would fail there rather than pass quietly.
func requireKeystore(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "darwin" {
		t.Skipf("no keystore backend on %s", runtime.GOOS)
	}
}

func keystoreCoordinates(t *testing.T, tag string) (string, string) {
	t.Helper()
	requireKeystore(t)
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	service := "com.reyta.rtp2.test." + tag + "." + hex.EncodeToString(suffix[:])
	account := "device-identity"
	t.Cleanup(func() {
		if _, err := rtp2.KeystoreForget(service, account); err != nil {
			t.Errorf("keystore cleanup: %v", err)
		}
	})
	return service, account
}

// TestKeystoreSealedIdentity is the ABI-level proof of §28.1: with the
// platform keystore selected, the seed is not in the record, the identity
// still survives a restart, and the runtime says so.
func TestKeystoreSealedIdentity(t *testing.T) {
	service, account := keystoreCoordinates(t, "sealed")
	state := filepath.Join(t.TempDir(), "state")
	opts := rtp2.RuntimeOptions{
		StateDir:        state,
		KeyProtection:   rtp2.KeyProtectionPlatformKeystore,
		KeystoreService: service,
		KeystoreAccount: account,
	}

	first, err := rtp2.NewRuntimeWithOptions(opts)
	if err != nil {
		t.Fatalf("keystore runtime: %v", err)
	}
	idFirst, err := first.DeviceID()
	if err != nil {
		t.Fatal(err)
	}
	info, err := first.KeyProtectionInfo()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(info, "platform-keystore/") {
		t.Errorf("key protection = %q, want a platform-keystore backend", info)
	}
	first.Close()

	// The same directory under the plaintext default must now be refused:
	// the record says PlatformKeystore, and a downgrade is not accepted just
	// because the caller asked for less.
	if rt, err := rtp2.NewRuntimeWithOptions(rtp2.RuntimeOptions{StateDir: state}); err == nil {
		rt.Close()
		t.Error("a keystore-sealed record was opened by a plaintext runtime")
	}

	second, err := rtp2.NewRuntimeWithOptions(opts)
	if err != nil {
		t.Fatalf("second keystore runtime: %v", err)
	}
	defer second.Close()
	idSecond, err := second.DeviceID()
	if err != nil {
		t.Fatal(err)
	}
	if idFirst != idSecond {
		t.Errorf("identity changed across restart: %x -> %x", idFirst, idSecond)
	}

	// The device id is derived from the seed, so finding it in the record
	// would mean the seed is there too.
	record, err := os.ReadFile(filepath.Join(state, "identity.rtp2"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(record, idFirst[:]) {
		t.Error("a keystore-sealed record contains seed-derived material")
	}
}

// TestKeystoreProtectedTransferOverRealQUIC is the one that matters: two
// devices whose identities exist only as keystore-sealed ciphertext on disk
// complete a real transfer over real QUIC, and are still the same two devices
// after a restart.
//
// Everything else in this file tests a property in isolation. This checks that
// turning the protection on did not break the thing the protection exists for.
func TestKeystoreProtectedTransferOverRealQUIC(t *testing.T) {
	senderSvc, account := keystoreCoordinates(t, "xfer-sender")
	receiverSvc, _ := keystoreCoordinates(t, "xfer-receiver")

	dir := t.TempDir()
	senderState := filepath.Join(dir, "sender")
	receiverState := filepath.Join(dir, "receiver")
	src := filepath.Join(dir, "src.bin")
	dst := filepath.Join(dir, "dst.bin")
	// Several chunks plus a short tail, so the Merkle tree is not a trivial
	// shape and the last chunk is partial.
	payload := writeRandom(t, src, 2*256*1024+4321)

	sealed := func(state, service string) rtp2.RuntimeOptions {
		return rtp2.RuntimeOptions{
			StateDir:        state,
			KeyProtection:   rtp2.KeyProtectionPlatformKeystore,
			KeystoreService: service,
			KeystoreAccount: account,
		}
	}

	senderRT, err := rtp2.NewRuntimeWithOptions(sealed(senderState, senderSvc))
	if err != nil {
		t.Fatalf("sender runtime: %v", err)
	}
	defer senderRT.Close()
	receiverRT, err := rtp2.NewRuntimeWithOptions(sealed(receiverState, receiverSvc))
	if err != nil {
		t.Fatalf("receiver runtime: %v", err)
	}
	defer receiverRT.Close()

	for name, rt := range map[string]*rtp2.Runtime{"sender": senderRT, "receiver": receiverRT} {
		info, err := rt.KeyProtectionInfo()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(info, "platform-keystore/") {
			t.Fatalf("%s is running unprotected: %q", name, info)
		}
	}

	senderID, err := senderRT.DeviceID()
	if err != nil {
		t.Fatal(err)
	}
	receiverID, err := receiverRT.DeviceID()
	if err != nil {
		t.Fatal(err)
	}
	if senderID == receiverID {
		t.Fatal("both sealed devices got the same identity")
	}

	sender, err := senderRT.StartEndpoint()
	if err != nil {
		t.Fatalf("sender endpoint: %v", err)
	}
	receiver, err := receiverRT.StartEndpoint()
	if err != nil {
		t.Fatalf("receiver endpoint: %v", err)
	}
	addr, err := receiver.AddressBlob()
	if err != nil {
		t.Fatal(err)
	}

	recvCh := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		raw, err := receiver.ReceiveFile(dst, 60_000)
		if err != nil {
			errCh <- err
			return
		}
		recvCh <- raw
	}()

	sendRaw, err := sender.SendFile(addr, src)
	if err != nil {
		t.Fatalf("SendFile: %v", err)
	}
	var recvRaw []byte
	select {
	case recvRaw = <-recvCh:
	case err := <-errCh:
		t.Fatalf("ReceiveFile: %v", err)
	case <-time.After(90 * time.Second):
		t.Fatal("receive timed out")
	}

	sendRep := parseReport(t, sendRaw)
	recvRep := parseReport(t, recvRaw)
	if sendRep.PlaintextDigest != recvRep.PlaintextDigest {
		t.Errorf("digest mismatch: %s vs %s", sendRep.PlaintextDigest, recvRep.PlaintextDigest)
	}
	if sendRep.CiphertextRoot != recvRep.CiphertextRoot {
		t.Error("ciphertext root mismatch")
	}

	// Each side authenticated the other device, and those are the same two
	// identities the keystore-sealed records hold.
	if !bytes.Equal(mustHex(t, sendRep.PeerDeviceID), receiverID[:]) {
		t.Error("sender did not authenticate the receiver's sealed identity")
	}
	if !bytes.Equal(mustHex(t, recvRep.PeerDeviceID), senderID[:]) {
		t.Error("receiver did not authenticate the sender's sealed identity")
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("received file differs (%d vs %d bytes)", len(got), len(payload))
	}
	digest, err := rtp2.HashFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(digest[:]) != recvRep.PlaintextDigest {
		t.Error("independently recomputed digest disagrees with the report")
	}

	// And the sealed identities survive a restart: neither device becomes a
	// stranger to its peers because the seed was encrypted.
	senderRT.Close()
	again, err := rtp2.NewRuntimeWithOptions(sealed(senderState, senderSvc))
	if err != nil {
		t.Fatalf("sealed identity did not reopen: %v", err)
	}
	defer again.Close()
	restarted, err := again.DeviceID()
	if err != nil {
		t.Fatal(err)
	}
	if restarted != senderID {
		t.Errorf("sealed identity changed across restart: %x -> %x", senderID, restarted)
	}

	// The record on disk must not carry the identity it protects.
	record, err := os.ReadFile(filepath.Join(senderState, "identity.rtp2"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(record, senderID[:]) {
		t.Error("the sealed record leaks seed-derived material")
	}
}

// TestEventsDuringRealTransfer drives the §25.3.1 queue through the C ABI on
// a live QUIC transfer: the application sees progress while bytes move, not
// only a result at the end.
func TestEventsDuringRealTransfer(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.bin")
	dst := filepath.Join(dir, "dst.bin")
	payload := writeRandom(t, src, 6*256*1024) // 6 chunks, so progress is visible

	senderRT := newRuntime(t)
	receiverRT := newRuntime(t)
	sender, err := senderRT.StartEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := receiverRT.StartEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	addr, err := receiver.AddressBlob()
	if err != nil {
		t.Fatal(err)
	}

	// Collect the receiver's events for the whole transfer.
	collected := make(chan []*rtp2.Event, 1)
	stop := make(chan struct{})
	go func() {
		var seen []*rtp2.Event
		drain := func(timeout uint32) bool {
			e, err := receiverRT.NextEvent(timeout)
			if err != nil {
				t.Errorf("NextEvent: %v", err)
				return false
			}
			if e == nil {
				return false
			}
			seen = append(seen, e)
			return true
		}
		for {
			select {
			case <-stop:
				// Drain whatever is still queued before reporting.
				for drain(0) {
				}
				collected <- seen
				return
			default:
				drain(100)
			}
		}
	}()

	recvDone := make(chan error, 1)
	go func() {
		_, err := receiver.ReceiveFile(dst, 60_000)
		recvDone <- err
	}()
	if _, err := sender.SendFile(addr, src); err != nil {
		t.Fatalf("SendFile: %v", err)
	}
	select {
	case err := <-recvDone:
		if err != nil {
			t.Fatalf("ReceiveFile: %v", err)
		}
	case <-time.After(90 * time.Second):
		t.Fatal("receive timed out")
	}
	close(stop)
	seen := <-collected

	var started, progress, objectDone, transferDone int
	var maxBytes uint64
	for _, e := range seen {
		switch e.Type {
		case rtp2.EventTransferStarted:
			started++
		case rtp2.EventTransferProgress:
			progress++
			if e.Role != rtp2.RoleReceiving {
				t.Errorf("receiver reported role %d, want receiving", e.Role)
			}
			if e.Bytes < maxBytes {
				t.Errorf("progress went backwards: %d after %d", e.Bytes, maxBytes)
			}
			maxBytes = e.Bytes
		case rtp2.EventObjectCompleted:
			objectDone++
		case rtp2.EventTransferCompleted:
			transferDone++
		case rtp2.EventTransferFailed:
			t.Error("a successful transfer reported failure")
		}
	}

	if started != 1 || objectDone != 1 || transferDone != 1 {
		t.Errorf("started=%d objectCompleted=%d transferCompleted=%d, want 1 each",
			started, objectDone, transferDone)
	}
	if progress == 0 {
		t.Error("no progress was reported; the application would only see a spinner")
	}
	// Verified progress must reach the whole object, and never exceed it.
	if maxBytes != uint64(len(payload)) {
		t.Errorf("final verified bytes = %d, want %d", maxBytes, len(payload))
	}
}

// TestRoutePolicyRefusesAndReports is the A1 property: the route a transfer
// actually took is visible, and a policy that excludes it is enforced rather
// than advisory.
//
// This is the defect that made it necessary: two endpoints in one process were
// measured moving 64 MiB at ~5 MiB/s because iroh does not advertise
// 127.0.0.1, so their traffic left the machine over a VPN. Nothing reported
// that. A transfer the user believes is local could traverse a tunnel, the LAN,
// or a third party's relay, unobservably.
func TestRoutePolicyRefusesAndReports(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.bin")
	dst := filepath.Join(dir, "dst.bin")
	writeRandom(t, src, 128*1024)

	// Under RouteAny the transfer succeeds and the report names the path.
	sendRep, recvRep := routeTransfer(t, rtp2.RouteAny, src, dst, false)
	if sendRep.Route == "" || recvRep.Route == "" {
		t.Fatal("the report must name the route the bytes took")
	}
	if sendRep.Route != recvRep.Route {
		t.Errorf("the two sides disagree on the route: %q vs %q", sendRep.Route, recvRep.Route)
	}
	t.Logf("observed route under RouteAny: %s", sendRep.Route)

	// LoopbackOnly has two acceptable outcomes and one forbidden one. It may
	// succeed, in which case the route must be loopback; or it may refuse,
	// distinguishably. What it must never do is complete over a path that
	// leaves the machine, which is the whole point of the policy.
	//
	// Note that the RouteAny run above commonly reports direct/private: the
	// policy is what pins the socket to loopback, so an unrestricted endpoint
	// takes the LAN address instead.
	loopSend, loopRecv, err := routeTransferErr(t, rtp2.RouteLoopbackOnly, src, filepath.Join(dir, "dst2.bin"))
	if err != nil {
		if !rtp2.IsRouteRefused(err) {
			t.Errorf("a policy refusal must be distinguishable from a transport or crypto failure, got %v", err)
		}
		return
	}
	if loopSend.Route != "direct/loopback" || loopRecv.Route != "direct/loopback" {
		t.Errorf("RouteLoopbackOnly completed over %q/%q, which left the machine",
			loopSend.Route, loopRecv.Route)
	}
}

func routeTransferErr(t *testing.T, policy rtp2.RoutePolicy, src, dst string) (report, report, error) {
	t.Helper()
	senderRT, err := rtp2.NewRuntimeWithOptions(rtp2.RuntimeOptions{RoutePolicy: policy})
	if err != nil {
		t.Fatal(err)
	}
	defer senderRT.Close()
	receiverRT, err := rtp2.NewRuntimeWithOptions(rtp2.RuntimeOptions{RoutePolicy: policy})
	if err != nil {
		t.Fatal(err)
	}
	defer receiverRT.Close()

	sender, err := senderRT.StartEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := receiverRT.StartEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	addr, err := receiver.AddressBlob()
	if err != nil {
		t.Fatal(err)
	}

	recvCh := make(chan []byte, 1)
	recvErr := make(chan error, 1)
	go func() {
		raw, err := receiver.ReceiveFile(dst, 30_000)
		if err != nil {
			recvErr <- err
			return
		}
		recvCh <- raw
	}()

	sendRaw, sendErr := sender.SendFile(addr, src)
	if sendErr != nil {
		// Drain the receiver so it does not outlive the test.
		select {
		case <-recvCh:
		case <-recvErr:
		case <-time.After(35 * time.Second):
		}
		return report{}, report{}, sendErr
	}
	select {
	case raw := <-recvCh:
		return parseReport(t, sendRaw), parseReport(t, raw), nil
	case err := <-recvErr:
		return report{}, report{}, err
	case <-time.After(60 * time.Second):
		t.Fatal("receive timed out")
		return report{}, report{}, nil
	}
}

func routeTransfer(t *testing.T, policy rtp2.RoutePolicy, src, dst string, wantErr bool) (report, report) {
	t.Helper()
	sendRep, recvRep, err := routeTransferErr(t, policy, src, dst)
	if err != nil && !wantErr {
		t.Fatalf("transfer under policy %d: %v", policy, err)
	}
	return sendRep, recvRep
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// TestPlaintextProtectionIsReportedAsSuch pins the default posture, so a
// build that must not ship with a plaintext seed has something to assert on.
func TestPlaintextProtectionIsReportedAsSuch(t *testing.T) {
	rt, err := rtp2.NewRuntimeWithOptions(rtp2.RuntimeOptions{
		StateDir: filepath.Join(t.TempDir(), "state"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	if info, err := rt.KeyProtectionInfo(); err != nil || info != "plaintext" {
		t.Errorf("key protection = %q, %v; want \"plaintext\"", info, err)
	}

	ephemeral := newRuntime(t)
	if info, err := ephemeral.KeyProtectionInfo(); err != nil || info != "ephemeral" {
		t.Errorf("key protection = %q, %v; want \"ephemeral\"", info, err)
	}
}

// TestKeystoreWithoutStateDirIsRejected: protecting an identity that is never
// written is a config error, not a silently ignored option. A caller asking
// for it believes it is getting a durable, sealed device.
func TestKeystoreWithoutStateDirIsRejected(t *testing.T) {
	rt, err := rtp2.NewRuntimeWithOptions(rtp2.RuntimeOptions{
		KeyProtection: rtp2.KeyProtectionPlatformKeystore,
	})
	if err == nil {
		rt.Close()
		t.Fatal("keystore protection was accepted for an ephemeral identity")
	}
}

// TestForgettingTheKeyMakesTheIdentityUnreadable pins the recovery story: a
// lost wrapping key is an error, never a silently regenerated device id.
func TestForgettingTheKeyMakesTheIdentityUnreadable(t *testing.T) {
	service, account := keystoreCoordinates(t, "forget")
	state := filepath.Join(t.TempDir(), "state")
	opts := rtp2.RuntimeOptions{
		StateDir:        state,
		KeyProtection:   rtp2.KeyProtectionPlatformKeystore,
		KeystoreService: service,
		KeystoreAccount: account,
	}

	rt, err := rtp2.NewRuntimeWithOptions(opts)
	if err != nil {
		t.Fatal(err)
	}
	rt.Close()
	before, err := os.ReadFile(filepath.Join(state, "identity.rtp2"))
	if err != nil {
		t.Fatal(err)
	}

	removed, err := rtp2.KeystoreForget(service, account)
	if err != nil {
		t.Fatal(err)
	}
	if !removed {
		t.Fatal("there was no key to forget")
	}
	if again, err := rtp2.KeystoreForget(service, account); err != nil || again {
		t.Errorf("second forget = %v, %v; want false, nil", again, err)
	}

	if rt, err := rtp2.NewRuntimeWithOptions(opts); err == nil {
		rt.Close()
		t.Fatal("the identity opened without its wrapping key")
	}
	after, err := os.ReadFile(filepath.Join(state, "identity.rtp2"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("an unopenable identity record was overwritten instead of refused")
	}
}

// TestStateDirPermissions checks the store's own hardening: 0700 directory,
// 0600 record.
func TestStateDirPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	rt, err := rtp2.NewRuntimeWithOptions(rtp2.RuntimeOptions{StateDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("state dir mode = %o, want 700", perm)
	}
	recInfo, err := os.Stat(filepath.Join(dir, "identity.rtp2"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := recInfo.Mode().Perm(); perm != 0o600 {
		t.Errorf("identity record mode = %o, want 600", perm)
	}
}

// TestBadStateDirFails ensures a regular file passed as StateDir is an error,
// not a panic across the ABI, and does not poison later use.
func TestBadStateDirFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(path, []byte("regular file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if rt, err := rtp2.NewRuntimeWithOptions(rtp2.RuntimeOptions{StateDir: path}); err == nil {
		rt.Close()
		t.Fatal("a regular file was accepted as a state directory")
	}

	// The ABI is still usable afterwards.
	rt := newRuntime(t)
	if _, err := rt.DeviceID(); err != nil {
		t.Fatalf("runtime unusable after a failed one: %v", err)
	}
}

// TestSendToBogusAddressFails ensures a malformed address blob is rejected
// cleanly (no panic across the ABI, no hang).
func TestSendToBogusAddressFails(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.bin")
	writeRandom(t, src, 1024)

	rt := newRuntime(t)
	ep, err := rt.StartEndpoint()
	if err != nil {
		t.Fatal(err)
	}

	for _, blob := range [][]byte{
		{0x00},
		{0xff, 0xff, 0xff},
		[]byte("not cbor at all"),
	} {
		if _, err := ep.SendFile(blob, src); err == nil {
			t.Errorf("SendFile accepted bogus address %x", blob)
		}
	}
	if _, err := ep.SendFile(nil, src); err == nil {
		t.Error("SendFile accepted nil address")
	}
}

// TestReceiveTimeout verifies the accept timeout is honored rather than
// blocking forever.
func TestReceiveTimeout(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "never.bin")

	rt := newRuntime(t)
	ep, err := rt.StartEndpoint()
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	if _, err := ep.ReceiveFile(dst, 1500); err == nil {
		t.Fatal("ReceiveFile returned success with no sender")
	}
	elapsed := time.Since(start)
	if elapsed > 20*time.Second {
		t.Errorf("timeout not honored: waited %v", elapsed)
	}
}

// TestHashFileMatchesKnownVector pins the BLAKE3 empty-input vector through
// the ABI.
func TestHashFileMatchesKnownVector(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.bin")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	digest, err := rtp2.HashFile(empty)
	if err != nil {
		t.Fatal(err)
	}
	const want = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
	if got := hex.EncodeToString(digest[:]); got != want {
		t.Errorf("BLAKE3(empty) = %s, want %s", got, want)
	}

	if _, err := rtp2.HashFile(filepath.Join(dir, "does-not-exist")); err == nil {
		t.Error("HashFile succeeded on a missing file")
	}
}

// TestHandleLifecycle checks the ABI's handle rules: closing a runtime
// invalidates it, double close is safe, and operations on a closed runtime
// fail rather than crash.
func TestHandleLifecycle(t *testing.T) {
	rt, err := rtp2.NewRuntime()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.StartEndpoint(); err != nil {
		t.Fatal(err)
	}
	if err := rt.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := rt.Close(); err != nil {
		t.Fatalf("second Close must be a no-op, got: %v", err)
	}
	if _, err := rt.StartEndpoint(); err == nil {
		t.Error("StartEndpoint succeeded on a closed runtime")
	}
	if msg := rt.LastError(); msg != "" {
		t.Errorf("LastError on closed runtime = %q, want empty", msg)
	}
}

// TestEmptyAndTinyFiles covers the chunk-count edge cases end to end.
func TestEmptyAndTinyFiles(t *testing.T) {
	for _, size := range []int{0, 1, 256 * 1024, 256*1024 + 1} {
		dir := t.TempDir()
		src := filepath.Join(dir, "src.bin")
		dst := filepath.Join(dir, "dst.bin")
		payload := writeRandom(t, src, size)

		senderRT := newRuntime(t)
		receiverRT := newRuntime(t)
		sender, err := senderRT.StartEndpoint()
		if err != nil {
			t.Fatal(err)
		}
		receiver, err := receiverRT.StartEndpoint()
		if err != nil {
			t.Fatal(err)
		}
		addr, err := receiver.AddressBlob()
		if err != nil {
			t.Fatal(err)
		}

		done := make(chan error, 1)
		go func() {
			_, err := receiver.ReceiveFile(dst, 60_000)
			done <- err
		}()
		if _, err := sender.SendFile(addr, src); err != nil {
			t.Fatalf("size %d: SendFile: %v", size, err)
		}
		if err := <-done; err != nil {
			t.Fatalf("size %d: ReceiveFile: %v", size, err)
		}

		got, err := os.ReadFile(dst)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("size %d: content mismatch", size)
		}
	}
}

// TestResumeStateCrossesTheABI pins the wiring for §18 resume.
//
// The core has kept per-object resume state since the first prototype, but the
// C entry point never passed the path through, so no application could reach
// it: a feature that existed and was tested in Rust yet was unreachable from
// every binding.
//
// A completed transfer deletes its state, which is what makes the deletion a
// usable probe. The test plants a file where the state belongs: the core must
// claim that path and remove it on success, and must not touch it when no
// state path was given.
func TestResumeStateCrossesTheABI(t *testing.T) {
	for _, tc := range []struct {
		name          string
		useState      bool
		wantRemaining bool
	}{
		{"with state path", true, false},
		{"without state path", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			src := filepath.Join(dir, "src.bin")
			dst := filepath.Join(dir, "dst.bin")
			state := filepath.Join(dir, "dst.rtp2-resume")
			payload := writeRandom(t, src, 3*256*1024+512)
			if err := os.WriteFile(state, []byte("stale"), 0o600); err != nil {
				t.Fatal(err)
			}

			senderRT := newRuntime(t)
			receiverRT := newRuntime(t)
			sender, err := senderRT.StartEndpoint()
			if err != nil {
				t.Fatal(err)
			}
			receiver, err := receiverRT.StartEndpoint()
			if err != nil {
				t.Fatal(err)
			}
			addr, err := receiver.AddressBlob()
			if err != nil {
				t.Fatal(err)
			}

			done := make(chan error, 1)
			go func() {
				if tc.useState {
					_, err := receiver.ReceiveFileResumable(dst, 60_000, state)
					done <- err
					return
				}
				_, err := receiver.ReceiveFile(dst, 60_000)
				done <- err
			}()
			if _, err := sender.SendFile(addr, src); err != nil {
				t.Fatalf("SendFile: %v", err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("receive: %v", err)
				}
			case <-time.After(90 * time.Second):
				t.Fatal("receive timed out")
			}

			got, err := os.ReadFile(dst)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Error("receive did not reproduce the file")
			}

			// A stale record names a different object, so it must be discarded
			// rather than trusted: the transfer succeeds either way.
			_, err = os.Stat(state)
			if tc.wantRemaining && err != nil {
				t.Error("a receive with no state path touched the file anyway")
			}
			if !tc.wantRemaining && err == nil {
				t.Error("the state path never reached the core: the stale record survived")
			}
		})
	}
}

// TestKeystoreRefusesWhereItDoesNotExist is the counterpart to the macOS
// keystore tests: on a platform with no backend, asking for keystore
// protection must fail. The failure is the feature. Handing back a working
// runtime whose seed sits on disk in the clear, while the caller believes it
// asked for a keystore, is the one outcome the ordered protection levels
// exist to rule out.
func TestKeystoreRefusesWhereItDoesNotExist(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("macOS has a keystore backend; the refusal path is not reachable")
	}
	rt, err := rtp2.NewRuntimeWithOptions(rtp2.RuntimeOptions{
		StateDir:      filepath.Join(t.TempDir(), "state"),
		KeyProtection: rtp2.KeyProtectionPlatformKeystore,
	})
	if err == nil {
		info, _ := rt.KeyProtectionInfo()
		rt.Close()
		t.Fatalf("keystore protection was granted without a backend, reporting %q", info)
	}
}
