// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

// alice-bob is a runnable end-to-end demonstration of RTP/2.
//
// Alice sends a file to Bob over real Iroh QUIC. Every step of the normative
// protocol runs for real: the hybrid X25519 + ML-KEM-768 handshake with
// Ed25519 + ML-DSA-65 device authentication, a signed TransferOffer carrying
// public and private manifests, the file key delivered only inside a sealed
// envelope, and each chunk verified against the BLAKE3 Merkle root before Bob
// writes a single byte to disk.
//
//	go run ./examples/alice-bob                 # 3 MiB of random data
//	go run ./examples/alice-bob /path/to/file   # a file of your choosing
//
// Both parties run in this one process so the demo needs no second machine;
// they are nevertheless two independent runtimes with two independent device
// identities, talking over a real QUIC connection.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aspectflow/reyta-transfer-protocol/prototype/rtp2"
)

type transferReport struct {
	TransferID      string `json:"transfer_id"`
	ObjectID        string `json:"object_id"`
	CiphertextRoot  string `json:"ciphertext_root"`
	PlaintextDigest string `json:"plaintext_digest"`
	Bytes           uint64 `json:"bytes"`
	Chunks          uint64 `json:"chunks"`
	PeerDeviceID    string `json:"peer_device_id"`
	PeerEndpointID  string `json:"peer_endpoint_id"`
}

// party bundles one participant's runtime and endpoint.
type party struct {
	name     string
	runtime  *rtp2.Runtime
	endpoint *rtp2.Endpoint
}

func newParty(name string) (*party, error) {
	rt, err := rtp2.NewRuntime()
	if err != nil {
		return nil, fmt.Errorf("%s: create runtime: %w", name, err)
	}
	ep, err := rt.StartEndpoint()
	if err != nil {
		rt.Close()
		return nil, fmt.Errorf("%s: start endpoint: %w", name, err)
	}
	return &party{name: name, runtime: rt, endpoint: ep}, nil
}

func (p *party) close() {
	if p != nil && p.runtime != nil {
		p.runtime.Close()
	}
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "\n  FAILED: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	workDir, err := os.MkdirTemp("", "rtp2-alice-bob-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workDir)

	// ---- the file Alice wants to send -----------------------------------
	//
	// Large files are never loaded into memory: verification below compares
	// BLAKE3 digests and, for small files only, the raw bytes.
	const inMemoryLimit = 64 * 1024 * 1024

	var source string
	if len(os.Args) > 1 {
		source = os.Args[1]
	} else {
		source = filepath.Join(workDir, "alice-photo.bin")
		payload := make([]byte, 3*1024*1024)
		if _, err := rand.Read(payload); err != nil {
			return err
		}
		if err := os.WriteFile(source, payload, 0o600); err != nil {
			return err
		}
	}
	info, err := os.Stat(source)
	if err != nil {
		return fmt.Errorf("stat %s: %w", source, err)
	}
	sourceSize := uint64(info.Size())

	// An explicit destination is kept after the run, so the received file can
	// be checked with tools outside this program.
	destination := filepath.Join(workDir, "bob-received.bin")
	keepDestination := false
	if len(os.Args) > 2 {
		destination = os.Args[2]
		keepDestination = true
	}

	section("RTP/2: Alice sends a file to Bob")
	fmt.Printf("  file            %s\n", filepath.Base(source))
	fmt.Printf("  size            %s (%d bytes)\n", humanBytes(sourceSize), sourceSize)

	sourceDigest, err := rtp2.HashFile(source)
	if err != nil {
		return fmt.Errorf("hash source: %w", err)
	}
	fmt.Printf("  BLAKE3          %s\n", hex.EncodeToString(sourceDigest[:]))

	// ---- both parties come online ---------------------------------------
	section("1. Devices come online")

	alice, err := newParty("Alice")
	if err != nil {
		return err
	}
	defer alice.close()

	bob, err := newParty("Bob")
	if err != nil {
		return err
	}
	defer bob.close()

	// Each runtime generated its own Ed25519 + ML-DSA-65 device identity
	// inside the Rust core. Go never sees those private keys.
	bobAddress, err := bob.endpoint.AddressBlob()
	if err != nil {
		return fmt.Errorf("Bob: endpoint address: %w", err)
	}
	fmt.Printf("  Alice           runtime up, Iroh endpoint bound\n")
	fmt.Printf("  Bob             runtime up, Iroh endpoint bound\n")
	fmt.Printf("  Bob's address   %d-byte CBOR blob (shared with Alice out of band)\n",
		len(bobAddress))

	// ---- Bob waits, Alice sends -----------------------------------------
	section("2. Transfer")
	fmt.Printf("  Bob             waiting for an inbound transfer...\n")

	type result struct {
		report []byte
		err    error
	}
	bobDone := make(chan result, 1)
	go func() {
		report, err := bob.endpoint.ReceiveFile(destination, 120_000)
		bobDone <- result{report, err}
	}()

	// Give Bob's accept loop a moment so the log reads in order.
	time.Sleep(100 * time.Millisecond)
	fmt.Printf("  Alice           dialing Bob over QUIC (ALPN reyta-transfer/2)\n")

	start := time.Now()
	aliceReport, err := alice.endpoint.SendFile(bobAddress, source)
	if err != nil {
		return fmt.Errorf("Alice: send: %w", err)
	}

	var bobResult result
	select {
	case bobResult = <-bobDone:
	case <-time.After(150 * time.Second):
		return fmt.Errorf("Bob: receive timed out")
	}
	if bobResult.err != nil {
		return fmt.Errorf("Bob: receive: %w", bobResult.err)
	}
	elapsed := time.Since(start)

	fmt.Printf("  handshake       X25519 + ML-KEM-768, Ed25519 + ML-DSA-65 device signatures\n")
	fmt.Printf("  offer           signed TransferOffer: manifests + sealed key envelope\n")
	fmt.Printf("  chunks          XChaCha20-Poly1305, each with a BLAKE3 Merkle proof\n")
	fmt.Printf("  elapsed         %s\n", elapsed.Round(time.Millisecond))
	if secs := elapsed.Seconds(); secs > 0 {
		fmt.Printf("  throughput      %s/s\n", humanBytes(uint64(float64(sourceSize)/secs)))
	}

	// ---- what each side ended up believing ------------------------------
	var aliceRep, bobRep transferReport
	if err := json.Unmarshal(aliceReport, &aliceRep); err != nil {
		return fmt.Errorf("Alice: bad report: %w", err)
	}
	if err := json.Unmarshal(bobResult.report, &bobRep); err != nil {
		return fmt.Errorf("Bob: bad report: %w", err)
	}

	section("3. What Alice and Bob each ended up with")
	fmt.Printf("  transfer id     %s\n", short(aliceRep.TransferID))
	fmt.Printf("  object id       %s\n", short(aliceRep.ObjectID))
	fmt.Printf("  ciphertext root %s   (BLAKE3 Merkle)\n", short(aliceRep.CiphertextRoot))
	fmt.Printf("  chunks          %d of %s each\n", aliceRep.Chunks, humanBytes(256*1024))
	fmt.Printf("\n")
	fmt.Printf("  Alice sees Bob  device %s\n", short(aliceRep.PeerDeviceID))
	fmt.Printf("  Bob sees Alice  device %s\n", short(bobRep.PeerDeviceID))

	// ---- the checks that make this a successful transfer ----------------
	section("4. Verification")

	checks := []struct {
		name string
		ok   bool
		note string
	}{
		{
			"identities differ",
			aliceRep.PeerDeviceID != bobRep.PeerDeviceID,
			"each side authenticated the other device, not itself",
		},
		{
			"transfer id agrees",
			aliceRep.TransferID == bobRep.TransferID,
			"same transfer on both sides",
		},
		{
			"ciphertext root agrees",
			aliceRep.CiphertextRoot == bobRep.CiphertextRoot,
			"Bob verified every chunk against Alice's Merkle root",
		},
		{
			"plaintext digest agrees",
			aliceRep.PlaintextDigest == bobRep.PlaintextDigest,
			"BLAKE3 of the decrypted bytes matches Alice's signed claim",
		},
		{
			"byte count agrees",
			aliceRep.Bytes == sourceSize && bobRep.Bytes == sourceSize,
			fmt.Sprintf("%d bytes", sourceSize),
		},
	}

	type check = struct {
		name string
		ok   bool
		note string
	}

	destInfo, err := os.Stat(destination)
	if err != nil {
		return fmt.Errorf("stat received file: %w", err)
	}
	checks = append(checks, check{
		"file size on disk agrees",
		uint64(destInfo.Size()) == sourceSize,
		fmt.Sprintf("%s written", humanBytes(uint64(destInfo.Size()))),
	})

	localDigest, err := rtp2.HashFile(destination)
	if err != nil {
		return err
	}
	checks = append(checks, check{
		"independent hash agrees",
		hex.EncodeToString(localDigest[:]) == bobRep.PlaintextDigest &&
			localDigest == sourceDigest,
		"recomputed from both files on disk, outside the protocol",
	})

	if sourceSize <= inMemoryLimit {
		src, err := os.ReadFile(source)
		if err != nil {
			return err
		}
		dst, err := os.ReadFile(destination)
		if err != nil {
			return err
		}
		checks = append(checks, check{
			"file content identical",
			bytes.Equal(src, dst),
			"byte-for-byte comparison of source and destination",
		})
	}

	allOK := true
	for _, c := range checks {
		mark := "ok  "
		if !c.ok {
			mark = "FAIL"
			allOK = false
		}
		fmt.Printf("  [%s] %-24s %s\n", mark, c.name, c.note)
	}
	if !allOK {
		return fmt.Errorf("one or more verification checks failed")
	}

	// ---- what an eavesdropper would have seen ---------------------------
	section("5. What a relay or eavesdropper saw")
	fmt.Printf("  ciphertext only: the file key never left Alice's Rust core except\n")
	fmt.Printf("  inside the sealed envelope, which only Bob's session key opens.\n")
	fmt.Printf("  The reports above contain no key material by construction:\n")
	fmt.Printf("  %s\n", string(bobResult.report))

	section("Done")
	fmt.Printf("  %s transferred and verified in %s\n",
		humanBytes(sourceSize), elapsed.Round(time.Millisecond))
	if keepDestination {
		fmt.Printf("  received file kept at %s\n", destination)
		fmt.Printf("  check it yourself:  shasum -a 256 %q %q\n", source, destination)
	}
	return nil
}

func section(title string) {
	fmt.Printf("\n%s\n", title)
	fmt.Printf("%s\n", repeat('-', len(title)))
}

func repeat(c rune, n int) string {
	out := make([]rune, n)
	for i := range out {
		out[i] = c
	}
	return string(out)
}

func short(hexStr string) string {
	if len(hexStr) <= 16 {
		return hexStr
	}
	return hexStr[:16] + "..."
}

func humanBytes(n uint64) string {
	switch {
	case n >= 1024*1024:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1024*1024))
	case n >= 1024:
		return fmt.Sprintf("%.1f KiB", float64(n)/1024)
	default:
		return fmt.Sprintf("%d B", n)
	}
}
