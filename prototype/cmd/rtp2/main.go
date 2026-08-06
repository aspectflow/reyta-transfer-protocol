// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Command rtp2 moves a file between two devices over RTP/2.
//
// Usage:
//
//	rtp2 recv <dest>            wait for one transfer, print the address to dial
//	rtp2 send <addr> <file>     send a file to a printed address
//	rtp2 loop <src> <dest>      both sides in one process
//	rtp2 hash <file>            BLAKE3 of a file
//	rtp2 forget [account...]    retire a keystore-sealed identity
//
// Flags (before the mode):
//
//	-state <dir>    persist this device's identity across restarts
//	-keystore       seal the identity under the platform keystore
//	-route <p>      any | direct | loopback
//	-timeout <d>    how long recv waits for a peer
//	-resume <file>  keep resume state so an interrupted recv continues
//
// Any file works: the protocol is content-agnostic and chunks whatever it is
// given. Size is bounded only by disk.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aspectflow/reyta-transfer-protocol/prototype/rtp2"
)

var (
	stateDir = flag.String("state", "", "directory holding a persistent device identity")
	keystore = flag.Bool("keystore", false, "seal the identity under the platform keystore")
	route    = flag.String("route", "any", "acceptable network path: any, direct or loopback")
	timeout  = flag.Duration("timeout", 10*time.Minute, "how long recv waits for a peer")
	resume   = flag.String("resume", "", "keep resume state here so an interrupted recv continues")
	quiet    = flag.Bool("quiet", false, "suppress progress output")
)

func main() {
	log.SetFlags(0)
	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	switch args[0] {
	case "hash":
		needArgs(args, 2)
		digest, err := rtp2.HashFile(args[1])
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(hex.EncodeToString(digest[:]))

	case "recv":
		needArgs(args, 2)
		receive(args[1])

	case "send":
		needArgs(args, 3)
		send(args[1], args[2])

	case "loop":
		needArgs(args, 3)
		loopback(args[1], args[2])

	case "forget":
		forget(flag.Args()[1:])

	default:
		usage()
		os.Exit(2)
	}
}

// options builds the runtime configuration from the flags. A runtime with no
// state directory has an ephemeral identity that lasts one process.
//
// suffix separates the two identities that loop mode needs. Sharing one state
// directory would give both sides the same device id, and a peer cannot
// connect to itself.
func options(suffix string) rtp2.RuntimeOptions {
	dir := *stateDir
	if dir != "" && suffix != "" {
		dir = filepath.Join(dir, suffix)
	}
	opts := rtp2.RuntimeOptions{StateDir: dir}

	if *keystore {
		if *stateDir == "" {
			log.Fatal("-keystore needs -state: an identity that is never written cannot be sealed")
		}
		opts.KeyProtection = rtp2.KeyProtectionPlatformKeystore
		opts.KeystoreAccount = "device-seed" + suffix
	}

	switch *route {
	case "any":
		opts.RoutePolicy = rtp2.RouteAny
	case "direct":
		opts.RoutePolicy = rtp2.RouteDirectOnly
	case "loopback":
		opts.RoutePolicy = rtp2.RouteLoopbackOnly
	default:
		log.Fatalf("unknown -route %q: use any, direct or loopback", *route)
	}
	return opts
}

func start(suffix string) (*rtp2.Runtime, *rtp2.Endpoint) {
	runtime, err := rtp2.NewRuntimeWithOptions(options(suffix))
	if err != nil {
		log.Fatalf("runtime: %v", err)
	}

	id, err := runtime.DeviceID()
	if err != nil {
		log.Fatal(err)
	}
	protection, err := runtime.KeyProtectionInfo()
	if err != nil {
		log.Fatal(err)
	}
	if !*quiet {
		fmt.Fprintf(os.Stderr, "device   %x\n", id[:8])
		fmt.Fprintf(os.Stderr, "identity %s\n", protection)
	}

	endpoint, err := runtime.StartEndpoint()
	if err != nil {
		runtime.Close()
		log.Fatalf("endpoint: %v", err)
	}
	return runtime, endpoint
}

func receive(dest string) {
	runtime, endpoint := start("")
	defer runtime.Close()

	addr, err := endpoint.AddressBlob()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(addr))
	if !*quiet {
		fmt.Fprintln(os.Stderr, "waiting for a peer")
	}

	stop := watchEvents(runtime)
	raw, err := endpoint.ReceiveFileResumable(dest, uint32(timeout.Milliseconds()), *resume)
	close(stop)
	if err != nil {
		fail(err)
	}
	report(raw, dest)
}

func send(addrBase64, file string) {
	addr, err := base64.StdEncoding.DecodeString(strings.TrimSpace(addrBase64))
	if err != nil {
		log.Fatalf("address is not valid base64: %v", err)
	}

	runtime, endpoint := start("")
	defer runtime.Close()

	stop := watchEvents(runtime)
	raw, err := endpoint.SendFile(addr, file)
	close(stop)
	if err != nil {
		fail(err)
	}
	report(raw, file)
}

// loopback runs both roles in one process. Useful as a self-test and as the
// smallest complete example of the API. With -state the two identities are
// kept in separate subdirectories, since a device cannot connect to itself.
func loopback(src, dest string) {
	senderRT, sender := start("sender")
	defer senderRT.Close()
	receiverRT, receiver := start("receiver")
	defer receiverRT.Close()

	addr, err := receiver.AddressBlob()
	if err != nil {
		log.Fatal(err)
	}

	stop := watchEvents(receiverRT)
	done := make(chan error, 1)
	go func() {
		_, err := receiver.ReceiveFile(dest, uint32(timeout.Milliseconds()))
		done <- err
	}()

	raw, err := sender.SendFile(addr, src)
	if err != nil {
		close(stop)
		fail(err)
	}
	if err := <-done; err != nil {
		close(stop)
		fail(err)
	}
	close(stop)
	report(raw, src)
}

// forget retires a device by removing the wrapping key its identity is sealed
// under. Every record sealed with that key becomes unreadable, including the
// identity itself, so the device id changes on the next run and peers must
// trust it again.
func forget(accounts []string) {
	if len(accounts) == 0 {
		accounts = []string{"device-seed"}
	}
	for _, account := range accounts {
		removed, err := rtp2.KeystoreForget("", account)
		if err != nil {
			log.Fatalf("%s: %v", account, err)
		}
		if removed {
			fmt.Printf("removed %s\n", account)
			continue
		}
		fmt.Printf("nothing to remove for %s\n", account)
	}
}

// watchEvents prints transfer progress until the returned channel is closed.
//
// Events are polled rather than delivered by callback: the core never calls
// back into Go from an arbitrary thread. The queue is bounded, so a consumer
// that falls behind loses progress events but never slows the transfer.
func watchEvents(runtime *rtp2.Runtime) chan struct{} {
	stop := make(chan struct{})
	if *quiet {
		return stop
	}
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			e, err := runtime.NextEvent(200)
			if err != nil || e == nil {
				continue
			}
			if line := describeEvent(e); line != "" {
				fmt.Fprintf(os.Stderr, "\r%-70s", line)
			}
		}
	}()
	return stop
}

func describeEvent(e *rtp2.Event) string {
	switch e.Type {
	case rtp2.EventTransferStarted:
		return fmt.Sprintf("started, %s expected", humanBytes(e.TotalBytes))

	case rtp2.EventTransferProgress:
		verb := "verified"
		if e.Role == rtp2.RoleSending {
			verb = "sent"
		}
		done, _ := e.Progress()
		return fmt.Sprintf("%s %s of %s (%.0f%%)",
			verb, humanBytes(e.Bytes), humanBytes(e.TotalBytes), done*100)

	case rtp2.EventTransferRoute:
		return "route " + routeName(e)

	case rtp2.EventObjectCompleted:
		return "object complete, digest " + hex.EncodeToString(e.PlaintextDigest[:8])

	case rtp2.EventTransferCompleted:
		return fmt.Sprintf("transfer complete, %d object(s)", e.Objects)

	case rtp2.EventTransferFailed:
		return fmt.Sprintf("failed, protocol error 0x%04x", e.Code)

	case rtp2.EventTransferCancelled:
		return "cancelled"

	case rtp2.EventsDropped:
		return fmt.Sprintf("%d progress events dropped", e.Lost)
	}
	return ""
}

func routeName(e *rtp2.Event) string {
	switch e.Route {
	case rtp2.RouteRelay:
		return "relay"
	case rtp2.RouteUnknown:
		return "unknown"
	}
	switch e.AddressClass {
	case rtp2.AddressLoopback:
		return "direct, loopback"
	case rtp2.AddressPrivate:
		return "direct, local network"
	default:
		return "direct, public"
	}
}

func report(raw []byte, file string) {
	var r struct {
		Bytes           uint64 `json:"bytes"`
		Chunks          uint64 `json:"chunks"`
		PlaintextDigest string `json:"plaintext_digest"`
		CiphertextRoot  string `json:"ciphertext_root"`
		PeerDeviceID    string `json:"peer_device_id"`
		Route           string `json:"route"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		log.Fatalf("report is not valid JSON: %v", err)
	}
	if !*quiet {
		fmt.Fprintln(os.Stderr)
	}
	fmt.Printf("file       %s\n", filepath.Base(file))
	fmt.Printf("size       %s in %d chunks\n", humanBytes(r.Bytes), r.Chunks)
	fmt.Printf("digest     %s\n", r.PlaintextDigest)
	fmt.Printf("root       %s\n", r.CiphertextRoot)
	fmt.Printf("peer       %s\n", short(r.PeerDeviceID))
	fmt.Printf("route      %s\n", r.Route)
}

// fail separates a route-policy refusal from every other error, because the
// remedy is different: retrying will not help until the policy or the network
// changes.
func fail(err error) {
	if rtp2.IsRouteRefused(err) {
		log.Fatalf("refused: the path did not satisfy -route %s", *route)
	}
	log.Fatal(err)
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for n/div >= unit && exp < 3 {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}

func short(hexID string) string {
	if len(hexID) > 16 {
		return hexID[:16]
	}
	return hexID
}

func needArgs(args []string, n int) {
	if len(args) < n {
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `rtp2 moves a file between two devices over RTP/2.

  rtp2 [flags] recv <dest>          wait for one transfer
  rtp2 [flags] send <addr> <file>   send to a printed address
  rtp2 [flags] loop <src> <dest>    both sides in one process
  rtp2 hash <file>                  BLAKE3 of a file
  rtp2 forget [account...]          retire a keystore-sealed identity

Flags:
`)
	flag.PrintDefaults()
	fmt.Fprint(os.Stderr, `
Example, two terminals on different machines:

  machine A:  rtp2 -state ~/.rtp2 recv received.bin
  machine B:  rtp2 -state ~/.rtp2 send <address printed by A> video.mp4

Example, refusing anything that leaves the machine:

  rtp2 -route loopback loop big.iso copy.iso

Example, a large file over a link that drops. Re-run the same command after
an interruption and only the missing chunks move:

  rtp2 -resume archive.rtp2-resume recv archive.tar
`)
}
