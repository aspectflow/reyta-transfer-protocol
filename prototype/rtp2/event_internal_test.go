// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build cgo

package rtp2

import "testing"

// The decoder is deliberately strict: an event that does not match the
// canonical encoding is an error, never a partially filled struct. A lenient
// decoder would let a truncated progress event read as 0 bytes transferred,
// which an application would show as a stalled transfer that is in fact fine.

func TestDecodeEventProgress(t *testing.T) {
	raw := []byte{0xa7, 0x00, 0x02}
	raw = append(raw, 0x01, 0x58, 0x20)
	for i := 0; i < 32; i++ {
		raw = append(raw, byte(i))
	}
	raw = append(raw,
		0x02, 0x19, 0x04, 0x00, // bytes = 1024
		0x03, 0x19, 0x08, 0x00, // total bytes = 2048
		0x04, 0x01, // chunks = 1
		0x05, 0x02, // total chunks = 2
		0x06, 0x01, // role = sending
	)

	e, err := decodeEvent(raw)
	if err != nil {
		t.Fatalf("decodeEvent: %v", err)
	}
	if e.Type != EventTransferProgress {
		t.Errorf("Type = %v, want progress", e.Type)
	}
	if e.Bytes != 1024 || e.TotalBytes != 2048 {
		t.Errorf("bytes = %d/%d, want 1024/2048", e.Bytes, e.TotalBytes)
	}
	if e.Role != RoleSending {
		t.Error("role should be sending")
	}
	if e.TransferID[0] != 0 || e.TransferID[31] != 31 {
		t.Errorf("transfer id not read verbatim: %x", e.TransferID)
	}
	if done, ok := e.Progress(); !ok || done != 0.5 {
		t.Errorf("Progress() = %v, %v, want 0.5, true", done, ok)
	}
	if e.Terminal() {
		t.Error("progress is not terminal")
	}
}

func TestDecodeEventRoute(t *testing.T) {
	raw := []byte{0xa4, 0x00, 0x08, 0x01, 0x58, 0x20}
	raw = append(raw, make([]byte, 32)...)
	raw = append(raw, 0x02, 0x00, 0x03, 0x00)

	e, err := decodeEvent(raw)
	if err != nil {
		t.Fatalf("decodeEvent: %v", err)
	}
	if e.Route != RouteDirect || e.AddressClass != AddressLoopback || !e.HasAddress {
		t.Errorf("route = %d class = %d has = %v, want direct/loopback/true",
			e.Route, e.AddressClass, e.HasAddress)
	}
}

func TestDecodeEventDropped(t *testing.T) {
	// Key 1 is a transfer id everywhere except in a dropped-count event, where
	// it is a plain integer. Reading it as a byte string would misparse.
	e, err := decodeEvent([]byte{0xa2, 0x00, 0x07, 0x01, 0x18, 0x2a})
	if err != nil {
		t.Fatalf("decodeEvent: %v", err)
	}
	if e.Type != EventsDropped || e.Lost != 42 {
		t.Errorf("got type %v lost %d, want events-dropped 42", e.Type, e.Lost)
	}
}

func TestDecodeEventRejectsMalformed(t *testing.T) {
	valid := []byte{0xa2, 0x00, 0x05, 0x01, 0x58, 0x20}
	valid = append(valid, make([]byte, 32)...)
	valid = append(valid, 0x02, 0x00)
	valid[0] = 0xa3
	if _, err := decodeEvent(valid); err != nil {
		t.Fatalf("control vector should decode: %v", err)
	}

	cases := map[string][]byte{
		"empty":            {},
		"not a map":        {0x82, 0x00, 0x01},
		"indefinite map":   {0xbf, 0x00, 0x01, 0xff},
		"truncated header": {0xa2, 0x00},
		"trailing bytes":   append(append([]byte{}, valid...), 0x00),
		"short id":         {0xa2, 0x00, 0x02, 0x01, 0x43, 0x01, 0x02, 0x03},
		"unknown key":      {0xa2, 0x00, 0x04, 0x7f, 0x00},
		"text where uint":  {0xa2, 0x00, 0x07, 0x01, 0x61, 0x78},
	}
	for name, raw := range cases {
		if _, err := decodeEvent(raw); err == nil {
			t.Errorf("%s: decoded without error, want rejection", name)
		}
	}
}
