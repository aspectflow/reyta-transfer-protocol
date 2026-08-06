// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

package rtp2

import (
	"errors"
	"fmt"
)

// EventType identifies what an Event reports (§25.3.1).
type EventType uint64

const (
	EventTransferStarted   EventType = 1
	EventTransferProgress  EventType = 2
	EventObjectCompleted   EventType = 3
	EventTransferCompleted EventType = 4
	EventTransferFailed    EventType = 5
	EventTransferCancelled EventType = 6
	EventsDropped          EventType = 7
	EventTransferRoute     EventType = 8
)

func (t EventType) String() string {
	switch t {
	case EventTransferStarted:
		return "started"
	case EventTransferProgress:
		return "progress"
	case EventObjectCompleted:
		return "object-completed"
	case EventTransferCompleted:
		return "completed"
	case EventTransferFailed:
		return "failed"
	case EventTransferCancelled:
		return "cancelled"
	case EventsDropped:
		return "events-dropped"
	case EventTransferRoute:
		return "route"
	}
	return fmt.Sprintf("event(%d)", uint64(t))
}

// ProgressRole says which side measured a progress event. The two sides cannot
// count the same thing: a receiver counts bytes that passed proof and AEAD
// checking, a sender counts bytes written to the transport. Sending-role
// progress is not delivery confirmation; only EventTransferCompleted is.
type ProgressRole uint64

const (
	RoleReceiving ProgressRole = 0
	RoleSending   ProgressRole = 1
)

// RouteClass is the kind of network path a transfer used (§16.3.1).
type RouteClass uint64

const (
	RouteDirect  RouteClass = 0
	RouteRelay   RouteClass = 1
	RouteUnknown RouteClass = 2
)

// AddressClass says how far a direct path reached.
type AddressClass uint64

const (
	AddressLoopback AddressClass = 0
	AddressPrivate  AddressClass = 1
	AddressPublic   AddressClass = 2
)

// Event is one decoded entry from the native event queue. Which fields carry
// meaning depends on Type; the rest are zero.
type Event struct {
	Type       EventType
	TransferID [32]byte

	Objects    uint64
	Bytes      uint64
	TotalBytes uint64
	Chunks     uint64
	Total      uint64
	Role       ProgressRole

	ObjectID        [32]byte
	PlaintextDigest [32]byte

	Code uint64
	Lost uint64

	Route        RouteClass
	AddressClass AddressClass
	HasAddress   bool
}

// Progress returns the completed fraction in [0,1], and false when the event
// carries no progress.
func (e *Event) Progress() (float64, bool) {
	if e.Type != EventTransferProgress || e.TotalBytes == 0 {
		return 0, false
	}
	return float64(e.Bytes) / float64(e.TotalBytes), true
}

// Terminal reports whether the event ends a transfer.
func (e *Event) Terminal() bool {
	switch e.Type {
	case EventObjectCompleted, EventTransferCompleted, EventTransferFailed, EventTransferCancelled:
		return true
	}
	return false
}

// NextEvent waits up to timeoutMS for the next event and decodes it. It
// returns nil, nil when nothing arrived in time; a zero timeout polls without
// blocking.
//
// An application that stops calling this loses progress events, reported as
// EventsDropped, but never slows a transfer: the queue is bounded by design.
func (r *Runtime) NextEvent(timeoutMS uint32) (*Event, error) {
	raw, err := r.PollEvent(timeoutMS)
	if err != nil || raw == nil {
		return nil, err
	}
	return decodeEvent(raw)
}

var errMalformedEvent = errors.New("rtp2: malformed event encoding")

// decodeEvent reads the deterministic CBOR the core emits: a definite-length
// map with ascending small integer keys, holding only unsigned integers and
// byte strings.
func decodeEvent(raw []byte) (*Event, error) {
	d := &cborReader{buf: raw}
	pairs, err := d.mapHeader()
	if err != nil {
		return nil, err
	}

	e := &Event{}
	for i := uint64(0); i < pairs; i++ {
		key, err := d.uint()
		if err != nil {
			return nil, err
		}
		if err := assignField(e, key, d); err != nil {
			return nil, err
		}
	}
	if !d.done() {
		return nil, errMalformedEvent
	}
	return e, nil
}

func assignField(e *Event, key uint64, d *cborReader) error {
	// Key 0 is the type and always comes first, so the meaning of later keys
	// is known by the time they are read.
	if key == 0 {
		v, err := d.uint()
		if err != nil {
			return err
		}
		e.Type = EventType(v)
		return nil
	}
	if key == 1 && e.Type != EventsDropped {
		return d.bytes32(&e.TransferID)
	}

	switch e.Type {
	case EventTransferStarted:
		return assignUints(d, key, map[uint64]*uint64{2: &e.Objects, 3: &e.TotalBytes})

	case EventTransferProgress:
		switch key {
		case 6:
			v, err := d.uint()
			e.Role = ProgressRole(v)
			return err
		default:
			return assignUints(d, key, map[uint64]*uint64{
				2: &e.Bytes, 3: &e.TotalBytes, 4: &e.Chunks, 5: &e.Total,
			})
		}

	case EventObjectCompleted:
		switch key {
		case 2:
			return d.bytes32(&e.ObjectID)
		case 3:
			return d.bytes32(&e.PlaintextDigest)
		}

	case EventTransferCompleted:
		return assignUints(d, key, map[uint64]*uint64{2: &e.Objects})

	case EventTransferFailed:
		return assignUints(d, key, map[uint64]*uint64{2: &e.Code})

	case EventsDropped:
		return assignUints(d, key, map[uint64]*uint64{1: &e.Lost})

	case EventTransferRoute:
		switch key {
		case 2:
			v, err := d.uint()
			e.Route = RouteClass(v)
			return err
		case 3:
			v, err := d.uint()
			e.AddressClass = AddressClass(v)
			e.HasAddress = true
			return err
		}
	}
	return errMalformedEvent
}

func assignUints(d *cborReader, key uint64, into map[uint64]*uint64) error {
	target, ok := into[key]
	if !ok {
		return errMalformedEvent
	}
	v, err := d.uint()
	if err != nil {
		return err
	}
	*target = v
	return nil
}

// cborReader accepts only the subset the core emits. Anything else is an
// error rather than a best-effort interpretation.
type cborReader struct {
	buf []byte
	pos int
}

func (d *cborReader) done() bool { return d.pos == len(d.buf) }

func (d *cborReader) head() (major byte, arg uint64, err error) {
	if d.pos >= len(d.buf) {
		return 0, 0, errMalformedEvent
	}
	b := d.buf[d.pos]
	d.pos++
	major = b >> 5
	info := b & 0x1f

	var width int
	switch {
	case info < 24:
		return major, uint64(info), nil
	case info == 24:
		width = 1
	case info == 25:
		width = 2
	case info == 26:
		width = 4
	case info == 27:
		width = 8
	default:
		return 0, 0, errMalformedEvent
	}
	v, err := d.take(width)
	return major, v, err
}

func (d *cborReader) take(n int) (uint64, error) {
	if d.pos+n > len(d.buf) {
		return 0, errMalformedEvent
	}
	var v uint64
	for _, b := range d.buf[d.pos : d.pos+n] {
		v = v<<8 | uint64(b)
	}
	d.pos += n
	return v, nil
}

func (d *cborReader) mapHeader() (uint64, error) {
	major, arg, err := d.head()
	if err != nil {
		return 0, err
	}
	if major != 5 {
		return 0, errMalformedEvent
	}
	return arg, nil
}

func (d *cborReader) uint() (uint64, error) {
	major, arg, err := d.head()
	if err != nil {
		return 0, err
	}
	if major != 0 {
		return 0, errMalformedEvent
	}
	return arg, nil
}

func (d *cborReader) bytes32(out *[32]byte) error {
	major, arg, err := d.head()
	if err != nil {
		return err
	}
	if major != 2 || arg != 32 || d.pos+32 > len(d.buf) {
		return errMalformedEvent
	}
	copy(out[:], d.buf[d.pos:d.pos+32])
	d.pos += 32
	return nil
}
