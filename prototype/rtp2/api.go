// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

package rtp2

// The package has two implementations, one over cgo and one that reports that
// cgo is off, and they must present the same surface. Nothing enforced that,
// so the no-cgo build only broke when a method was added to one of them and
// not the other.
//
// These assertions move that break to compile time in both configurations.
// Adding a method to the API means adding it here, which then fails whichever
// build has not caught up.

type runtimeAPI interface {
	DeviceID() ([32]byte, error)
	KeyProtectionInfo() (string, error)
	StartEndpoint() (*Endpoint, error)
	PollEvent(timeoutMS uint32) ([]byte, error)
	NextEvent(timeoutMS uint32) (*Event, error)
	LastError() string
	Close() error
}

type endpointAPI interface {
	AddressBlob() ([]byte, error)
	SendFile(addrBlob []byte, path string) ([]byte, error)
	ReceiveFile(destPath string, timeoutMS uint32) ([]byte, error)
	ReceiveFileResumable(destPath string, timeoutMS uint32, statePath string) ([]byte, error)
}

var (
	_ runtimeAPI  = (*Runtime)(nil)
	_ endpointAPI = (*Endpoint)(nil)
)
