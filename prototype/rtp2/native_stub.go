// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !cgo

package rtp2

import "errors"

var errCGODisabled = errors.New("rtp2: cgo is disabled; build the Rust core and enable cgo")

type Runtime struct{}
type Endpoint struct{}

type KeyProtection uint32

const (
	KeyProtectionPlaintext KeyProtection = iota
	KeyProtectionPlatformKeystore
	KeyProtectionHardwareKeystore
)

type RoutePolicy uint32

const (
	RouteAny RoutePolicy = iota
	RouteDirectOnly
	RouteLoopbackOnly
)

type NativeError struct {
	Op     string
	Code   int32
	Detail string
}

func (e *NativeError) Error() string { return e.Op }

func IsRouteRefused(err error) bool { return false }

type RuntimeOptions struct {
	StateDir        string
	KeyProtection   KeyProtection
	KeystoreService string
	KeystoreAccount string
	RoutePolicy     RoutePolicy
}

func NewRuntime() (*Runtime, error)                               { return nil, errCGODisabled }
func NewRuntimeWithOptions(opts RuntimeOptions) (*Runtime, error) { return nil, errCGODisabled }
func (r *Runtime) DeviceID() ([32]byte, error)                    { return [32]byte{}, errCGODisabled }
func (r *Runtime) Close() error                                   { return nil }
func (r *Runtime) LastError() string                              { return "" }
func (r *Runtime) KeyProtectionInfo() (string, error)             { return "", errCGODisabled }
func (r *Runtime) StartEndpoint() (*Endpoint, error)              { return nil, errCGODisabled }

func (r *Runtime) PollEvent(timeoutMS uint32) ([]byte, error) { return nil, errCGODisabled }

func (e *Endpoint) AddressBlob() ([]byte, error) { return nil, errCGODisabled }
func (e *Endpoint) SendFile(addrBlob []byte, path string) ([]byte, error) {
	return nil, errCGODisabled
}
func (e *Endpoint) ReceiveFile(destPath string, timeoutMS uint32) ([]byte, error) {
	return nil, errCGODisabled
}
func (e *Endpoint) ReceiveFileResumable(destPath string, timeoutMS uint32, statePath string) ([]byte, error) {
	return nil, errCGODisabled
}

func HashFile(path string) ([32]byte, error) { return [32]byte{}, errCGODisabled }

func KeystoreForget(service, account string) (bool, error) { return false, errCGODisabled }
