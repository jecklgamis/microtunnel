//go:build !linux && !darwin

// Package tun opens TUN devices: /dev/net/tun on Linux, utun on macOS.
package tun

import (
	"errors"
	"io"
)

// Open is only implemented on Linux and macOS.
func Open(name string) (io.ReadWriteCloser, string, error) {
	return nil, "", errors.New("TUN devices are only supported on Linux and macOS")
}
