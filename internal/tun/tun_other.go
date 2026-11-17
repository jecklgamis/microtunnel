//go:build !linux

// Package tun opens Linux TUN devices.
package tun

import (
	"errors"
	"os"
)

// Open is only implemented on Linux (it needs /dev/net/tun).
func Open(name string) (*os.File, string, error) {
	return nil, "", errors.New("TUN devices are only supported on Linux (use Docker on other platforms)")
}
