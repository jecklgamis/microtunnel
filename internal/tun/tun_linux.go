//go:build linux

// Package tun opens TUN devices: /dev/net/tun on Linux, utun on macOS.
package tun

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const devPath = "/dev/net/tun"

// Open attaches to (or creates) the TUN interface called name in IFF_TUN |
// IFF_NO_PI mode: each Read returns exactly one raw IP packet and each Write
// injects exactly one. It returns the device and the interface name the
// kernel actually assigned.
//
// The returned *os.File is non-blocking and registered with Go's poller, so
// any number of goroutines may Read from it concurrently (the kernel hands
// each packet to exactly one reader) and Close unblocks them all.
func Open(name string) (io.ReadWriteCloser, string, error) {
	fd, err := unix.Open(devPath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", fmt.Errorf("unable to open tunnel %s: %w", devPath, err)
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(fd)
		return nil, "", fmt.Errorf("invalid interface name %q: %w", name, err)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		return nil, "", fmt.Errorf("unable to issue TUNSETIFF for %s: %w", name, err)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, "", fmt.Errorf("unable to set %s non-blocking: %w", name, err)
	}
	return os.NewFile(uintptr(fd), devPath), ifr.Name(), nil
}
