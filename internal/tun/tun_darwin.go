//go:build darwin

// Package tun opens TUN devices: /dev/net/tun on Linux, utun on macOS.
package tun

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	utunControlName = "com.apple.net.utun_control"
	sysprotoControl = 2 // SYSPROTO_CONTROL (not defined by x/sys/unix)
	utunOptIfName   = 2 // UTUN_OPT_IFNAME
	maxPacket       = 65535
)

// utun adapts a macOS utun socket to one-raw-IP-packet-per-Read/Write by
// stripping and adding the 4-byte address-family header.
type utun struct {
	f    *os.File
	pool sync.Pool
}

// Open creates a utun interface and returns it with its kernel-assigned name
// (utunN). name selects a specific "utunN"; any other value (including the
// Linux-style default names) lets the kernel pick the next free one. Creating
// utun devices requires root.
//
// The returned device is non-blocking and registered with Go's poller, so
// several goroutines may Read concurrently and Close unblocks them.
func Open(name string) (io.ReadWriteCloser, string, error) {
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		return nil, "", fmt.Errorf("unable to create utun control socket: %w", err)
	}
	fail := func(format string, a ...any) (io.ReadWriteCloser, string, error) {
		unix.Close(fd)
		return nil, "", fmt.Errorf(format, a...)
	}
	info := &unix.CtlInfo{}
	copy(info.Name[:], utunControlName)
	if err := unix.IoctlCtlInfo(fd, info); err != nil {
		return fail("unable to look up %s: %w", utunControlName, err)
	}
	if err := unix.Connect(fd, &unix.SockaddrCtl{ID: info.Id, Unit: utunUnit(name)}); err != nil {
		if err == unix.EPERM || err == unix.EACCES {
			return fail("unable to create utun device (macOS requires root, run with sudo): %w", err)
		}
		return fail("unable to create utun device %q: %w", name, err)
	}
	ifname, err := unix.GetsockoptString(fd, sysprotoControl, utunOptIfName)
	if err != nil {
		return fail("unable to read utun interface name: %w", err)
	}
	ifname = strings.TrimRight(ifname, "\x00")
	if err := unix.SetNonblock(fd, true); err != nil {
		return fail("unable to set %s non-blocking: %w", ifname, err)
	}
	unix.CloseOnExec(fd)

	u := &utun{f: os.NewFile(uintptr(fd), "utun")}
	u.pool.New = func() any { b := make([]byte, utunHeaderLen+maxPacket); return &b }
	return u, ifname, nil
}

func (u *utun) Read(p []byte) (int, error) {
	bp := u.pool.Get().(*[]byte)
	defer u.pool.Put(bp)
	buf := (*bp)[:utunHeaderLen+min(len(p), maxPacket)]
	n, err := u.f.Read(buf)
	if err != nil {
		return 0, err
	}
	if n <= utunHeaderLen {
		return 0, nil
	}
	return copy(p, buf[utunHeaderLen:n]), nil
}

func (u *utun) Write(p []byte) (int, error) {
	hdr, err := utunHeader(p)
	if err != nil {
		return 0, err
	}
	bp := u.pool.Get().(*[]byte)
	defer u.pool.Put(bp)
	if len(p) > maxPacket {
		return 0, unix.EMSGSIZE
	}
	buf := (*bp)[:utunHeaderLen+len(p)]
	copy(buf, hdr[:])
	copy(buf[utunHeaderLen:], p)
	if _, err := u.f.Write(buf); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (u *utun) Close() error { return u.f.Close() }
