package tun

import (
	"errors"
	"strconv"
	"strings"
)

// macOS utun devices prefix every packet with a 4-byte, big-endian address
// family. The helpers below are platform-neutral so they can be unit-tested
// anywhere; only tun_darwin.go uses them at runtime.
const (
	utunHeaderLen = 4
	utunAFInet    = 2  // AF_INET on macOS
	utunAFInet6   = 30 // AF_INET6 on macOS
)

var errNotIP = errors.New("tun: packet is neither IPv4 nor IPv6")

// utunHeader returns the 4-byte address-family header for pkt, chosen from the
// IP version nibble.
func utunHeader(pkt []byte) ([utunHeaderLen]byte, error) {
	var h [utunHeaderLen]byte
	if len(pkt) == 0 {
		return h, errNotIP
	}
	switch pkt[0] >> 4 {
	case 4:
		h[3] = utunAFInet
	case 6:
		h[3] = utunAFInet6
	default:
		return h, errNotIP
	}
	return h, nil
}

// utunUnit maps an interface name to the kernel-control unit to request:
// "utunN" selects exactly that interface (unit N+1); anything else ("utun",
// "", or a Linux-style name such as "microtunnel0") lets the kernel pick the
// next free one (unit 0).
func utunUnit(name string) uint32 {
	n, ok := strings.CutPrefix(name, "utun")
	if !ok || n == "" {
		return 0
	}
	i, err := strconv.ParseUint(n, 10, 31)
	if err != nil {
		return 0
	}
	return uint32(i) + 1
}
