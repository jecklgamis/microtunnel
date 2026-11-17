package config

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Prefix is an IPv4 network in host byte order, used for AllowedIPs routing.
type Prefix struct {
	Network uint32
	Mask    uint32
	Len     int
}

// ParseCIDR parses "a.b.c.d/len" (or a bare address, meaning /32). Host bits
// are masked off, so "10.9.0.5/24" yields network 10.9.0.0. Only IPv4 is
// supported.
func ParseCIDR(s string) (Prefix, error) {
	addrPart, lenPart, hasSlash := strings.Cut(s, "/")
	plen := 32
	if hasSlash {
		n, err := strconv.Atoi(lenPart)
		if err != nil || n < 0 || n > 32 {
			return Prefix{}, fmt.Errorf("invalid prefix length in %q", s)
		}
		plen = n
	}
	addr, err := netip.ParseAddr(addrPart)
	if err != nil || !addr.Is4() {
		return Prefix{}, fmt.Errorf("invalid IPv4 address in %q", s)
	}
	a4 := addr.As4()
	var mask uint32
	if plen > 0 {
		mask = ^uint32(0) << (32 - plen)
	}
	return Prefix{
		Network: binary.BigEndian.Uint32(a4[:]) & mask,
		Mask:    mask,
		Len:     plen,
	}, nil
}

// Contains reports whether ip (host byte order) falls inside the prefix.
func (p Prefix) Contains(ip uint32) bool { return ip&p.Mask == p.Network }

// String renders the prefix as "a.b.c.d/len".
func (p Prefix) String() string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], p.Network)
	return fmt.Sprintf("%s/%d", netip.AddrFrom4(b), p.Len)
}
