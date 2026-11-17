package adminapi

import (
	"io"
	"net/netip"
	"strings"
)

func netipAP(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func stringsReader(s string) io.Reader { return strings.NewReader(s) }
