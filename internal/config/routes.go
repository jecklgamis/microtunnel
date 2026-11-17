package config

import (
	"fmt"
	"net/netip"

	"github.com/jecklgamis/microtunnel/internal/proto"
)

// UnroutedWarnings lists peer allowed_ips that the OS will not send into the
// tunnel. allowed_ips only choose the peer and filter sources inside
// microtunnel; a kernel route is created only for the overlay subnet (from
// tunnel_address) and for tunnel_routes, and only at startup. A network behind
// a peer therefore needs a tunnel_routes entry as well.
//
// It reports nothing when tunnel_address is unset, because then the operator
// manages the interface and its routes (for example with
// microtunnel-create-tunnel.sh).
func (c *Config) UnroutedWarnings() []string {
	return UnroutedWarnings(c.TunnelAddress, c.TunnelRoutes, c.Peers)
}

// UnroutedWarnings is the function behind Config.UnroutedWarnings, usable with
// a peer list that was loaded later (a live reload) and the tunnel settings the
// process started with.
func UnroutedWarnings(addr netip.Prefix, routes []netip.Prefix, peers []Peer) []string {
	if !addr.IsValid() {
		return nil
	}
	routed := append([]netip.Prefix{addr.Masked()}, routes...)
	var w []string
	for _, p := range peers {
		for _, ip := range p.AllowedIPs {
			pfx, err := netip.ParsePrefix(ip.String())
			if err != nil || covered(pfx, routed) {
				continue
			}
			w = append(w, fmt.Sprintf("peer %s: allowed_ips %s is not routed through the tunnel, so the OS will not send that traffic here; add it to tunnel_routes and restart (allowed_ips never create kernel routes)", peerLabel(p), pfx))
		}
	}
	return w
}

func covered(p netip.Prefix, routed []netip.Prefix) bool {
	for _, r := range routed {
		if r.Bits() <= p.Bits() && r.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

func peerLabel(p Peer) string {
	if p.Name != "" {
		return fmt.Sprintf("%q", p.Name)
	}
	return proto.BytesToHex(p.PublicKey[:4]) + "..."
}
