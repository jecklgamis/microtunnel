package tun

import (
	"fmt"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"

	"github.com/jecklgamis/microtunnel/internal/logx"
)

// tunMTU is the inner MTU used on macOS: Ethernet - outer IPv4 - UDP - tunnel
// overhead (see proto.TunMTU). Linux keeps the kernel default, as before.
const tunMTU = 1428

// Command is one external command used to configure the interface. Optional
// commands (route additions, which fail harmlessly when the route already
// exists) only warn on failure.
type Command struct {
	Args     []string
	Optional bool
}

func (c Command) String() string { return strings.Join(c.Args, " ") }

// Commands returns the commands that bring up interface name with overlay
// address addr (e.g. 10.9.0.2/24) and route routes through it, for the given
// GOOS ("linux" or "darwin"). It is pure so it can be tested on any platform.
func Commands(goos, name string, addr netip.Prefix, routes []netip.Prefix) ([]Command, error) {
	if !addr.IsValid() || !addr.Addr().Is4() {
		return nil, fmt.Errorf("tunnel_address %v must be a valid IPv4 CIDR", addr)
	}
	for _, r := range routes {
		if !r.IsValid() || !r.Addr().Is4() {
			return nil, fmt.Errorf("tunnel route %v must be a valid IPv4 CIDR", r)
		}
	}
	var cmds []Command
	switch goos {
	case "linux":
		cmds = append(cmds,
			Command{Args: []string{"ip", "link", "set", "dev", name, "up"}},
			Command{Args: []string{"ip", "addr", "add", addr.String(), "dev", name}},
		)
		for _, r := range routes {
			cmds = append(cmds, Command{Args: []string{"ip", "route", "add", r.Masked().String(), "dev", name}, Optional: true})
		}
	case "darwin":
		ip := addr.Addr().String()
		mask := netip.AddrFrom4(prefixMask(addr.Bits())).String()
		// utun is point-to-point: local and peer address are both our overlay IP,
		// and the subnet is routed explicitly below.
		cmds = append(cmds, Command{Args: []string{"ifconfig", name, "inet", ip, ip, "netmask", mask, "mtu", fmt.Sprint(tunMTU), "up"}})
		seen := map[netip.Prefix]bool{}
		for _, r := range append([]netip.Prefix{addr}, routes...) {
			r = r.Masked()
			if seen[r] || r.Bits() == 32 && r.Addr() == addr.Addr() {
				continue // own address is already reachable via the interface
			}
			seen[r] = true
			cmds = append(cmds, Command{Args: []string{"route", "-q", "-n", "add", "-inet", "-net", r.String(), "-interface", name}, Optional: true})
		}
	default:
		return nil, fmt.Errorf("interface configuration is not supported on %s", goos)
	}
	return cmds, nil
}

func prefixMask(bits int) [4]byte {
	var m uint32
	if bits > 0 {
		m = ^uint32(0) << (32 - bits)
	}
	return [4]byte{byte(m >> 24), byte(m >> 16), byte(m >> 8), byte(m)}
}

// Configure assigns addr to the (already open) interface name, brings it up and
// adds routes. It needs the same privileges that opening the device did.
func Configure(name string, addr netip.Prefix, routes []netip.Prefix) error {
	cmds, err := Commands(runtime.GOOS, name, addr, routes)
	if err != nil {
		return err
	}
	for _, c := range cmds {
		out, err := exec.Command(c.Args[0], c.Args[1:]...).CombinedOutput()
		if err == nil {
			logx.Debugf("Ran: %s", c)
			continue
		}
		msg := fmt.Sprintf("%s: %v: %s", c, err, strings.TrimSpace(string(out)))
		if c.Optional {
			logx.Warnf("%s", msg)
			continue
		}
		return fmt.Errorf("%s", msg)
	}
	logx.Infof("Configured %s: address %s, %d route(s)", name, addr, len(routes))
	return nil
}
