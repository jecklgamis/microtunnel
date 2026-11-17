package tun

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestUtunHeader(t *testing.T) {
	h, err := utunHeader([]byte{0x45, 0, 0, 20})
	if err != nil || h != [4]byte{0, 0, 0, 2} {
		t.Fatalf("IPv4: h=%v err=%v", h, err)
	}
	h, err = utunHeader([]byte{0x60, 0, 0, 0})
	if err != nil || h != [4]byte{0, 0, 0, 30} {
		t.Fatalf("IPv6: h=%v err=%v", h, err)
	}
	for _, bad := range [][]byte{nil, {}, {0x10}, {0x00}, {0xF5}} {
		if _, err := utunHeader(bad); err == nil {
			t.Errorf("utunHeader(% x) accepted a non-IP packet", bad)
		}
	}
}

func TestUtunUnit(t *testing.T) {
	cases := map[string]uint32{
		"utun0": 1, "utun5": 6, "utun123": 124,
		"utun": 0, "": 0, "microtunnel0": 0, "utunX": 0, "utun-1": 0, "tun0": 0, "utun99999999999": 0,
	}
	for name, want := range cases {
		if got := utunUnit(name); got != want {
			t.Errorf("utunUnit(%q)=%d want %d", name, got, want)
		}
	}
}

func args(cs []Command) [][]string {
	var out [][]string
	for _, c := range cs {
		out = append(out, c.Args)
	}
	return out
}

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func TestCommandsDarwin(t *testing.T) {
	cmds, err := Commands("darwin", "utun7", pfx("10.9.0.2/24"), []netip.Prefix{pfx("192.168.50.0/24"), pfx("10.9.0.5/24")})
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"ifconfig", "utun7", "inet", "10.9.0.2", "10.9.0.2", "netmask", "255.255.255.0", "mtu", "1428", "up"},
		{"route", "-q", "-n", "add", "-inet", "-net", "10.9.0.0/24", "-interface", "utun7"},
		{"route", "-q", "-n", "add", "-inet", "-net", "192.168.50.0/24", "-interface", "utun7"},
		// 10.9.0.5/24 masks to 10.9.0.0/24, a duplicate of the overlay subnet: not repeated.
	}
	if got := args(cmds); !reflect.DeepEqual(got, want) {
		t.Fatalf("got:\n%v\nwant:\n%v", got, want)
	}
	if cmds[0].Optional {
		t.Error("ifconfig must be mandatory")
	}
	if !cmds[1].Optional || !cmds[2].Optional {
		t.Error("route additions must be optional (they fail harmlessly if the route exists)")
	}
}

func TestCommandsDarwinHostAddressNeedsNoRoute(t *testing.T) {
	cmds, err := Commands("darwin", "utun0", pfx("10.9.0.1/32"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 1 || cmds[0].Args[0] != "ifconfig" {
		t.Fatalf("got %v", args(cmds))
	}
	if !strings.Contains(cmds[0].String(), "netmask 255.255.255.255") {
		t.Fatalf("bad mask: %s", cmds[0])
	}
}

func TestCommandsDarwinMasks(t *testing.T) {
	for bits, mask := range map[int]string{0: "0.0.0.0", 8: "255.0.0.0", 16: "255.255.0.0", 23: "255.255.254.0", 30: "255.255.255.252"} {
		cmds, err := Commands("darwin", "utun0", netip.PrefixFrom(netip.MustParseAddr("10.9.0.2"), bits), nil)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(cmds[0].String(), "netmask "+mask+" ") {
			t.Errorf("/%d: %s (want netmask %s)", bits, cmds[0], mask)
		}
	}
}

func TestCommandsLinux(t *testing.T) {
	cmds, err := Commands("linux", "microtunnel0", pfx("10.9.0.2/24"), []netip.Prefix{pfx("192.168.50.7/24")})
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"ip", "link", "set", "dev", "microtunnel0", "up"},
		{"ip", "addr", "add", "10.9.0.2/24", "dev", "microtunnel0"},
		{"ip", "route", "add", "192.168.50.0/24", "dev", "microtunnel0"},
	}
	if got := args(cmds); !reflect.DeepEqual(got, want) {
		t.Fatalf("got:\n%v\nwant:\n%v", got, want)
	}
}

func TestCommandsRejectsBadInput(t *testing.T) {
	if _, err := Commands("darwin", "utun0", netip.Prefix{}, nil); err == nil {
		t.Error("zero prefix accepted")
	}
	if _, err := Commands("darwin", "utun0", pfx("fd00::1/64"), nil); err == nil {
		t.Error("IPv6 address accepted")
	}
	if _, err := Commands("linux", "t0", pfx("10.0.0.1/24"), []netip.Prefix{pfx("fd00::/8")}); err == nil {
		t.Error("IPv6 route accepted")
	}
	if _, err := Commands("plan9", "t0", pfx("10.0.0.1/24"), nil); err == nil {
		t.Error("unsupported OS accepted")
	}
}
