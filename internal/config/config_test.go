package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	pubA = "ba54232056ec3b8ff1982904345cea131293ca5daff441d11a23c010c0528442"
	pubB = "d6ce2b2246de6ab18b4d12c86889575958ac186e4894b92fdde597c2bcda2b7a"
)

const minimalYAML = `
interface: microtunnel0
peers:
  - public_key: ` + pubA + `
`

func TestParseAppliesDefaults(t *testing.T) {
	c, err := Parse([]byte(minimalYAML))
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		name      string
		got, want int
	}{
		{"port", c.Port, 5040},
		{"keepalive", c.KeepaliveInterval, 25},
		{"rekey_after", c.RekeyAfter, 180},
		{"reconnect_interval", c.ReconnectInterval, 30},
		{"session_expiry", c.SessionExpiry, 540},
		{"prev_key_grace", c.PrevKeyGrace, 90},
		{"handshake_timeout", c.HandshakeTimeout, 5},
		{"handshake_cooldown", c.HandshakeCooldown, 5},
	}
	for _, ck := range checks {
		if ck.got != ck.want {
			t.Errorf("%s = %d, want %d", ck.name, ck.got, ck.want)
		}
	}
	if c.PrivateKeyFile != "peer.key" {
		t.Errorf("private_key_file default = %q", c.PrivateKeyFile)
	}
	if c.HasPSK || c.Verbose || c.Address != "" {
		t.Errorf("unexpected non-default: %+v", c)
	}
	wantWorkers := min(4, runtime.NumCPU())
	if c.WorkerThreads != wantWorkers {
		t.Errorf("worker_threads = %d, want %d", c.WorkerThreads, wantWorkers)
	}
}

func TestParseAllFields(t *testing.T) {
	c, err := Parse([]byte(`
interface: tun7
address: 192.0.2.10
port: 6000
private_key_file: /etc/microtunnel/x.key
pre_shared_key: secret
verbose: true
keepalive_interval: 10
rekey_after: 100
reconnect_interval: 7
session_expiry: 400
prev_key_grace: 20
handshake_timeout: 3
handshake_cooldown: 2
worker_threads: 2
peers:
  - public_key: ` + pubA + `
    endpoint: relay.example.com:5040
    allowed_ips: [10.9.0.0/24, 192.168.1.0/24]
  - public_key: ` + strings.ToUpper(pubB) + `
    allowed_ips:
      - 10.9.0.3/32
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Interface != "tun7" || c.Address != "192.0.2.10" || c.Port != 6000 ||
		c.PrivateKeyFile != "/etc/microtunnel/x.key" || c.PreSharedKey != "secret" || !c.HasPSK || !c.Verbose ||
		c.KeepaliveInterval != 10 || c.RekeyAfter != 100 || c.ReconnectInterval != 7 ||
		c.SessionExpiry != 400 || c.PrevKeyGrace != 20 || c.HandshakeTimeout != 3 ||
		c.HandshakeCooldown != 2 || c.WorkerThreads != 2 {
		t.Fatalf("unexpected config: %+v", c)
	}
	if len(c.Peers) != 2 {
		t.Fatalf("peers=%d", len(c.Peers))
	}
	p0, p1 := c.Peers[0], c.Peers[1]
	if !p0.HasEndpoint() || p0.Host != "relay.example.com" || p0.Port != 5040 {
		t.Errorf("peer0 endpoint: %+v", p0)
	}
	if len(p0.AllowedIPs) != 2 || p0.AllowedIPs[1].String() != "192.168.1.0/24" {
		t.Errorf("peer0 routes: %v", p0.AllowedIPs)
	}
	if p1.HasEndpoint() {
		t.Error("peer1 should be inbound-only")
	}
	if p1.PublicKey[0] != 0xd6 || p1.PublicKey[31] != 0x7a {
		t.Errorf("peer1 uppercase hex key parsed wrong: %x", p1.PublicKey)
	}
}

func TestParseEndpointUsesLastColon(t *testing.T) {
	c, err := Parse([]byte(minimalYAML + "    endpoint: host.with:colon:5041\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Peers[0].Host != "host.with:colon" || c.Peers[0].Port != 5041 {
		t.Fatalf("got %q:%d", c.Peers[0].Host, c.Peers[0].Port)
	}
}

func TestParseIgnoresUnknownKeys(t *testing.T) {
	if _, err := Parse([]byte("future_option: 1\n" + minimalYAML)); err != nil {
		t.Fatal(err)
	}
}

func TestParseRejectsInvalid(t *testing.T) {
	peer := "\npeers:\n  - public_key: " + pubA + "\n"
	cases := []struct {
		name, yaml, wantSubstr string
	}{
		{"empty document", "", "interface is required"},
		{"missing interface", "port: 5040" + peer, "interface is required"},
		{"interface too long", "interface: abcdefghijklmnop" + peer, "15 characters"},
		{"no peers", "interface: t0\n", "at least one peer"},
		{"bad yaml", "interface: [unterminated", "YAML"},
		{"port zero", "interface: t0\nport: 0" + peer, "port must be"},
		{"port too big", "interface: t0\nport: 70000" + peer, "port must be"},
		{"keepalive zero", "interface: t0\nkeepalive_interval: 0" + peer, "keepalive_interval"},
		{"rekey negative", "interface: t0\nrekey_after: -1" + peer, "rekey_after"},
		{"reconnect zero", "interface: t0\nreconnect_interval: 0" + peer, "reconnect_interval"},
		{"expiry <= rekey", "interface: t0\nrekey_after: 600" + peer, "session_expiry"},
		{"expiry == rekey", "interface: t0\nrekey_after: 100\nsession_expiry: 100" + peer, "session_expiry"},
		{"grace zero", "interface: t0\nprev_key_grace: 0" + peer, "prev_key_grace"},
		{"hs timeout zero", "interface: t0\nhandshake_timeout: 0" + peer, "handshake_timeout"},
		{"hs cooldown zero", "interface: t0\nhandshake_cooldown: 0" + peer, "handshake_cooldown"},
		{"workers negative", "interface: t0\nworker_threads: -1" + peer, "worker_threads"},
		{"workers too many", "interface: t0\nworker_threads: 33" + peer, "worker_threads"},
		{"empty psk", "interface: t0\npre_shared_key: \"\"" + peer, "pre_shared_key"},
		{"peer without key", "interface: t0\npeers:\n  - endpoint: a:1\n", "public_key is required"},
		{"short key", "interface: t0\npeers:\n  - public_key: abcd\n", "invalid public_key"},
		{"non-hex key", "interface: t0\npeers:\n  - public_key: " + strings.Repeat("zz", 32) + "\n", "invalid public_key"},
		{"endpoint without port", "interface: t0" + peer + "    endpoint: justahost\n", "invalid endpoint"},
		{"endpoint empty host", "interface: t0" + peer + "    endpoint: ':5040'\n", "invalid endpoint"},
		{"endpoint port zero", "interface: t0" + peer + "    endpoint: h:0\n", "invalid port"},
		{"endpoint port too big", "interface: t0" + peer + "    endpoint: h:65536\n", "invalid port"},
		{"endpoint port text", "interface: t0" + peer + "    endpoint: h:http\n", "invalid port"},
		{"bad cidr", "interface: t0" + peer + "    allowed_ips: [nope]\n", "invalid CIDR"},
		{"ipv6 cidr", "interface: t0" + peer + "    allowed_ips: ['fd00::/8']\n", "invalid CIDR"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.yaml))
			if err == nil {
				t.Fatalf("expected error containing %q", tc.wantSubstr)
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("error %q does not contain %q", err, tc.wantSubstr)
			}
		})
	}
}

func TestParseTooManyPeers(t *testing.T) {
	var b strings.Builder
	b.WriteString("interface: t0\npeers:\n")
	for i := 0; i < MaxPeers+1; i++ {
		b.WriteString("  - public_key: " + pubA + "\n")
	}
	if _, err := Parse([]byte(b.String())); err == nil || !strings.Contains(err.Error(), "too many peers") {
		t.Fatalf("err=%v", err)
	}
	// Exactly MaxPeers is fine.
	b.Reset()
	b.WriteString("interface: t0\npeers:\n")
	for i := 0; i < MaxPeers; i++ {
		b.WriteString("  - public_key: " + pubA + "\n")
	}
	if _, err := Parse([]byte(b.String())); err != nil {
		t.Fatalf("MaxPeers rejected: %v", err)
	}
}

func TestParseTooManyRoutes(t *testing.T) {
	var b strings.Builder
	b.WriteString(minimalYAML + "    allowed_ips:\n")
	for i := 0; i < MaxRoutesPerPeer+1; i++ {
		b.WriteString("      - 10.0." + string(rune('0'+i%10)) + ".0/24\n")
	}
	if _, err := Parse([]byte(b.String())); err == nil || !strings.Contains(err.Error(), "too many allowed_ips") {
		t.Fatalf("err=%v", err)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadWrapsParseErrorWithPath(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(p, []byte("interface: t0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(p)
	if err == nil || !strings.Contains(err.Error(), "bad.yaml") {
		t.Fatalf("err=%v", err)
	}
}

// The configs shipped in the repo (used by the docs, Docker scripts and
// packages) must always parse.
func TestShippedConfigsParse(t *testing.T) {
	for _, name := range []string{"relay.yaml", "peer-1.yaml", "peer-2.yaml"} {
		t.Run(name, func(t *testing.T) {
			c, err := Load(filepath.Join("..", "..", "config", name))
			if err != nil {
				t.Fatal(err)
			}
			if c.Interface != "microtunnel0" || !c.HasPSK || len(c.Peers) == 0 {
				t.Fatalf("unexpected: %+v", c)
			}
		})
	}
	relay, _ := Load(filepath.Join("..", "..", "config", "relay.yaml"))
	if len(relay.Peers) != 2 || relay.Peers[0].HasEndpoint() || relay.Peers[0].AllowedIPs[0].String() != "10.9.0.2/32" {
		t.Errorf("relay.yaml peers unexpected: %+v", relay.Peers)
	}
	p1, _ := Load(filepath.Join("..", "..", "config", "peer-1.yaml"))
	if !p1.Peers[0].HasEndpoint() || p1.Peers[0].AllowedIPs[0].String() != "10.9.0.0/24" {
		t.Errorf("peer-1.yaml unexpected: %+v", p1.Peers)
	}
}

// config/peer.yaml is a template with placeholders and must be rejected until
// the operator fills it in, rather than silently running with a zero key.
func TestPeerTemplateRejectedUntilEdited(t *testing.T) {
	if _, err := Load(filepath.Join("..", "..", "config", "peer.yaml")); err == nil {
		t.Fatal("placeholder peer.yaml unexpectedly parsed")
	}
}

func TestParseTunnelAddressAndRoutes(t *testing.T) {
	c, err := Parse([]byte(minimalYAML + "tunnel_address: 10.9.0.2/24\ntunnel_routes: [192.168.50.9/24, 10.8.0.0/16]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.TunnelAddress.String(); got != "10.9.0.2/24" {
		t.Fatalf("tunnel_address=%s", got)
	}
	if len(c.TunnelRoutes) != 2 || c.TunnelRoutes[0].String() != "192.168.50.0/24" || c.TunnelRoutes[1].String() != "10.8.0.0/16" {
		t.Fatalf("tunnel_routes=%v (host bits must be masked)", c.TunnelRoutes)
	}
}

func TestParseTunnelAddressUnsetByDefault(t *testing.T) {
	c, err := Parse([]byte(minimalYAML))
	if err != nil {
		t.Fatal(err)
	}
	if c.TunnelAddress.IsValid() || len(c.TunnelRoutes) != 0 {
		t.Fatal("tunnel_address must be opt-in")
	}
}

func TestParseTunnelAddressRejectsInvalid(t *testing.T) {
	for _, tc := range []struct{ name, extra, want string }{
		{"no prefix", "tunnel_address: 10.9.0.2\n", "tunnel_address"},
		{"ipv6", "tunnel_address: fd00::1/64\n", "tunnel_address"},
		{"garbage", "tunnel_address: nope\n", "tunnel_address"},
		{"routes without address", "tunnel_routes: [10.0.0.0/8]\n", "requires tunnel_address"},
		{"bad route", "tunnel_address: 10.9.0.2/24\ntunnel_routes: [nope]\n", "tunnel_routes"},
		{"ipv6 route", "tunnel_address: 10.9.0.2/24\ntunnel_routes: ['fd00::/8']\n", "tunnel_routes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(minimalYAML + tc.extra))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v, want containing %q", err, tc.want)
			}
		})
	}
}
