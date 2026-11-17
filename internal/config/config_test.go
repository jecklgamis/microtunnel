package config

import (
	"fmt"
	"github.com/jecklgamis/microtunnel/internal/proto"
	"os"
	"path/filepath"
	"regexp"
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
		b.WriteString(fmt.Sprintf("  - public_key: %064x\n", i+1))
	}
	if _, err := Parse([]byte(b.String())); err == nil || !strings.Contains(err.Error(), "too many peers") {
		t.Fatalf("err=%v", err)
	}
	// Exactly MaxPeers is fine.
	b.Reset()
	b.WriteString("interface: t0\npeers:\n")
	for i := 0; i < MaxPeers; i++ {
		b.WriteString(fmt.Sprintf("  - public_key: %064x\n", i+1))
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

func TestParseDuplicatePeerKey(t *testing.T) {
	y := minimalYAML + "  - public_key: " + pubA + "\n"
	if _, err := Parse([]byte(y)); err == nil || !strings.Contains(err.Error(), "duplicate peer public_key") {
		t.Fatalf("err=%v", err)
	}
}

func writePeerFile(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeConfig(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, "relay.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadPeersDirMergesWithInline(t *testing.T) {
	dir := t.TempDir()
	pd := filepath.Join(dir, "peers.d")
	if err := os.Mkdir(pd, 0o755); err != nil {
		t.Fatal(err)
	}
	writePeerFile(t, pd, "laptop.yaml", "public_key: "+pubB+"\nallowed_ips: [10.9.0.5/32]\n")
	writePeerFile(t, pd, "notes.txt", "ignored")
	writePeerFile(t, pd, ".hidden.yaml", "garbage: [")
	writePeerFile(t, pd, "laptop.yaml.tmp", "garbage: [")

	// peers_dir is relative: resolved against the config file's directory.
	path := writeConfig(t, dir, minimalYAML+"peers_dir: peers.d\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PeersDir != pd {
		t.Fatalf("PeersDir=%q want %q", cfg.PeersDir, pd)
	}
	if len(cfg.Peers) != 2 {
		t.Fatalf("peers=%d want 2", len(cfg.Peers))
	}
	got := cfg.Peers[1]
	if got.Name != "laptop" || len(got.AllowedIPs) != 1 || got.AllowedIPs[0].String() != "10.9.0.5/32" {
		t.Fatalf("dir peer = %+v", got)
	}
	if cfg.Peers[0].Name != "" {
		t.Fatalf("inline peer should have no Name, got %q", cfg.Peers[0].Name)
	}
}

func TestLoadPeersDirAllowsZeroPeers(t *testing.T) {
	dir := t.TempDir()
	pd := filepath.Join(dir, "peers.d")
	if err := os.Mkdir(pd, 0o755); err != nil {
		t.Fatal(err)
	}
	path := writeConfig(t, dir, "interface: t0\npeers_dir: "+pd+"\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Peers) != 0 {
		t.Fatalf("peers=%d", len(cfg.Peers))
	}
	// Without peers_dir, zero peers is still an error.
	if _, err := Parse([]byte("interface: t0\n")); err == nil {
		t.Fatal("zero peers without peers_dir must be rejected")
	}
}

func TestLoadPeersDirErrors(t *testing.T) {
	dir := t.TempDir()
	pd := filepath.Join(dir, "peers.d")
	if err := os.Mkdir(pd, 0o755); err != nil {
		t.Fatal(err)
	}
	path := writeConfig(t, dir, "interface: t0\npeers_dir: "+pd+"\n")

	for name, tc := range map[string]struct{ file, body, want string }{
		"bad yaml":  {"a.yaml", "public_key: [", "a.yaml"},
		"no key":    {"a.yaml", "endpoint: x:1\n", "public_key is required"},
		"bad cidr":  {"a.yaml", "public_key: " + pubA + "\nallowed_ips: [nope]\n", "invalid CIDR"},
		"duplicate": {"b.yaml", "public_key: " + pubA + "\n", "duplicate peer public_key"},
	} {
		t.Run(name, func(t *testing.T) {
			_ = os.Remove(filepath.Join(pd, "a.yaml"))
			_ = os.Remove(filepath.Join(pd, "b.yaml"))
			if name == "duplicate" {
				writePeerFile(t, pd, "a.yaml", "public_key: "+pubA+"\n")
			}
			writePeerFile(t, pd, tc.file, tc.body)
			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v want substring %q", err, tc.want)
			}
		})
	}

	// A missing directory is an error too (typo protection).
	path = writeConfig(t, dir, "interface: t0\npeers_dir: "+filepath.Join(dir, "nope")+"\n")
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "peers_dir") {
		t.Fatalf("missing dir err=%v", err)
	}
}

func TestPeersDirFingerprint(t *testing.T) {
	pd := t.TempDir()
	if PeersDirFingerprint(filepath.Join(pd, "nope")) != "" {
		t.Fatal("missing dir should fingerprint to empty")
	}
	empty := PeersDirFingerprint(pd)
	writePeerFile(t, pd, "a.yaml", "public_key: "+pubA+"\n")
	one := PeersDirFingerprint(pd)
	if one == empty {
		t.Fatal("adding a file must change the fingerprint")
	}
	writePeerFile(t, pd, "ignored.txt", "x")
	writePeerFile(t, pd, "a.yaml.tmp", "x")
	if PeersDirFingerprint(pd) != one {
		t.Fatal("non-peer files must not change the fingerprint")
	}
	writePeerFile(t, pd, "a.yaml", "public_key: "+pubB+"\n")
	if PeersDirFingerprint(pd) == one {
		t.Fatal("editing a file must change the fingerprint")
	}
	if err := os.Remove(filepath.Join(pd, "a.yaml")); err != nil {
		t.Fatal(err)
	}
	if PeersDirFingerprint(pd) != empty {
		t.Fatal("removing the file must restore the fingerprint")
	}
}

func TestPeerName(t *testing.T) {
	for in, want := range map[string]string{"a.yaml": "a", "b.yml": "b", "/x/y/c-1.yaml": "c-1"} {
		if got := PeerName(in); got != want {
			t.Errorf("PeerName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestAdminSocketAndPublicEndpoint(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, minimalYAML+"admin_socket: run/admin.sock\npublic_endpoint: relay.example.com:5040\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AdminSocket != filepath.Join(dir, "run/admin.sock") {
		t.Fatalf("relative admin_socket not resolved against the config dir: %q", cfg.AdminSocket)
	}
	if cfg.PublicEndpoint != "relay.example.com:5040" {
		t.Fatalf("public_endpoint=%q", cfg.PublicEndpoint)
	}
	path = writeConfig(t, dir, minimalYAML+"admin_socket: /run/mt.sock\n")
	if cfg, err = Load(path); err != nil || cfg.AdminSocket != "/run/mt.sock" {
		t.Fatalf("absolute admin_socket changed: %v %v", cfg, err)
	}
	for _, bad := range []string{"nohostport", "host:0", "host:99999", ":5040"} {
		if _, err := Parse([]byte(minimalYAML + "public_endpoint: " + bad + "\n")); err == nil {
			t.Errorf("public_endpoint %q should be rejected", bad)
		}
	}
}

func TestDemoKeysMatchTheCommittedFiles(t *testing.T) {
	// demoKeys must describe exactly the key pairs checked in under config/.
	for _, name := range []string{"relay", "peer-1", "peer-2"} {
		pub, err := proto.LoadPublicKey(filepath.Join("..", "..", "config", name+".crt"))
		if err != nil {
			t.Fatal(err)
		}
		got, ok := DemoKeyName(pub)
		if !ok || got != name {
			t.Errorf("config/%s.crt (%x) is not listed as demo key %q (got %q, %v)", name, pub[:4], name, got, ok)
		}
	}
	if len(demoKeys) != 3 {
		t.Errorf("demoKeys has %d entries, want 3", len(demoKeys))
	}
}

func TestWarningsFlagPlaceholdersAndDemoKeys(t *testing.T) {
	demo, _ := Parse([]byte("interface: t0\npre_shared_key: some-psk\npeers:\n  - public_key: ba54232056ec3b8ff1982904345cea131293ca5daff441d11a23c010c0528442\n"))
	w := demo.Warnings()
	if len(w) != 2 || !strings.Contains(w[0], "some-psk") || !strings.Contains(w[1], `"peer-1"`) {
		t.Fatalf("warnings = %q", w)
	}
	const realKey = "0000000000000000000000000000000000000000000000000000000000000001"
	if w := mustParse(t, "interface: t0\npre_shared_key: change-me\npeers:\n  - public_key: "+realKey+"\n").Warnings(); len(w) != 1 || !strings.Contains(w[0], "change-me") {
		t.Fatalf("change-me should give exactly the placeholder warning: %q", w)
	}
	// A real configuration is silent.
	clean := mustParse(t, "interface: t0\npre_shared_key: 8f3k29xv-long-random-secret\npeers:\n  - public_key: 0000000000000000000000000000000000000000000000000000000000000001\n")
	if w := clean.Warnings(); len(w) != 0 {
		t.Fatalf("unexpected warnings: %q", w)
	}
	// No PSK at all is not a placeholder warning (main warns about that separately).
	if w := mustParse(t, "interface: t0\npeers:\n  - public_key: 0000000000000000000000000000000000000000000000000000000000000001\n").Warnings(); len(w) != 0 {
		t.Fatalf("unexpected warnings: %q", w)
	}
}

func mustParse(t *testing.T, y string) *Config {
	t.Helper()
	c, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPackagedTemplatesAreSafePlaceholders(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "packaging", "config", "*.yaml"))
	if err != nil || len(files) != 2 {
		t.Fatalf("expected the 2 packaged examples (relay, peer), got %v (%v)", files, err)
	}
	keyPlaceholder := regexp.MustCompile(`<[a-z0-9-]*public-key-hex>`)
	anyPlaceholder := regexp.MustCompile(`<[^>\n]+>`)
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		text := string(raw)
		// No secrets, demo identities or well-known values may ship in a package.
		for hexKey := range demoKeys {
			if strings.Contains(text, hexKey) {
				t.Errorf("%s contains a demo public key", f)
			}
		}
		for _, psk := range placeholderPSKs {
			if strings.Contains(text, "pre_shared_key: "+psk) {
				t.Errorf("%s ships the well-known pre-shared key %q", f, psk)
			}
		}
		// As shipped it must NOT load: the service cannot start until the
		// administrator has replaced the placeholders.
		if _, err := Parse(raw); err == nil {
			t.Errorf("%s loads as-is; an untouched template must not run", f)
		}
		// Once the placeholders are filled in with real-looking values it must be valid.
		n := 0
		filled := keyPlaceholder.ReplaceAllStringFunc(text, func(string) string {
			n++ // distinct keys: duplicates are rejected
			return fmt.Sprintf("%064x", 0xa0+n)
		})
		filled = strings.ReplaceAll(filled, "<relay-host-or-ip>", "relay.example.com")
		filled = anyPlaceholder.ReplaceAllStringFunc(filled, func(string) string { return "filled-in-value" })
		cfg, err := Parse([]byte(filled))
		if err != nil {
			t.Errorf("%s is not a valid config once filled in: %v\n%s", f, err, filled)
			continue
		}
		if len(cfg.Peers) == 0 && cfg.PeersDir == "" {
			t.Errorf("%s has neither peers nor a peers_dir once filled in", f)
		}
	}
}

func TestPlaceholderPSKIsRejected(t *testing.T) {
	for _, psk := range []string{"<replace-with-a-long-random-secret>", "<same-secret-as-the-relay>", "<x>"} {
		_, err := Parse([]byte(minimalYAML + "pre_shared_key: \"" + psk + "\"\n"))
		if err == nil || !strings.Contains(err.Error(), "placeholder") {
			t.Errorf("psk %q: err=%v, want a placeholder error", psk, err)
		}
	}
	// Ordinary secrets that merely contain angle brackets are fine.
	for _, psk := range []string{"a<b>c", "<>", "<", "secret>"} {
		if _, err := Parse([]byte(minimalYAML + "pre_shared_key: \"" + psk + "\"\n")); err != nil {
			t.Errorf("psk %q wrongly rejected: %v", psk, err)
		}
	}
}
