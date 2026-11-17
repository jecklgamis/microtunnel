package admin

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jecklgamis/microtunnel/internal/config"
	"github.com/jecklgamis/microtunnel/internal/proto"
)

// relayEnv is a relay config on disk with its own key and an empty peers_dir.
type relayEnv struct {
	dir, cfgPath, peersDir string
	relayPub               string
}

func newRelayEnv(t *testing.T, extra string) *relayEnv {
	t.Helper()
	e := &relayEnv{dir: t.TempDir()}
	e.peersDir = filepath.Join(e.dir, "peers.d")
	if err := os.Mkdir(e.peersDir, 0o755); err != nil {
		t.Fatal(err)
	}
	key, err := proto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := proto.WriteKeyPair(filepath.Join(e.dir, "relay"), key); err != nil {
		t.Fatal(err)
	}
	pub := proto.PubBytes(key)
	e.relayPub = proto.BytesToHex(pub[:])
	e.cfgPath = filepath.Join(e.dir, "relay.yaml")
	body := "interface: microtunnel0\nport: 5040\nprivate_key_file: relay.key\npre_shared_key: s3cret\n" +
		"tunnel_address: 10.9.0.1/24\npeers_dir: peers.d\n" + extra
	if err := os.WriteFile(e.cfgPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return e
}

func randPub(t *testing.T) string {
	t.Helper()
	k, err := proto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	p := proto.PubBytes(k)
	return proto.BytesToHex(p[:])
}

func add(t *testing.T, e *relayEnv, name string, mod func(*AddOptions)) (*AddResult, error) {
	t.Helper()
	o := AddOptions{ConfigPath: e.cfgPath, Name: name, PublicKeyHex: randPub(t), Endpoint: "relay.example.com:5040"}
	if mod != nil {
		mod(&o)
	}
	return Add(o)
}

func TestAddAllocatesSequentialIPsAndRelayLoadsThem(t *testing.T) {
	e := newRelayEnv(t, "")
	for i, name := range []string{"laptop", "phone", "server"} {
		res, err := add(t, e, name, nil)
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"10.9.0.2", "10.9.0.3", "10.9.0.4"}[i]; res.IP.String() != want {
			t.Fatalf("%s got %s want %s", name, res.IP, want)
		}
	}
	cfg, err := config.Load(e.cfgPath)
	if err != nil {
		t.Fatalf("relay cannot load what Add wrote: %v", err)
	}
	if len(cfg.Peers) != 3 {
		t.Fatalf("peers=%d", len(cfg.Peers))
	}
	if cfg.Peers[1].Name != "phone" || cfg.Peers[1].AllowedIPs[0].String() != "10.9.0.3/32" {
		t.Fatalf("peer = %+v", cfg.Peers[1])
	}
}

func TestAddReusesFreedIP(t *testing.T) {
	e := newRelayEnv(t, "")
	for _, n := range []string{"a", "b", "c"} {
		if _, err := add(t, e, n, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := Remove(e.cfgPath, "b"); err != nil {
		t.Fatal(err)
	}
	res, err := add(t, e, "d", nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.IP.String() != "10.9.0.3" {
		t.Fatalf("freed address not reused: %s", res.IP)
	}
}

func TestAddExplicitIP(t *testing.T) {
	e := newRelayEnv(t, "")
	res, err := add(t, e, "x", func(o *AddOptions) { o.IP = "10.9.0.77" })
	if err != nil || res.IP.String() != "10.9.0.77" {
		t.Fatalf("res=%v err=%v", res, err)
	}
	for name, ip := range map[string]string{
		"taken":     "10.9.0.77",
		"relay":     "10.9.0.1",
		"network":   "10.9.0.0",
		"broadcast": "10.9.0.255",
		"outside":   "10.8.0.5",
		"garbage":   "nope",
	} {
		if _, err := add(t, e, "y-"+name, func(o *AddOptions) { o.IP = ip }); err == nil {
			t.Errorf("%s: IP %s should be rejected", name, ip)
		}
	}
	// A rejected add leaves nothing behind.
	if _, err := os.Stat(filepath.Join(e.peersDir, "y-taken.yaml")); err == nil {
		t.Fatal("rejected add left a peer file")
	}
}

func TestAddRejectsBadInput(t *testing.T) {
	e := newRelayEnv(t, "")
	good, err := add(t, e, "good", nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*AddOptions){
		"duplicate name": func(o *AddOptions) { o.Name = "good" },
		"duplicate key":  func(o *AddOptions) { o.PublicKeyHex = proto.BytesToHex(good.PublicKey[:]) },
		"short key":      func(o *AddOptions) { o.PublicKeyHex = "abcd" },
		"non-hex key":    func(o *AddOptions) { o.PublicKeyHex = strings.Repeat("zz", 32) },
		"no key":         func(o *AddOptions) { o.PublicKeyHex = "" },
		"both":           func(o *AddOptions) { o.Generate = true },
		"path in name":   func(o *AddOptions) { o.Name = "../evil" },
		"dot name":       func(o *AddOptions) { o.Name = ".hidden" },
		"empty name":     func(o *AddOptions) { o.Name = "" },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := add(t, e, "fresh", mod); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
	entries, _ := os.ReadDir(e.peersDir)
	if len(entries) != 1 {
		t.Fatalf("failed adds left files behind: %v", entries)
	}
}

func TestAddRequiresPeersDirAndSubnet(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "r.yaml")
	_ = os.WriteFile(p, []byte("interface: t0\npeers:\n  - public_key: "+randPub(t)+"\n"), 0o644)
	if _, err := Add(AddOptions{ConfigPath: p, Name: "x", PublicKeyHex: randPub(t)}); err == nil ||
		!strings.Contains(err.Error(), "peers_dir") {
		t.Fatalf("err=%v", err)
	}

	// peers_dir but no tunnel_address (Linux relay configured externally): needs an explicit subnet.
	e := newRelayEnv(t, "")
	body, _ := os.ReadFile(e.cfgPath)
	_ = os.WriteFile(e.cfgPath, []byte(strings.Replace(string(body), "tunnel_address: 10.9.0.1/24\n", "", 1)), 0o644)
	if _, err := add(t, e, "x", nil); err == nil || !strings.Contains(err.Error(), "subnet") {
		t.Fatalf("err=%v", err)
	}
	res, err := add(t, e, "x", func(o *AddOptions) { o.Subnet = "10.50.0.0/24" })
	if err != nil || res.IP.String() != "10.50.0.2" { // .1 is reserved for the relay by convention
		t.Fatalf("res=%v err=%v", res, err)
	}
}

func TestAddExhaustsSubnet(t *testing.T) {
	e := newRelayEnv(t, "")
	body, _ := os.ReadFile(e.cfgPath)
	_ = os.WriteFile(e.cfgPath, []byte(strings.Replace(string(body), "10.9.0.1/24", "10.9.0.1/30", 1)), 0o644)
	if _, err := add(t, e, "one", nil); err != nil { // /30: .1 relay, .2 free, .3 broadcast
		t.Fatal(err)
	}
	if _, err := add(t, e, "two", nil); err == nil || !strings.Contains(err.Error(), "no free addresses") {
		t.Fatalf("err=%v", err)
	}
}

func TestAddGenerateWritesUsableBundle(t *testing.T) {
	e := newRelayEnv(t, "")
	out := filepath.Join(e.dir, "bundle")
	res, err := add(t, e, "laptop", func(o *AddOptions) { o.PublicKeyHex = ""; o.Generate = true; o.KeyDir = out })
	if err != nil {
		t.Fatal(err)
	}
	key, err := proto.LoadStaticKey(res.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if Key(proto.PubBytes(key)) != res.PublicKey {
		t.Fatal("registered public key does not match the generated private key")
	}
	if _, err := proto.LoadPublicKey(res.CrtFile); err != nil {
		t.Fatal(err)
	}

	// The saved spoke config must itself be a valid microtunnel config that
	// points back at this relay.
	spoke, err := config.Load(res.SpokeFile)
	if err != nil {
		t.Fatalf("generated spoke config is invalid: %v\n%s", err, res.SpokeConfig)
	}
	if spoke.TunnelAddress.String() != "10.9.0.2/24" || spoke.PreSharedKey != "s3cret" || spoke.PrivateKeyFile != "laptop.key" {
		t.Fatalf("spoke = addr %v psk %q key %q", spoke.TunnelAddress, spoke.PreSharedKey, spoke.PrivateKeyFile)
	}
	if len(spoke.Peers) != 1 || proto.BytesToHex(spoke.Peers[0].PublicKey[:]) != e.relayPub ||
		spoke.Peers[0].Host != "relay.example.com" || spoke.Peers[0].Port != 5040 ||
		spoke.Peers[0].AllowedIPs[0].String() != "10.9.0.0/24" {
		t.Fatalf("spoke peer = %+v", spoke.Peers)
	}
	if st, _ := os.Stat(res.SpokeFile); st.Mode().Perm() != 0o600 {
		t.Fatalf("spoke config mode %v (it carries the PSK)", st.Mode().Perm())
	}
}

func TestAddWithOwnKeyDoesNotGenerateFiles(t *testing.T) {
	e := newRelayEnv(t, "")
	out := filepath.Join(e.dir, "bundle")
	res, err := add(t, e, "laptop", func(o *AddOptions) { o.KeyDir = out; o.Endpoint = "" })
	if err != nil {
		t.Fatal(err)
	}
	if res.KeyFile != "" || res.SpokeFile != "" {
		t.Fatalf("no files expected: %+v", res)
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("key dir should not be created when the peer brings its own key")
	}
	if !strings.Contains(res.SpokeConfig, "RELAY_HOST:5040") {
		t.Fatalf("missing endpoint placeholder:\n%s", res.SpokeConfig)
	}
}

func TestRemoveAndList(t *testing.T) {
	e := newRelayEnv(t, "peers:\n  - public_key: "+strings.Repeat("ab", 32)+"\n    allowed_ips: [10.9.0.9/32]\n")
	if _, err := add(t, e, "laptop", nil); err != nil {
		t.Fatal(err)
	}
	entries, err := List(e.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || !entries[0].Inline || entries[1].Name != "laptop" || entries[1].AllowedIPs[0] != "10.9.0.2/32" {
		t.Fatalf("entries=%+v", entries)
	}
	// The inline peer's .9 is respected by the allocator.
	if res, err := add(t, e, "phone", func(o *AddOptions) { o.IP = "10.9.0.9" }); err == nil {
		t.Fatalf("allocated an address held by an inline peer: %v", res.IP)
	}

	if err := Remove(e.cfgPath, "laptop"); err != nil {
		t.Fatal(err)
	}
	if err := Remove(e.cfgPath, "laptop"); err == nil || !strings.Contains(err.Error(), "no such peer") {
		t.Fatalf("err=%v", err)
	}
	if err := Remove(e.cfgPath, "../relay"); err == nil {
		t.Fatal("path traversal in name must be rejected")
	}
	if entries, _ = List(e.cfgPath); len(entries) != 1 {
		t.Fatalf("entries=%+v", entries)
	}
}

func TestRegisterDefaultsEndpointAndRoundTripsJSON(t *testing.T) {
	e := newRelayEnv(t, "public_endpoint: relay.example.com:5040\n")
	reg, err := Register(e.cfgPath, RegisterOptions{Name: "laptop", PublicKeyHex: randPub(t)})
	if err != nil {
		t.Fatal(err)
	}
	if reg.Endpoint != "relay.example.com:5040" || reg.IP.String() != "10.9.0.2" || reg.Subnet.String() != "10.9.0.0/24" {
		t.Fatalf("reg = %+v", reg)
	}
	if reg.RelayPublicKey.String() != e.relayPub || reg.PreSharedKey != "s3cret" {
		t.Fatalf("relay identity not carried: %+v", reg)
	}
	raw, err := json.Marshal(reg)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"ip":"10.9.0.2"`, `"subnet":"10.9.0.0/24"`, `"relay_public_key":"` + e.relayPub + `"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("json missing %s: %s", want, raw)
		}
	}
	if strings.Contains(string(raw), "peers.d") {
		t.Errorf("the server-side file path must not be serialised: %s", raw)
	}
	var back Registration
	if err := json.Unmarshal(raw, &back); err != nil || back.IP != reg.IP || back.PublicKey != reg.PublicKey {
		t.Fatalf("round trip: %+v %v", back, err)
	}
	if err := json.Unmarshal([]byte(`{"public_key":"zz"}`), &back); err == nil {
		t.Fatal("bad hex must not unmarshal")
	}

	if _, err := Register(e.cfgPath, RegisterOptions{Name: "x", PublicKeyHex: randPub(t), Endpoint: "no-port"}); err == nil {
		t.Fatal("a malformed endpoint override must be rejected")
	}
	if _, err := os.Stat(filepath.Join(e.peersDir, "x.yaml")); err == nil {
		t.Fatal("rejected registration left a file behind")
	}
}

func TestSpokeConfigVariants(t *testing.T) {
	reg := &Registration{Name: "mac", IP: netip.MustParseAddr("10.9.0.7"), Subnet: netip.MustParsePrefix("10.9.0.0/24"),
		Endpoint: "r:5040"}
	out := SpokeConfig(reg, SpokeOptions{KeyFile: "/etc/mt/mac.key", Interface: "utun"})
	for _, want := range []string{"interface: utun\n", "private_key_file: /etc/mt/mac.key", "tunnel_address: 10.9.0.7/24", "endpoint: r:5040"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "pre_shared_key") {
		t.Errorf("no PSK was set, none should be emitted:\n%s", out)
	}
	if _, err := config.Parse([]byte(out)); err != nil {
		t.Fatalf("generated config does not parse: %v\n%s", err, out)
	}
}

func TestSpokeConfigQuotesHostileValues(t *testing.T) {
	relay, _ := proto.GenerateKey()
	rp := proto.PubBytes(relay)
	for _, psk := range []string{"plain", "has: colon", "has # hash", `quo"te`, "multi\nline: x\npeers: []", "  spaced  ", "'single'"} {
		reg := &Registration{Name: "n", IP: netip.MustParseAddr("10.9.0.2"), Subnet: netip.MustParsePrefix("10.9.0.0/24"),
			Endpoint: "r.example.com:5040", PreSharedKey: psk, RelayPublicKey: Key(rp)}
		out := SpokeConfig(reg, SpokeOptions{KeyFile: "n.key"})
		cfg, err := config.Parse([]byte(out))
		if err != nil {
			t.Fatalf("psk %q produced an invalid config: %v\n%s", psk, err, out)
		}
		if cfg.PreSharedKey != psk {
			t.Fatalf("psk %q came back as %q\n%s", psk, cfg.PreSharedKey, out)
		}
		if len(cfg.Peers) != 1 {
			t.Fatalf("psk %q injected or dropped peers (%d)\n%s", psk, len(cfg.Peers), out)
		}
	}
}
