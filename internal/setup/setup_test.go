package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jecklgamis/microtunnel/internal/admin"
	"github.com/jecklgamis/microtunnel/internal/config"
	"github.com/jecklgamis/microtunnel/internal/proto"
)

func perm(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func TestInitRelayWritesACompleteValidConfig(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "etc")
	res, err := InitRelay(RelayOptions{Dir: dir, Endpoint: "relay.example.com:5040", AdminSocket: "/run/microtunnel/admin.sock"})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(res.ConfigFile)
	if err != nil {
		t.Fatalf("the daemon would not accept what init wrote: %v", err)
	}
	if cfg.TunnelAddress.String() != "10.9.0.1/24" || cfg.Port != 5040 || cfg.PreSharedKey != res.PSK ||
		cfg.PeersDir != res.PeersDir || cfg.AdminSocket != "/run/microtunnel/admin.sock" || cfg.PublicEndpoint != "relay.example.com:5040" {
		t.Fatalf("config = %+v", cfg)
	}
	if len(res.PSK) != 64 {
		t.Fatalf("psk %q is not 32 random bytes of hex", res.PSK)
	}
	if w := cfg.Warnings(); len(w) != 0 {
		t.Fatalf("a freshly initialised relay must not trip the insecure-value warnings: %q", w)
	}
	if k, err := proto.LoadStaticKey(res.KeyFile); err != nil || admin.Key(proto.PubBytes(k)) != res.PublicKey {
		t.Fatalf("key file does not match the reported public key: %v", err)
	}
	if _, err := proto.LoadPublicKey(res.CrtFile); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{res.KeyFile: 0o600, res.ConfigFile: 0o600, res.PeersDir: 0o750} {
		if got := perm(t, path); got != want {
			t.Errorf("%s mode %v, want %v", path, got, want)
		}
	}
	if res.ReusedKey || res.Overwrote {
		t.Fatalf("fresh init flagged as reuse/overwrite: %+v", res)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(leftovers) != 0 {
		t.Fatalf("temp files left behind: %v", leftovers)
	}
}

func TestInitRelayOptions(t *testing.T) {
	dir := t.TempDir()
	res, err := InitRelay(RelayOptions{Dir: dir, Address: "172.20.0.1/16", Port: 6000, AdminSocket: NoAdminSocket})
	if err != nil {
		t.Fatal(err)
	}
	text, _ := os.ReadFile(res.ConfigFile)
	if strings.Contains(string(text), "admin_socket") || strings.Contains(string(text), "public_endpoint") {
		t.Fatalf("disabled/unset options leaked into the config:\n%s", text)
	}
	cfg, _ := config.Load(res.ConfigFile)
	if cfg.TunnelAddress.String() != "172.20.0.1/16" || cfg.Port != 6000 || cfg.AdminSocket != "" {
		t.Fatalf("cfg = %+v", cfg)
	}
}

func TestInitRelayNeverClobbersAnExistingKeyOrConfig(t *testing.T) {
	dir := t.TempDir()
	first, err := InitRelay(RelayOptions{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	keyBefore, _ := os.ReadFile(first.KeyFile)
	cfgBefore, _ := os.ReadFile(first.ConfigFile)

	if _, err := InitRelay(RelayOptions{Dir: dir}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second init must refuse: %v", err)
	}
	if after, _ := os.ReadFile(first.ConfigFile); string(after) != string(cfgBefore) {
		t.Fatal("a refused init changed the config")
	}

	// -force replaces the config (new pre-shared key) but keeps the identity.
	second, err := InitRelay(RelayOptions{Dir: dir, Force: true})
	if err != nil {
		t.Fatal(err)
	}
	if !second.Overwrote || !second.ReusedKey || second.PublicKey != first.PublicKey || second.PSK == first.PSK {
		t.Fatalf("force result = %+v", second)
	}
	if keyAfter, _ := os.ReadFile(first.KeyFile); string(keyAfter) != string(keyBefore) {
		t.Fatal("the private key was modified")
	}
}

func TestInitRelayReusesAKeyMadeEarlier(t *testing.T) {
	dir := t.TempDir()
	k, _ := proto.GenerateKey()
	if _, _, err := proto.WriteKeyPair(filepath.Join(dir, "relay"), k); err != nil { // e.g. an earlier `microtunnel keygen relay`
		t.Fatal(err)
	}
	res, err := InitRelay(RelayOptions{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if !res.ReusedKey || res.PublicKey != admin.Key(proto.PubBytes(k)) {
		t.Fatalf("an existing key must be reused: %+v", res)
	}

	// A key that cannot be read is reported and left alone.
	dir2 := t.TempDir()
	bad := filepath.Join(dir2, "relay.key")
	_ = os.WriteFile(bad, []byte("not a key"), 0o600)
	if _, err := InitRelay(RelayOptions{Dir: dir2}); err == nil || !strings.Contains(err.Error(), "was not touched") {
		t.Fatalf("err=%v", err)
	}
	if got, _ := os.ReadFile(bad); string(got) != "not a key" {
		t.Fatal("an unreadable key file was modified")
	}
	if _, err := os.Stat(filepath.Join(dir2, "relay.yaml")); err == nil {
		t.Fatal("a config was written despite the key problem")
	}
}

func TestInitRelayRejectsBadInput(t *testing.T) {
	for name, o := range map[string]RelayOptions{
		"bad address":    {Address: "nope"},
		"ipv6 address":   {Address: "fd00::1/64"},
		"no host bits":   {Address: "10.9.0.1/31"},
		"bad port":       {Port: 70000},
		"bad endpoint":   {Endpoint: "no-port"},
		"relative admin": {AdminSocket: "admin.sock"},
	} {
		t.Run(name, func(t *testing.T) {
			o.Dir = t.TempDir()
			if _, err := InitRelay(o); err == nil {
				t.Fatal("expected an error")
			}
			if entries, _ := os.ReadDir(o.Dir); len(entries) != 0 {
				t.Fatalf("a rejected init left files: %v", entries)
			}
		})
	}
}

func TestInitPeerWithAnAddress(t *testing.T) {
	relay := mustRelay(t)
	dir := t.TempDir()
	res, err := InitPeer(PeerOptions{Dir: dir, Name: "laptop", Relay: "relay.example.com:5040",
		RelayKey: relay.PublicKey.String(), PSK: relay.PSK, Address: "10.9.0.2/24"})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(res.ConfigFile)
	if err != nil {
		t.Fatalf("daemon would not accept the peer config: %v", err)
	}
	if cfg.TunnelAddress.String() != "10.9.0.2/24" || cfg.PreSharedKey != relay.PSK || cfg.PrivateKeyFile != res.KeyFile ||
		len(cfg.Peers) != 1 || admin.Key(cfg.Peers[0].PublicKey) != relay.PublicKey ||
		cfg.Peers[0].Host != "relay.example.com" || cfg.Peers[0].AllowedIPs[0].String() != "10.9.0.0/24" {
		t.Fatalf("cfg = %+v", cfg)
	}
	if cfg.ReconnectInterval != 5 {
		t.Fatalf("a fresh peer should retry quickly, reconnect_interval=%d", cfg.ReconnectInterval)
	}
	if perm(t, res.KeyFile) != 0o600 || perm(t, res.ConfigFile) != 0o600 {
		t.Fatal("key and config (it holds the PSK) must be 0600")
	}
	if filepath.Base(res.ConfigFile) != "laptop.yaml" || filepath.Base(res.KeyFile) != "laptop.key" {
		t.Fatalf("files = %s %s", res.ConfigFile, res.KeyFile)
	}
}

func TestInitPeerBeforeTheAddressIsAssigned(t *testing.T) {
	relay := mustRelay(t)
	res, err := InitPeer(PeerOptions{Dir: t.TempDir(), Relay: "r:5040", RelayKey: relay.PublicKey.String(), PSK: relay.PSK, Subnet: "10.50.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	text, _ := os.ReadFile(res.ConfigFile)
	if !strings.Contains(string(text), "#tunnel_address:") {
		t.Fatalf("expected a marked, commented tunnel_address line:\n%s", text)
	}
	cfg, err := config.Load(res.ConfigFile)
	if err != nil || cfg.TunnelAddress.IsValid() || cfg.Peers[0].AllowedIPs[0].String() != "10.50.0.0/16" {
		t.Fatalf("cfg=%+v err=%v", cfg, err)
	}
	if res.Address.IsValid() || res.Name != "peer" {
		t.Fatalf("result = %+v", res)
	}
}

func TestInitPeerKeepsItsKeyAcrossReruns(t *testing.T) {
	relay := mustRelay(t)
	dir := t.TempDir()
	o := PeerOptions{Dir: dir, Relay: "r:5040", RelayKey: relay.PublicKey.String(), PSK: relay.PSK}
	first, err := InitPeer(o)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InitPeer(o); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("rerun without force must refuse: %v", err)
	}
	// The admin has now assigned an address: rerun with -force. The public key,
	// which the admin already registered, must not change.
	o.Force, o.Address = true, "10.9.0.7/24"
	second, err := InitPeer(o)
	if err != nil {
		t.Fatal(err)
	}
	if !second.ReusedKey || !second.Overwrote || second.PublicKey != first.PublicKey {
		t.Fatalf("rerun result = %+v", second)
	}
	if cfg, _ := config.Load(second.ConfigFile); cfg.TunnelAddress.String() != "10.9.0.7/24" {
		t.Fatalf("address not applied on rerun: %v", cfg.TunnelAddress)
	}
}

func TestInitPeerRejectsBadInput(t *testing.T) {
	relay := mustRelay(t)
	good := PeerOptions{Relay: "r:5040", RelayKey: relay.PublicKey.String(), PSK: "secret-value"}
	for name, mod := range map[string]func(*PeerOptions){
		"no relay":        func(o *PeerOptions) { o.Relay = "" },
		"no relay key":    func(o *PeerOptions) { o.RelayKey = "" },
		"no psk":          func(o *PeerOptions) { o.PSK = "" },
		"bad relay":       func(o *PeerOptions) { o.Relay = "noport" },
		"short relay key": func(o *PeerOptions) { o.RelayKey = "abcd" },
		"non-hex key":     func(o *PeerOptions) { o.RelayKey = strings.Repeat("zz", 32) },
		"placeholder psk": func(o *PeerOptions) { o.PSK = "<same-secret-as-the-relay>" },
		"bad name":        func(o *PeerOptions) { o.Name = "../x" },
		"bad address":     func(o *PeerOptions) { o.Address = "10.9.0.2" },
		"ipv6 address":    func(o *PeerOptions) { o.Address = "fd00::2/64" },
		"bad subnet":      func(o *PeerOptions) { o.Subnet = "nope" },
	} {
		t.Run(name, func(t *testing.T) {
			o := good
			o.Dir = t.TempDir()
			mod(&o)
			if _, err := InitPeer(o); err == nil {
				t.Fatal("expected an error")
			}
			if entries, _ := os.ReadDir(o.Dir); len(entries) != 0 {
				t.Fatalf("a rejected init left files (a stray key would be orphaned): %v", entries)
			}
		})
	}
}

func TestInitPeerQuotesAHostilePSK(t *testing.T) {
	relay := mustRelay(t)
	for _, psk := range []string{"has: colon", "has # hash", "multi\nline: x\npeers: []", `quo"te`} {
		res, err := InitPeer(PeerOptions{Dir: t.TempDir(), Relay: "r:5040", RelayKey: relay.PublicKey.String(), PSK: psk})
		if err != nil {
			t.Fatalf("psk %q: %v", psk, err)
		}
		cfg, err := config.Load(res.ConfigFile)
		if err != nil || cfg.PreSharedKey != psk || len(cfg.Peers) != 1 {
			t.Fatalf("psk %q came back as %q (peers %d): %v", psk, cfg.PreSharedKey, len(cfg.Peers), err)
		}
	}
}

// The whole story: init relay, a peer inits, the admin registers it, the peer
// learns its address, and both configs agree.
func TestRelayAndPeerInitWorkTogether(t *testing.T) {
	relay := mustRelay(t)
	peer, err := InitPeer(PeerOptions{Dir: t.TempDir(), Name: "laptop", Relay: "relay.example.com:5040",
		RelayKey: relay.PublicKey.String(), PSK: relay.PSK})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := admin.Register(relay.ConfigFile, admin.RegisterOptions{Name: "laptop", PublicKeyHex: peer.PublicKey.String()})
	if err != nil {
		t.Fatalf("the relay config written by init must support peer add: %v", err)
	}
	if reg.IP.String() != "10.9.0.2" || reg.RelayPublicKey != relay.PublicKey || reg.PreSharedKey != relay.PSK {
		t.Fatalf("registration = %+v", reg)
	}
	again, err := InitPeer(PeerOptions{Dir: filepath.Dir(peer.ConfigFile), Name: "laptop", Relay: "relay.example.com:5040",
		RelayKey: relay.PublicKey.String(), PSK: relay.PSK, Address: reg.IP.String() + "/24", Force: true})
	if err != nil || again.PublicKey != peer.PublicKey {
		t.Fatalf("second init: %v %+v", err, again)
	}
}

func mustRelay(t *testing.T) *RelayResult {
	t.Helper()
	res, err := InitRelay(RelayOptions{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	return res
}
