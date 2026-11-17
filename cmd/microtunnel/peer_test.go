package main

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jecklgamis/microtunnel/internal/adminapi"
	"github.com/jecklgamis/microtunnel/internal/peer"
	"github.com/jecklgamis/microtunnel/internal/proto"
)

func relayConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "peers.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	key, _ := proto.GenerateKey()
	if _, _, err := proto.WriteKeyPair(filepath.Join(dir, "relay"), key); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "relay.yaml")
	body := "interface: microtunnel0\nprivate_key_file: relay.key\ntunnel_address: 10.9.0.1/24\npeers_dir: peers.d\n"
	if err := os.WriteFile(cfg, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func peerCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out, errb bytes.Buffer
	err := runPeerCmd(args, &out, &errb)
	return out.String(), err
}

func TestPeerCLIAddListRemove(t *testing.T) {
	cfg := relayConfig(t)
	key, _ := proto.GenerateKey()
	pub := proto.PubBytes(key)

	out, err := peerCmd(t, "add", "laptop", "-c", cfg, "-public-key", proto.BytesToHex(pub[:]), "-endpoint", "relay.example.com:5040")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`Added peer "laptop": 10.9.0.2/32`, "tunnel_address: 10.9.0.2/24", "endpoint: relay.example.com:5040"} {
		if !strings.Contains(out, want) {
			t.Errorf("add output missing %q:\n%s", want, out)
		}
	}

	out, err = peerCmd(t, "list", "-c", cfg)
	if err != nil || !strings.Contains(out, "laptop") || !strings.Contains(out, "10.9.0.2/32") {
		t.Fatalf("list: %v\n%s", err, out)
	}

	if _, err = peerCmd(t, "remove", "laptop", "-c", cfg); err != nil {
		t.Fatal(err)
	}
	out, _ = peerCmd(t, "list", "-c", cfg)
	if strings.Contains(out, "laptop") {
		t.Fatalf("peer still listed after remove:\n%s", out)
	}
}

func TestPeerCLIGenerate(t *testing.T) {
	cfg := relayConfig(t)
	dir := filepath.Join(filepath.Dir(cfg), "out")
	out, err := peerCmd(t, "add", "phone", "-c", cfg, "-generate", "-key-dir", dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"phone.key", "phone.crt", "phone.yaml"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("missing %s: %v", f, err)
		}
	}
	if !strings.Contains(out, "delete the key from here") {
		t.Fatalf("output should tell the operator to move the key:\n%s", out)
	}
}

func TestPeerCLIUsageErrors(t *testing.T) {
	cfg := relayConfig(t)
	for name, args := range map[string][]string{
		"no subcommand":     {},
		"unknown":           {"frobnicate"},
		"add without name":  {"add", "-c", cfg},
		"flags before name": {"add", "-generate", "laptop", "-c", cfg},
		"extra arg":         {"remove", "a", "b", "-c", cfg},
		"add without key":   {"add", "x", "-c", cfg},
		"unknown flag":      {"add", "x", "-c", cfg, "-nope"},
		"flag on remove":    {"remove", "x", "-c", cfg, "-generate"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := peerCmd(t, args...); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
	if out, err := peerCmd(t, "help"); err != nil || !strings.Contains(out, "Usage:") {
		t.Fatalf("help: %v %q", err, out)
	}
}

func TestKeygen(t *testing.T) {
	dir := t.TempDir()
	var out, errb bytes.Buffer
	if err := runKeygen([]string{"node", "-dir", dir}, &out, &errb); err != nil {
		t.Fatal(err)
	}
	key, err := proto.LoadStaticKey(filepath.Join(dir, "node.key"))
	if err != nil {
		t.Fatal(err)
	}
	pub := proto.PubBytes(key)
	if !strings.Contains(out.String(), "public key: "+proto.BytesToHex(pub[:])) {
		t.Fatalf("output does not print the public key:\n%s", out.String())
	}
	// Refuses to clobber, and rejects bad usage.
	if err := runKeygen([]string{"node", "-dir", dir}, &out, &errb); err == nil {
		t.Fatal("second keygen must not overwrite")
	}
	for _, args := range [][]string{{}, {"-dir", dir}, {"../x", "-dir", dir}, {"a", "b"}} {
		if err := runKeygen(args, &out, &errb); err == nil {
			t.Fatalf("args %v should fail", args)
		}
	}
}

// --- API mode ---------------------------------------------------------------

type stubNode struct {
	mu       sync.Mutex
	reloads  int
	sessions []peer.SessionInfo
}

func (n *stubNode) ReloadFrom(string) (peer.ReloadResult, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.reloads++
	return peer.ReloadResult{}, nil
}

func (n *stubNode) Sessions() []peer.SessionInfo {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]peer.SessionInfo(nil), n.sessions...)
}

// relayWithAPI is relayConfig plus a running admin API on a unix socket.
func relayWithAPI(t *testing.T) (cfg, sock string, node *stubNode) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "mtcli")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Mkdir(filepath.Join(dir, "peers.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	key, _ := proto.GenerateKey()
	if _, _, err := proto.WriteKeyPair(filepath.Join(dir, "relay"), key); err != nil {
		t.Fatal(err)
	}
	sock = filepath.Join(dir, "a.sock")
	cfg = filepath.Join(dir, "relay.yaml")
	body := "interface: mt0\nprivate_key_file: relay.key\npre_shared_key: psk\ntunnel_address: 10.9.0.1/24\n" +
		"peers_dir: peers.d\nadmin_socket: a.sock\npublic_endpoint: relay.example.com:5040\n"
	if err := os.WriteFile(cfg, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	ln, err := adminapi.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	node = &stubNode{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = adminapi.New(node, cfg, "test").Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); <-done })
	return cfg, sock, node
}

func TestPeerCLIAutoUsesAdminSocketFromConfig(t *testing.T) {
	cfg, _, node := relayWithAPI(t)
	key, _ := proto.GenerateKey()
	pub := proto.PubBytes(key)

	// Only -c is given: the config names admin_socket, so the API is used.
	out, err := peerCmd(t, "add", "laptop", "-c", cfg, "-public-key", proto.BytesToHex(pub[:]))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "registered through the admin socket") || !strings.Contains(out, "endpoint: relay.example.com:5040") {
		t.Fatalf("add output:\n%s", out)
	}
	if node.reloads != 1 {
		t.Fatalf("relay reloads=%d, want 1 (applied immediately)", node.reloads)
	}

	node.mu.Lock()
	node.sessions = []peer.SessionInfo{{PublicKey: pub, Addr: netip.MustParseAddrPort("198.51.100.9:5040"),
		LastSeen: time.Now(), RxBytes: 2048, TxBytes: 12}}
	node.mu.Unlock()
	out, err = peerCmd(t, "list", "-c", cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"laptop", "connected", "198.51.100.9:5040", "2.0KiB", "12B"} {
		if !strings.Contains(out, want) {
			t.Errorf("live list missing %q:\n%s", want, out)
		}
	}

	if out, err = peerCmd(t, "remove", "laptop", "-c", cfg); err != nil || !strings.Contains(out, "dropped immediately") {
		t.Fatalf("remove: %v\n%s", err, out)
	}
}

func TestPeerCLIExplicitSocketNeedsNoConfig(t *testing.T) {
	_, sock, _ := relayWithAPI(t)
	key, _ := proto.GenerateKey()
	pub := proto.PubBytes(key)
	// No -c at all (and the default peer.yaml does not exist): -socket is enough,
	// which is how a remote relay is managed through a forwarded socket.
	if _, err := peerCmd(t, "add", "phone", "-socket", sock, "-public-key", proto.BytesToHex(pub[:])); err != nil {
		t.Fatal(err)
	}
	out, err := peerCmd(t, "list", "-socket", sock)
	if err != nil || !strings.Contains(out, "phone") || !strings.Contains(out, "offline") {
		t.Fatalf("list: %v\n%s", err, out)
	}
	if _, err := peerCmd(t, "list", "-socket", "/tmp/definitely-not-here.sock"); err == nil {
		t.Fatal("an unreachable explicit -socket must fail, not fall back to files")
	}
}

func TestPeerCLIGenerateViaAPIKeepsPrivateKeyLocal(t *testing.T) {
	cfg, _, _ := relayWithAPI(t)
	dir := filepath.Join(filepath.Dir(cfg), "bundle")
	out, err := peerCmd(t, "add", "tablet", "-c", cfg, "-generate", "-key-dir", dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "generated") {
		t.Fatalf("output:\n%s", out)
	}
	for _, f := range []string{"tablet.key", "tablet.crt", "tablet.yaml"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("missing %s", f)
		}
	}
	// The relay's peer file holds only the public key.
	peerFile, _ := os.ReadFile(filepath.Join(filepath.Dir(cfg), "peers.d", "tablet.yaml"))
	priv, _ := os.ReadFile(filepath.Join(dir, "tablet.key"))
	if strings.Contains(string(peerFile), "PRIVATE") || len(priv) == 0 || strings.Contains(string(peerFile), strings.TrimSpace(string(priv))) {
		t.Fatal("private key material reached the relay")
	}

	// A rejected registration must not leave a stray key pair behind.
	dir2 := filepath.Join(filepath.Dir(cfg), "bundle2")
	if _, err := peerCmd(t, "add", "tablet", "-c", cfg, "-generate", "-key-dir", dir2); err == nil {
		t.Fatal("duplicate name must be rejected")
	}
	if entries, _ := os.ReadDir(dir2); len(entries) != 0 {
		t.Fatalf("rejected add left key files: %v", entries)
	}
}

func TestPeerCLIFallsBackToFilesWhenSocketIsDown(t *testing.T) {
	cfg := relayConfig(t) // no admin_socket in this config at all
	key, _ := proto.GenerateKey()
	pub := proto.PubBytes(key)
	out, err := peerCmd(t, "add", "x", "-c", cfg, "-public-key", proto.BytesToHex(pub[:]))
	if err != nil || !strings.Contains(out, "wrote") {
		t.Fatalf("file mode expected: %v\n%s", err, out)
	}
}
