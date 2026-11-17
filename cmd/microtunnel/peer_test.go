package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
