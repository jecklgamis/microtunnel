package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/jecklgamis/microtunnel/internal/config"
	"github.com/jecklgamis/microtunnel/internal/setup"
)

func initCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out, errb bytes.Buffer
	err := runInit(args, &out, &errb)
	return out.String(), err
}

var (
	pskRE    = regexp.MustCompile(`MICROTUNNEL_PSK=([0-9a-f]{64}) microtunnel init peer -relay (\S+) -relay-key ([0-9a-f]{64})`)
	pubKeyRE = regexp.MustCompile(`public key:\s+([0-9a-f]{64})`)
)

func TestInitRelayThenPeerThroughTheCLI(t *testing.T) {
	root := t.TempDir()
	relayDir, peerDir := filepath.Join(root, "relay"), filepath.Join(root, "peer")

	out, err := initCmd(t, "relay", "-dir", relayDir, "-endpoint", "relay.example.com:5040")
	if err != nil {
		t.Fatal(err)
	}
	m := pskRE.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("the peer hint (with the PSK in an env var, not argv) is missing:\n%s", out)
	}
	psk, endpoint, relayKey := m[1], m[2], m[3]
	if endpoint != "relay.example.com:5040" {
		t.Fatalf("hint endpoint %q", endpoint)
	}
	if strings.Contains(out, "--psk ") || strings.Contains(out, " -psk ") {
		t.Fatalf("the PSK must not be suggested as a command-line argument (it shows in `ps`):\n%s", out)
	}
	if !strings.Contains(out, "sudo microtunnel -c "+filepath.Join(relayDir, "microtunnel.yaml")) {
		t.Fatalf("a non-default dir should print the explicit -c command:\n%s", out)
	}

	// The peer side, taking the PSK from the environment as the hint says.
	t.Setenv("MICROTUNNEL_PSK", psk)
	out, err = initCmd(t, "peer", "-dir", peerDir, "-name", "laptop", "-relay", endpoint, "-relay-key", relayKey)
	if err != nil {
		t.Fatal(err)
	}
	pub := pubKeyRE.FindStringSubmatch(out)
	if pub == nil {
		t.Fatalf("peer public key not printed:\n%s", out)
	}
	if !strings.Contains(out, "microtunnel peer add laptop -public-key "+pub[1]) || !strings.Contains(out, "-address <assigned-ip>/24 -force") {
		t.Fatalf("next-step guidance missing:\n%s", out)
	}
	if strings.Contains(out, psk) {
		t.Fatalf("the PSK was echoed by init peer:\n%s", out)
	}

	// Rerun with the assigned address: key kept, config updated.
	out, err = initCmd(t, "peer", "-dir", peerDir, "-name", "laptop", "-relay", endpoint, "-relay-key", relayKey, "-address", "10.9.0.2/24", "-force")
	if err != nil {
		t.Fatal(err)
	}
	if again := pubKeyRE.FindStringSubmatch(out); again == nil || again[1] != pub[1] {
		t.Fatalf("the public key changed on rerun (the admin already registered the old one):\n%s", out)
	}
	if !strings.Contains(out, "-ip 10.9.0.2") || !strings.Contains(out, "existing key reused") {
		t.Fatalf("rerun output:\n%s", out)
	}
	cfg, err := config.Load(filepath.Join(peerDir, "laptop.yaml"))
	if err != nil || cfg.TunnelAddress.String() != "10.9.0.2/24" || cfg.PreSharedKey != psk {
		t.Fatalf("peer config: %v %+v", err, cfg)
	}
}

func TestInitPeerPSKSourcesAndPriority(t *testing.T) {
	relay := t.TempDir()
	out, _ := initCmd(t, "relay", "-dir", relay)
	m := pskRE.FindStringSubmatch(out)
	relayKey := m[3]
	psk := m[1]

	pskFile := filepath.Join(t.TempDir(), "psk")
	if err := os.WriteFile(pskFile, []byte(psk+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MICROTUNNEL_PSK", "")
	for name, args := range map[string][]string{
		"-psk":      {"-psk", psk},
		"-psk-file": {"-psk-file", pskFile},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if _, err := initCmd(t, append([]string{"peer", "-dir", dir, "-relay", "r:5040", "-relay-key", relayKey}, args...)...); err != nil {
				t.Fatal(err)
			}
			if cfg, err := config.Load(filepath.Join(dir, "microtunnel.yaml")); err != nil || cfg.PreSharedKey != psk {
				t.Fatalf("psk not applied (trailing newline in the file must be trimmed): %v %+v", err, cfg)
			}
		})
	}
	// An explicit flag beats the environment.
	t.Setenv("MICROTUNNEL_PSK", "from-the-environment")
	dir := t.TempDir()
	if _, err := initCmd(t, "peer", "-dir", dir, "-relay", "r:5040", "-relay-key", relayKey, "-psk", psk); err != nil {
		t.Fatal(err)
	}
	if cfg, _ := config.Load(filepath.Join(dir, "microtunnel.yaml")); cfg.PreSharedKey != psk {
		t.Fatalf("the environment overrode an explicit -psk")
	}
	if _, err := initCmd(t, "peer", "-dir", t.TempDir(), "-relay", "r:5040", "-relay-key", relayKey, "-psk-file", "/nonexistent"); err == nil {
		t.Fatal("a missing -psk-file must be an error")
	}
}

func TestInitRefusesToOverwriteAndPrintsHowToProceed(t *testing.T) {
	dir := t.TempDir()
	if _, err := initCmd(t, "relay", "-dir", dir); err != nil {
		t.Fatal(err)
	}
	if _, err := initCmd(t, "relay", "-dir", dir); err == nil || !strings.Contains(err.Error(), "-force") {
		t.Fatalf("err=%v", err)
	}
	out, err := initCmd(t, "relay", "-dir", dir, "-force")
	if err != nil || !strings.Contains(out, "NEW pre-shared key") {
		t.Fatalf("a forced re-init must warn that peers need the new key: %v\n%s", err, out)
	}
}

func TestInitUsageErrors(t *testing.T) {
	dir := t.TempDir()
	for name, args := range map[string][]string{
		"none":               {},
		"unknown":            {"frob"},
		"relay extra arg":    {"relay", "-dir", dir, "stray"},
		"peer no flags":      {"peer", "-dir", dir},
		"peer bad key":       {"peer", "-dir", dir, "-relay", "r:5040", "-relay-key", "xyz", "-psk", "p"},
		"relay start custom": {"relay", "-dir", dir, "-start"},
		"peer start custom":  {"peer", "-dir", dir, "-relay", "r:5040", "-relay-key", strings.Repeat("ab", 32), "-psk", "p", "-start"},
		"relay bad address":  {"relay", "-dir", dir, "-address", "nope"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("MICROTUNNEL_PSK", "")
			if _, err := initCmd(t, args...); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
	if out, err := initCmd(t, "help"); err != nil || !strings.Contains(out, "Usage:") {
		t.Fatalf("help: %v %q", err, out)
	}
}

func TestUnitNamesAndHints(t *testing.T) {
	if setup.Unit("microtunnel") != "microtunnel" || setup.Unit("") != "microtunnel" || setup.Unit("laptop") != "microtunnel@laptop" {
		t.Fatal("unit names")
	}
	if startHintOS("linux", "microtunnel", "/etc/microtunnel/microtunnel.yaml", "/etc/microtunnel", false) != "sudo systemctl enable --now microtunnel" {
		t.Fatal("default dir should print the systemctl command")
	}
	if cFlag(setup.DefaultConfigPath, "/etc/microtunnel") != "" || cFlag("/tmp/x/microtunnel.yaml", "/tmp/x") != " -c /tmp/x/microtunnel.yaml" {
		t.Fatal("cFlag")
	}
	if got := startHintOS("linux", "u", "/tmp/x/relay.yaml", "/tmp/x", false); got != "sudo microtunnel -c /tmp/x/relay.yaml" {
		t.Fatalf("custom dir hint = %q", got)
	}
	if got := startHintOS("darwin", "microtunnel", "/etc/microtunnel/microtunnel.yaml", "/etc/microtunnel", true); got != "sudo launchctl bootstrap system /Library/LaunchDaemons/io.github.jecklgamis.microtunnel.plist" {
		t.Fatalf("darwin hint with plist = %q", got)
	}
	if got := startHintOS("darwin", "home", "/etc/microtunnel/home.yaml", "/etc/microtunnel", false); !strings.Contains(got, "sudo microtunnel -c /etc/microtunnel/home.yaml") || !strings.Contains(got, "-start") {
		t.Fatalf("darwin hint without plist = %q", got)
	}
}

func TestInitRelayHonoursNameForTheFilesAndTheUnit(t *testing.T) {
	dir := t.TempDir()
	out, err := initCmd(t, "relay", "-dir", dir, "-name", "home")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"home.yaml", "home.key", "home.crt", "home.peers.d"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("missing %s: %v", f, err)
		}
	}
	cfg, err := config.Load(filepath.Join(dir, "home.yaml"))
	if err != nil || cfg.AdminSocket != setup.AdminSocketFor("home") {
		t.Fatalf("named instance must use its own runtime dir: %v %+v", err, cfg)
	}
	if !strings.Contains(out, "peer add <name> -public-key <hex> -c "+filepath.Join(dir, "home.yaml")) {
		t.Fatalf("the peer-add hint must say which config to use:\n%s", out)
	}
	// A second instance in the same directory does not collide with the first.
	if _, err := initCmd(t, "relay", "-dir", dir); err != nil {
		t.Fatalf("default instance beside a named one: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "microtunnel.yaml")); err != nil {
		t.Fatal(err)
	}
}
