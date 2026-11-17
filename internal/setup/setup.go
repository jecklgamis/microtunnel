// Package setup implements first-run configuration: `microtunnel init relay`
// and `microtunnel init peer`. Each turns the manual steps (generate a key,
// invent a pre-shared key, write a config, wire up the interface) into one
// call that leaves a complete, validated config behind.
//
// Safety rules shared by both:
//   - an existing config is never overwritten without Force;
//   - an existing private key is reused, never replaced or deleted;
//   - the written config is loaded back through config.Load before returning,
//     so a config that init produces is one the daemon accepts;
//   - files holding secrets are created mode 0600.
package setup

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/jecklgamis/microtunnel/internal/admin"
	"github.com/jecklgamis/microtunnel/internal/config"
	"github.com/jecklgamis/microtunnel/internal/proto"
)

// DefaultDir is where the packages keep configuration.
const DefaultDir = "/etc/microtunnel"

// DefaultName names the default instance: config /etc/microtunnel/microtunnel.yaml,
// key microtunnel.key, run by the `microtunnel` service. The same program is a
// relay or a peer; the config decides which.
const DefaultName = "microtunnel"

// DefaultConfigPath is the config the default service (and the CLI) uses.
const DefaultConfigPath = DefaultDir + "/" + DefaultName + ".yaml"

// Unit returns the systemd unit that runs the instance called name: the plain
// `microtunnel` service for the default instance, `microtunnel@<name>` otherwise.
func Unit(name string) string {
	if name == "" || name == DefaultName {
		return "microtunnel"
	}
	return "microtunnel@" + name
}

// AdminSocketFor is the default admin socket path for the instance called name.
// On Linux the packaged units create /run/microtunnel (default instance) or
// /run/microtunnel-<name> as a runtime directory; macOS has no /run, so it uses
// /var/run, and the daemon creates the directory itself.
func AdminSocketFor(name string) string { return adminSocketFor(runtime.GOOS, name) }

func adminSocketFor(goos, name string) string {
	base := "/run"
	if goos == "darwin" {
		base = "/var/run"
	}
	if name == "" || name == DefaultName {
		return base + "/microtunnel/admin.sock"
	}
	return base + "/microtunnel-" + name + "/admin.sock"
}

// peersDirFor is the peers directory beside the config: peers.d for the default
// instance, <name>.peers.d for a named one (so instances never share peers).
func peersDirFor(dir, name string) string {
	if name == DefaultName {
		return filepath.Join(dir, "peers.d")
	}
	return filepath.Join(dir, name+".peers.d")
}

// NoAdminSocket, as RelayOptions.AdminSocket, turns the admin API off.
const NoAdminSocket = "none"

// RelayOptions configures InitRelay.
type RelayOptions struct {
	Dir         string // config directory (default DefaultDir)
	Name        string // names the files <name>.key/.yaml (default DefaultName)
	Address     string // the relay's overlay address with prefix (default 10.9.0.1/24)
	Port        int    // UDP port (default 5040)
	Endpoint    string // public host:port, written as public_endpoint and used in the peer hint
	AdminSocket string // default AdminSocketFor(Name); NoAdminSocket disables
	Force       bool   // overwrite an existing relay.yaml (a new pre-shared key is generated)
}

// RelayResult describes what InitRelay produced.
type RelayResult struct {
	ConfigFile string
	KeyFile    string
	CrtFile    string
	PeersDir   string
	PublicKey  admin.Key
	PSK        string
	Address    netip.Prefix
	Port       int
	Endpoint   string
	ReusedKey  bool
	Overwrote  bool
}

// PeerOptions configures InitPeer.
type PeerOptions struct {
	Dir      string // config directory (default DefaultDir)
	Name     string // names the files: <name>.key, <name>.crt, <name>.yaml (default DefaultName)
	Relay    string // the relay's public host:port
	RelayKey string // the relay's public key (hex)
	PSK      string // the relay's pre-shared key
	Address  string // this peer's overlay address with prefix, if the admin has assigned one
	Subnet   string // overlay subnet when no Address is given (default 10.9.0.0/24)
	Force    bool   // overwrite an existing <name>.yaml
}

// PeerResult describes what InitPeer produced.
type PeerResult struct {
	Name       string
	ConfigFile string
	KeyFile    string
	CrtFile    string
	PublicKey  admin.Key
	Address    netip.Prefix // zero if none was given
	ReusedKey  bool
	Overwrote  bool
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// loadOrCreateKey reuses dir/base.key if present (never replacing it), else
// generates a key pair there.
func loadOrCreateKey(dir, base string) (key admin.Key, keyFile, crtFile string, reused bool, err error) {
	keyFile = filepath.Join(dir, base+".key")
	crtFile = filepath.Join(dir, base+".crt")
	if _, statErr := os.Stat(keyFile); statErr == nil {
		k, err := proto.LoadStaticKey(keyFile)
		if err != nil {
			return key, "", "", false, fmt.Errorf("existing key %s is unusable (it was not touched): %w", keyFile, err)
		}
		return admin.Key(proto.PubBytes(k)), keyFile, crtFile, true, nil
	}
	k, err := proto.GenerateKey()
	if err != nil {
		return key, "", "", false, err
	}
	if keyFile, crtFile, err = proto.WriteKeyPair(filepath.Join(dir, base), k); err != nil {
		return key, "", "", false, err
	}
	return admin.Key(proto.PubBytes(k)), keyFile, crtFile, false, nil
}

// writeSecretFile writes path atomically with mode 0600 (it may hold the
// pre-shared key).
func writeSecretFile(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func checkConfigFree(path string, force bool) (overwrote bool, err error) {
	if _, statErr := os.Stat(path); statErr == nil {
		if !force {
			return false, fmt.Errorf("%s already exists; refusing to overwrite it (pass -force to replace it; your private key is kept either way)", path)
		}
		return true, nil
	}
	return false, nil
}

// InitRelay creates the relay's key (if needed), a random pre-shared key, the
// peers directory and a complete relay.yaml.
func InitRelay(o RelayOptions) (*RelayResult, error) {
	if o.Dir == "" {
		o.Dir = DefaultDir
	}
	if o.Name == "" {
		o.Name = DefaultName
	}
	if !admin.ValidName(o.Name) {
		return nil, fmt.Errorf("invalid name %q (letters, digits, '.', '_', '-')", o.Name)
	}
	if o.Address == "" {
		o.Address = "10.9.0.1/24"
	}
	if o.Port == 0 {
		o.Port = config.DefaultPort
	}
	if o.AdminSocket == "" {
		o.AdminSocket = AdminSocketFor(o.Name)
	}
	addr, err := netip.ParsePrefix(o.Address)
	if err != nil || !addr.Addr().Is4() {
		return nil, fmt.Errorf("invalid address %q (want an IPv4 address with prefix length, e.g. 10.9.0.1/24)", o.Address)
	}
	if addr.Bits() > 30 {
		return nil, fmt.Errorf("address %s leaves no room for peers", o.Address)
	}
	if o.Port < 1 || o.Port > 65535 {
		return nil, fmt.Errorf("invalid port %d", o.Port)
	}
	if o.Endpoint != "" {
		if _, _, err := config.SplitHostPort(o.Endpoint); err != nil {
			return nil, err
		}
	}
	if o.AdminSocket != NoAdminSocket && !filepath.IsAbs(o.AdminSocket) {
		return nil, fmt.Errorf("admin socket %q must be an absolute path (or %q)", o.AdminSocket, NoAdminSocket)
	}

	dir, err := filepath.Abs(o.Dir)
	if err != nil {
		return nil, err
	}
	res := &RelayResult{
		ConfigFile: filepath.Join(dir, o.Name+".yaml"),
		PeersDir:   peersDirFor(dir, o.Name),
		Address:    addr, Port: o.Port, Endpoint: o.Endpoint,
	}
	if res.Overwrote, err = checkConfigFree(res.ConfigFile, o.Force); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(res.PeersDir, 0o750); err != nil {
		return nil, err
	}
	if res.PublicKey, res.KeyFile, res.CrtFile, res.ReusedKey, err = loadOrCreateKey(dir, o.Name); err != nil {
		return nil, err
	}
	if res.PSK, err = randomHex(32); err != nil {
		return nil, err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# Generated by `microtunnel init relay` on %s.\n", time.Now().UTC().Format(time.RFC3339))
	b.WriteString("# Holds the pre-shared key: keep this file private (mode 0600).\n")
	b.WriteString("interface: microtunnel0\n")
	fmt.Fprintf(&b, "port: %d\n", o.Port)
	fmt.Fprintf(&b, "private_key_file: %s\n", res.KeyFile)
	fmt.Fprintf(&b, "pre_shared_key: %s\n", res.PSK)
	fmt.Fprintf(&b, "tunnel_address: %s   # the program assigns this overlay address and route itself\n", addr)
	b.WriteString("verbose: false\n\n")
	b.WriteString("# One file per peer, managed by `microtunnel peer add|remove|list`.\n")
	fmt.Fprintf(&b, "peers_dir: %s\n", res.PeersDir)
	if o.AdminSocket != NoAdminSocket {
		b.WriteString("# Local admin API (unix socket, root only): `microtunnel peer ...` uses it automatically.\n")
		fmt.Fprintf(&b, "admin_socket: %s\n", o.AdminSocket)
	}
	if o.Endpoint != "" {
		b.WriteString("# The address peers dial; put into the configs generated for new peers.\n")
		fmt.Fprintf(&b, "public_endpoint: %s\n", o.Endpoint)
	}
	if err := writeSecretFile(res.ConfigFile, []byte(b.String())); err != nil {
		return nil, err
	}
	if _, err := config.Load(res.ConfigFile); err != nil {
		_ = os.Remove(res.ConfigFile)
		return nil, fmt.Errorf("internal error: the generated relay config does not load: %w", err)
	}
	return res, nil
}

// InitPeer creates this machine's key (if needed) and a complete peer config
// pointing at the relay.
func InitPeer(o PeerOptions) (*PeerResult, error) {
	if o.Dir == "" {
		o.Dir = DefaultDir
	}
	if o.Name == "" {
		o.Name = DefaultName
	}
	if !admin.ValidName(o.Name) {
		return nil, fmt.Errorf("invalid name %q (letters, digits, '.', '_', '-')", o.Name)
	}
	if o.Relay == "" || o.RelayKey == "" || o.PSK == "" {
		return nil, errors.New("the relay's address (-relay), public key (-relay-key) and pre-shared key (-psk, -psk-file or MICROTUNNEL_PSK) are all required")
	}
	if _, _, err := config.SplitHostPort(o.Relay); err != nil {
		return nil, fmt.Errorf("-relay: %w", err)
	}
	var relayKey admin.Key
	if err := relayKey.UnmarshalText([]byte(o.RelayKey)); err != nil {
		return nil, fmt.Errorf("-relay-key: %w", err)
	}
	if v := o.PSK; len(v) > 2 && v[0] == '<' && v[len(v)-1] == '>' {
		return nil, fmt.Errorf("the pre-shared key %s is a template placeholder; use the relay's real one", v)
	}

	var assigned netip.Addr
	var subnet netip.Prefix
	res := &PeerResult{Name: o.Name}
	if o.Address != "" {
		p, err := netip.ParsePrefix(o.Address)
		if err != nil || !p.Addr().Is4() {
			return nil, fmt.Errorf("invalid address %q (want an IPv4 address with prefix length, e.g. 10.9.0.2/24)", o.Address)
		}
		assigned, subnet, res.Address = p.Addr(), p.Masked(), p
	} else {
		s := o.Subnet
		if s == "" {
			s = "10.9.0.0/24"
		}
		p, err := netip.ParsePrefix(s)
		if err != nil || !p.Addr().Is4() {
			return nil, fmt.Errorf("invalid subnet %q (want an IPv4 CIDR, e.g. 10.9.0.0/24)", s)
		}
		subnet = p.Masked()
	}

	dir, err := filepath.Abs(o.Dir)
	if err != nil {
		return nil, err
	}
	res.ConfigFile = filepath.Join(dir, o.Name+".yaml")
	if res.Overwrote, err = checkConfigFree(res.ConfigFile, o.Force); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if res.PublicKey, res.KeyFile, res.CrtFile, res.ReusedKey, err = loadOrCreateKey(dir, o.Name); err != nil {
		return nil, err
	}

	iface := ""
	if runtime.GOOS == "darwin" {
		iface = "utun"
	}
	text := admin.SpokeConfig(&admin.Registration{
		Name: o.Name, IP: assigned, Subnet: subnet, RelayPublicKey: relayKey, Endpoint: o.Relay, PreSharedKey: o.PSK,
	}, admin.SpokeOptions{KeyFile: res.KeyFile, Generated: true, Interface: iface})
	text = strings.Replace(text, "generated by `microtunnel peer add`", "generated by `microtunnel init peer`", 1)
	if err := writeSecretFile(res.ConfigFile, []byte(text)); err != nil {
		return nil, err
	}
	if _, err := config.Load(res.ConfigFile); err != nil {
		_ = os.Remove(res.ConfigFile)
		return nil, fmt.Errorf("the generated peer config does not load (check the values you gave): %w", err)
	}
	return res, nil
}
