// Package config loads and validates microtunnel's YAML configuration.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/jecklgamis/microtunnel/internal/proto"
)

// Limits and defaults.
const (
	MaxPeers          = 64
	MaxRoutesPerPeer  = 16
	MaxWorkerThreads  = 32
	DefaultWorkers    = 4
	DefaultPort       = 5040
	DefaultKeyFile    = "peer.key"
	DefaultKeepalive  = 25  // seconds
	DefaultRekeyAfter = 180 // seconds
	DefaultReconnect  = 30  // seconds
	DefaultExpiry     = 3 * DefaultRekeyAfter
	DefaultPrevGrace  = 90 // seconds
	DefaultHSTimeout  = 5  // seconds
	DefaultHSCooldown = 5  // seconds
)

// Peer is one entry of the `peers:` list.
type Peer struct {
	PublicKey [proto.PubKeyLen]byte
	// Host and Port are set only for peers we dial (those with an `endpoint:`);
	// inbound-only peers leave them empty.
	Host        string
	Port        int
	AllowedIPs  []Prefix
	hasEndpoint bool
	// Name is the file name (without extension) for peers loaded from
	// peers_dir; empty for peers listed inline in the main config.
	Name string
}

// HasEndpoint reports whether we initiate connections to this peer.
func (p *Peer) HasEndpoint() bool { return p.hasEndpoint }

// Config is the validated runtime configuration. All durations are seconds,
// matching the YAML keys.
type Config struct {
	Interface         string
	Address           string // optional local bind address; "" means 0.0.0.0
	Port              int
	PrivateKeyFile    string
	PreSharedKey      string
	HasPSK            bool
	Verbose           bool
	KeepaliveInterval int
	RekeyAfter        int
	ReconnectInterval int
	SessionExpiry     int
	PrevKeyGrace      int
	HandshakeTimeout  int
	HandshakeCooldown int
	WorkerThreads     int // resolved: never 0 after Load/Parse

	// Optional: let the program configure the TUN interface itself (needed on
	// macOS, where a utun device only exists once the process has opened it).
	// TunnelAddress is this node's overlay address, e.g. 10.9.0.2/24; its subnet
	// is routed through the interface automatically on macOS. TunnelRoutes lists
	// extra CIDRs to route through it. Unset means "configure it externally"
	// (e.g. scripts/create-tunnel.sh on Linux).
	TunnelAddress netip.Prefix
	TunnelRoutes  []netip.Prefix

	// PeersDir, when set, is a directory of one-peer-per-file YAML (*.yaml,
	// *.yml). Load merges those peers with the inline `peers:` list, and the
	// running daemon re-reads it when it changes. A relative path is resolved
	// against the config file's directory by Load.
	PeersDir string
	Peers    []Peer
}

type rawPeer struct {
	PublicKey  string   `yaml:"public_key"`
	Endpoint   string   `yaml:"endpoint"`
	AllowedIPs []string `yaml:"allowed_ips"`
}

type rawConfig struct {
	Interface         string    `yaml:"interface"`
	Address           string    `yaml:"address"`
	Port              *int      `yaml:"port"`
	PrivateKeyFile    *string   `yaml:"private_key_file"`
	PreSharedKey      *string   `yaml:"pre_shared_key"`
	Verbose           bool      `yaml:"verbose"`
	KeepaliveInterval *int      `yaml:"keepalive_interval"`
	RekeyAfter        *int      `yaml:"rekey_after"`
	ReconnectInterval *int      `yaml:"reconnect_interval"`
	SessionExpiry     *int      `yaml:"session_expiry"`
	PrevKeyGrace      *int      `yaml:"prev_key_grace"`
	HandshakeTimeout  *int      `yaml:"handshake_timeout"`
	HandshakeCooldown *int      `yaml:"handshake_cooldown"`
	WorkerThreads     *int      `yaml:"worker_threads"`
	TunnelAddress     string    `yaml:"tunnel_address"`
	TunnelRoutes      []string  `yaml:"tunnel_routes"`
	PeersDir          string    `yaml:"peers_dir"`
	Peers             []rawPeer `yaml:"peers"`
}

func orDefault(p *int, def int) int {
	if p == nil {
		return def
	}
	return *p
}

// Load reads and validates the YAML file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open config file: %w", err)
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if cfg.PeersDir != "" {
		if !filepath.IsAbs(cfg.PeersDir) {
			cfg.PeersDir = filepath.Join(filepath.Dir(path), cfg.PeersDir)
		}
		extra, err := LoadPeersDir(cfg.PeersDir)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		cfg.Peers = append(cfg.Peers, extra...)
		if err := checkPeers(cfg.Peers); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	return cfg, nil
}

// Parse decodes and validates YAML configuration bytes. Unknown keys are
// ignored, as they always were.
func Parse(data []byte) (*Config, error) {
	var raw rawConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&raw); err != nil && !errors.Is(err, io.EOF) { // io.EOF: empty document
		return nil, fmt.Errorf("YAML parse error: %w", err)
	}

	cfg := &Config{
		Interface:         raw.Interface,
		Address:           raw.Address,
		Port:              orDefault(raw.Port, DefaultPort),
		PrivateKeyFile:    DefaultKeyFile,
		Verbose:           raw.Verbose,
		KeepaliveInterval: orDefault(raw.KeepaliveInterval, DefaultKeepalive),
		RekeyAfter:        orDefault(raw.RekeyAfter, DefaultRekeyAfter),
		ReconnectInterval: orDefault(raw.ReconnectInterval, DefaultReconnect),
		SessionExpiry:     orDefault(raw.SessionExpiry, DefaultExpiry),
		PrevKeyGrace:      orDefault(raw.PrevKeyGrace, DefaultPrevGrace),
		HandshakeTimeout:  orDefault(raw.HandshakeTimeout, DefaultHSTimeout),
		HandshakeCooldown: orDefault(raw.HandshakeCooldown, DefaultHSCooldown),
		WorkerThreads:     orDefault(raw.WorkerThreads, 0),
		PeersDir:          raw.PeersDir,
	}
	if raw.PrivateKeyFile != nil {
		cfg.PrivateKeyFile = *raw.PrivateKeyFile
	}
	if raw.PreSharedKey != nil {
		if *raw.PreSharedKey == "" {
			return nil, errors.New("pre_shared_key must not be empty (omit it to disable PSK authentication)")
		}
		cfg.PreSharedKey = *raw.PreSharedKey
		cfg.HasPSK = true
	}

	if raw.TunnelAddress != "" {
		a, err := netip.ParsePrefix(raw.TunnelAddress)
		if err != nil || !a.Addr().Is4() {
			return nil, fmt.Errorf("tunnel_address must be an IPv4 address with prefix length, e.g. 10.9.0.2/24 (got %q)", raw.TunnelAddress)
		}
		cfg.TunnelAddress = a
	}
	if len(raw.TunnelRoutes) > 0 && raw.TunnelAddress == "" {
		return nil, errors.New("tunnel_routes requires tunnel_address")
	}
	for _, r := range raw.TunnelRoutes {
		pfx, err := netip.ParsePrefix(r)
		if err != nil || !pfx.Addr().Is4() {
			return nil, fmt.Errorf("invalid tunnel_routes entry %q (expected IPv4 CIDR)", r)
		}
		cfg.TunnelRoutes = append(cfg.TunnelRoutes, pfx.Masked())
	}

	if len(raw.Peers) > MaxPeers {
		return nil, fmt.Errorf("too many peers (max %d)", MaxPeers)
	}
	for i, rp := range raw.Peers {
		p, err := parsePeer(rp)
		if err != nil {
			return nil, fmt.Errorf("peers[%d]: %w", i, err)
		}
		cfg.Peers = append(cfg.Peers, p)
	}

	if err := checkPeers(cfg.Peers); err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if cfg.WorkerThreads == 0 {
		cfg.WorkerThreads = min(DefaultWorkers, runtime.NumCPU())
	}
	return cfg, nil
}

// checkPeers rejects too many peers and duplicate public keys.
func checkPeers(peers []Peer) error {
	if len(peers) > MaxPeers {
		return fmt.Errorf("too many peers (max %d)", MaxPeers)
	}
	seen := make(map[[proto.PubKeyLen]byte]bool, len(peers))
	for _, p := range peers {
		if seen[p.PublicKey] {
			return fmt.Errorf("duplicate peer public_key %s", proto.BytesToHex(p.PublicKey[:8])+"...")
		}
		seen[p.PublicKey] = true
	}
	return nil
}

func parsePeer(rp rawPeer) (Peer, error) {
	var p Peer
	if rp.PublicKey == "" {
		return p, errors.New("public_key is required")
	}
	pub, err := proto.HexToBytes(rp.PublicKey, proto.PubKeyLen)
	if err != nil {
		return p, fmt.Errorf("invalid public_key hex: %s", rp.PublicKey)
	}
	copy(p.PublicKey[:], pub)

	if rp.Endpoint != "" {
		i := strings.LastIndexByte(rp.Endpoint, ':')
		if i <= 0 {
			return p, fmt.Errorf("invalid endpoint (expected host:port): %s", rp.Endpoint)
		}
		port, err := strconv.Atoi(rp.Endpoint[i+1:])
		if err != nil || port <= 0 || port > 65535 {
			return p, fmt.Errorf("invalid port in endpoint: %s", rp.Endpoint)
		}
		p.Host = rp.Endpoint[:i]
		p.Port = port
		p.hasEndpoint = true
	}

	if len(rp.AllowedIPs) > MaxRoutesPerPeer {
		return p, fmt.Errorf("too many allowed_ips (max %d)", MaxRoutesPerPeer)
	}
	for _, s := range rp.AllowedIPs {
		pfx, err := ParseCIDR(s)
		if err != nil {
			return p, fmt.Errorf("invalid CIDR: %s", s)
		}
		p.AllowedIPs = append(p.AllowedIPs, pfx)
	}
	return p, nil
}

func (c *Config) validate() error {
	switch {
	case c.Interface == "":
		return errors.New("interface is required")
	case len(c.Interface) > 15:
		return fmt.Errorf("interface name %q is longer than 15 characters", c.Interface)
	case len(c.Peers) == 0 && c.PeersDir == "":
		return errors.New("at least one peer is required (or set peers_dir)")
	case c.Port <= 0 || c.Port > 65535:
		return fmt.Errorf("port must be 1-65535 (got %d)", c.Port)
	case c.KeepaliveInterval <= 0:
		return fmt.Errorf("keepalive_interval must be > 0 (got %d)", c.KeepaliveInterval)
	case c.RekeyAfter <= 0:
		return fmt.Errorf("rekey_after must be > 0 (got %d)", c.RekeyAfter)
	case c.ReconnectInterval <= 0:
		return fmt.Errorf("reconnect_interval must be > 0 (got %d)", c.ReconnectInterval)
	case c.SessionExpiry <= c.RekeyAfter:
		return fmt.Errorf("session_expiry (%d) must be greater than rekey_after (%d)", c.SessionExpiry, c.RekeyAfter)
	case c.PrevKeyGrace <= 0:
		return fmt.Errorf("prev_key_grace must be > 0 (got %d)", c.PrevKeyGrace)
	case c.HandshakeTimeout <= 0:
		return fmt.Errorf("handshake_timeout must be > 0 (got %d)", c.HandshakeTimeout)
	case c.HandshakeCooldown <= 0:
		return fmt.Errorf("handshake_cooldown must be > 0 (got %d)", c.HandshakeCooldown)
	case c.WorkerThreads < 0:
		return fmt.Errorf("worker_threads must be >= 0 (got %d)", c.WorkerThreads)
	case c.WorkerThreads > MaxWorkerThreads:
		return fmt.Errorf("worker_threads must be <= %d (got %d)", MaxWorkerThreads, c.WorkerThreads)
	}
	return nil
}
