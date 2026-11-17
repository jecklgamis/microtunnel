// Package admin manages a relay's peer files (the directory named by
// `peers_dir`): adding a peer allocates it an overlay IP and writes its file,
// removing deletes the file. A running relay notices the change by itself (see
// peer.WatchPeers), so no restart or signal is needed.
//
// Adds are not serialised across processes: two `peer add` runs started at the
// same instant could pick the same free IP. Run them one at a time.
package admin

import (
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/jecklgamis/microtunnel/internal/config"
	"github.com/jecklgamis/microtunnel/internal/proto"
)

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ValidName reports whether name is usable as a peer name (it becomes the
// file name <name>.yaml in peers_dir, so no path separators or leading dots).
func ValidName(name string) bool { return nameRE.MatchString(name) }

// AddOptions describes one `peer add`.
type AddOptions struct {
	ConfigPath string // the relay's config file
	Name       string

	// Exactly one of PublicKeyHex (the peer generated its own key; preferred,
	// since the private key never leaves its machine) or Generate (create a key
	// pair here, into KeyDir) must be set.
	PublicKeyHex string
	Generate     bool
	KeyDir       string // where Generate writes <name>.key/.crt/.yaml (default ".")

	IP       string // fixed overlay IP; empty allocates the lowest free one
	Subnet   string // overlay subnet; default: the relay's tunnel_address network
	Endpoint string // relay's public host:port, written into the spoke config
}

// AddResult is what Add created.
type AddResult struct {
	Name        string
	IP          netip.Addr
	PublicKey   [proto.PubKeyLen]byte
	PeerFile    string // the file written into peers_dir
	KeyFile     string // set when a key pair was generated
	CrtFile     string
	SpokeConfig string // ready-to-use config for the new peer
	SpokeFile   string // set when a key pair was generated: SpokeConfig saved beside the keys
}

// Add registers a new peer with the relay described by opts.ConfigPath.
func Add(opts AddOptions) (*AddResult, error) {
	if !ValidName(opts.Name) {
		return nil, fmt.Errorf("invalid peer name %q (letters, digits, '.', '_', '-'; must start with a letter or digit; max 64)", opts.Name)
	}
	if (opts.PublicKeyHex == "") == !opts.Generate {
		return nil, errors.New("specify exactly one of a public key (the peer's own) or generate (create a key pair here)")
	}
	cfg, err := loadRelay(opts.ConfigPath)
	if err != nil {
		return nil, err
	}
	file := filepath.Join(cfg.PeersDir, opts.Name+".yaml")
	if _, err := os.Stat(file); err == nil {
		return nil, fmt.Errorf("peer %q already exists (%s); remove it first", opts.Name, file)
	}

	subnet, relayIP, err := overlay(cfg, opts.Subnet)
	if err != nil {
		return nil, err
	}
	ip, err := pickIP(subnet, relayIP, cfg.Peers, opts.IP)
	if err != nil {
		return nil, err
	}

	res := &AddResult{Name: opts.Name, IP: ip, PeerFile: file}
	var key *ecdh.PrivateKey
	if opts.Generate {
		if key, err = proto.GenerateKey(); err != nil {
			return nil, err
		}
		res.PublicKey = proto.PubBytes(key)
	} else {
		b, err := proto.HexToBytes(opts.PublicKeyHex, proto.PubKeyLen)
		if err != nil {
			return nil, fmt.Errorf("invalid public key (want %d hex characters): %w", 2*proto.PubKeyLen, err)
		}
		copy(res.PublicKey[:], b)
	}
	for _, p := range cfg.Peers {
		if p.PublicKey == res.PublicKey {
			return nil, fmt.Errorf("that public key is already registered (peer %q)", peerLabel(p))
		}
	}

	relayPub, err := relayPublicKey(cfg, opts.ConfigPath)
	if err != nil {
		return nil, err
	}

	// Everything that can fail has been checked; now write. Keys first, so a
	// failure leaves nothing registered with the relay.
	spokeKeyName := opts.Name + ".key"
	if opts.Generate {
		dir := opts.KeyDir
		if dir == "" {
			dir = "."
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
		if res.KeyFile, res.CrtFile, err = proto.WriteKeyPair(filepath.Join(dir, opts.Name), key); err != nil {
			return nil, err
		}
	}
	res.SpokeConfig = spokeConfig(cfg, opts, subnet, ip, relayPub, spokeKeyName)
	if opts.Generate {
		res.SpokeFile = filepath.Join(filepath.Dir(res.KeyFile), opts.Name+".yaml")
		if err := os.WriteFile(res.SpokeFile, []byte(res.SpokeConfig), 0o600); err != nil {
			_ = os.Remove(res.KeyFile)
			_ = os.Remove(res.CrtFile)
			return nil, err
		}
	}
	body := fmt.Sprintf("# Added by `microtunnel peer add` on %s\npublic_key: %s\nallowed_ips:\n  - %s/32\n",
		time.Now().UTC().Format(time.RFC3339), proto.BytesToHex(res.PublicKey[:]), ip)
	if err := writeAtomic(file, []byte(body)); err != nil {
		if opts.Generate {
			_ = os.Remove(res.KeyFile)
			_ = os.Remove(res.CrtFile)
			_ = os.Remove(res.SpokeFile)
		}
		return nil, err
	}
	return res, nil
}

// Remove deletes the named peer's file. The running relay drops its session
// and rejects it from then on.
func Remove(configPath, name string) error {
	if !ValidName(name) {
		return fmt.Errorf("invalid peer name %q", name)
	}
	cfg, err := loadRelay(configPath)
	if err != nil {
		return err
	}
	file := filepath.Join(cfg.PeersDir, name+".yaml")
	if err := os.Remove(file); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("no such peer %q in %s (peers listed inline in the main config must be removed by editing it)", name, cfg.PeersDir)
		}
		return err
	}
	return nil
}

// Entry is one configured peer as shown by List.
type Entry struct {
	Name       string // "" for peers listed inline in the main config
	PublicKey  [proto.PubKeyLen]byte
	AllowedIPs []string
	Endpoint   string
	Inline     bool
}

// List returns every configured peer: inline ones first, then peers_dir.
func List(configPath string) ([]Entry, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, p := range cfg.Peers {
		e := Entry{Name: p.Name, PublicKey: p.PublicKey, Inline: p.Name == ""}
		for _, r := range p.AllowedIPs {
			e.AllowedIPs = append(e.AllowedIPs, r.String())
		}
		if p.HasEndpoint() {
			e.Endpoint = fmt.Sprintf("%s:%d", p.Host, p.Port)
		}
		out = append(out, e)
	}
	return out, nil
}

func peerLabel(p config.Peer) string {
	if p.Name != "" {
		return p.Name
	}
	return "inline in the main config"
}

func loadRelay(path string) (*config.Config, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	if cfg.PeersDir == "" {
		return nil, fmt.Errorf("%s has no peers_dir; add e.g. `peers_dir: peers.d` and create the directory", path)
	}
	return cfg, nil
}

// overlay returns the overlay subnet and the relay's own address in it.
func overlay(cfg *config.Config, override string) (netip.Prefix, netip.Addr, error) {
	var subnet netip.Prefix
	switch {
	case override != "":
		p, err := netip.ParsePrefix(override)
		if err != nil || !p.Addr().Is4() {
			return subnet, netip.Addr{}, fmt.Errorf("invalid subnet %q (want IPv4 CIDR, e.g. 10.9.0.0/24)", override)
		}
		subnet = p.Masked()
	case cfg.TunnelAddress.IsValid():
		subnet = cfg.TunnelAddress.Masked()
	default:
		return subnet, netip.Addr{}, errors.New("cannot tell which subnet to allocate from: set tunnel_address in the relay config or pass a subnet")
	}
	if subnet.Bits() > 30 {
		return subnet, netip.Addr{}, fmt.Errorf("subnet %s is too small", subnet)
	}
	relayIP := subnet.Addr().Next() // convention: the first host is the relay
	if cfg.TunnelAddress.IsValid() && subnet.Contains(cfg.TunnelAddress.Addr()) {
		relayIP = cfg.TunnelAddress.Addr()
	}
	return subnet, relayIP, nil
}

func addrU32(a netip.Addr) uint32 { b := a.As4(); return binary.BigEndian.Uint32(b[:]) }
func u32Addr(v uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

// pickIP validates a requested overlay IP, or allocates the lowest free host
// address in subnet. Taken means: the relay's own address, or the exact /32 of
// an existing peer.
func pickIP(subnet netip.Prefix, relayIP netip.Addr, peers []config.Peer, want string) (netip.Addr, error) {
	used := map[netip.Addr]string{relayIP: "the relay's own address"}
	for _, p := range peers {
		for _, r := range p.AllowedIPs {
			if r.Len == 32 {
				used[u32Addr(r.Network)] = fmt.Sprintf("peer %q", peerLabel(p))
			}
		}
	}
	first := addrU32(subnet.Addr()) + 1
	last := addrU32(subnet.Addr()) | (^uint32(0) >> subnet.Bits()) - 1 // exclude the broadcast address

	if want != "" {
		ip, err := netip.ParseAddr(want)
		if err != nil || !ip.Is4() {
			return ip, fmt.Errorf("invalid IP %q", want)
		}
		if !subnet.Contains(ip) || addrU32(ip) < first || addrU32(ip) > last {
			return ip, fmt.Errorf("%s is not a usable host address in %s", ip, subnet)
		}
		if by, taken := used[ip]; taken {
			return ip, fmt.Errorf("%s is already used by %s", ip, by)
		}
		return ip, nil
	}
	for v := first; v <= last; v++ {
		if _, taken := used[u32Addr(v)]; !taken {
			return u32Addr(v), nil
		}
	}
	return netip.Addr{}, fmt.Errorf("no free addresses left in %s", subnet)
}

// relayPublicKey derives the relay's public key from its private key file,
// which may be given relative to the working directory or to the config file.
func relayPublicKey(cfg *config.Config, configPath string) ([proto.PubKeyLen]byte, error) {
	path := cfg.PrivateKeyFile
	if !filepath.IsAbs(path) {
		if _, err := os.Stat(path); err != nil {
			if alt := filepath.Join(filepath.Dir(configPath), path); fileExists(alt) {
				path = alt
			}
		}
	}
	key, err := proto.LoadStaticKey(path)
	if err != nil {
		return [proto.PubKeyLen]byte{}, fmt.Errorf("cannot read the relay's own key to build the spoke config: %w", err)
	}
	return proto.PubBytes(key), nil
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func spokeConfig(cfg *config.Config, opts AddOptions, subnet netip.Prefix, ip netip.Addr,
	relayPub [proto.PubKeyLen]byte, keyFile string) string {
	endpoint := opts.Endpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("RELAY_HOST:%d", cfg.Port)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# microtunnel config for %s, generated by `microtunnel peer add`.\n", opts.Name)
	fmt.Fprintf(&b, "interface: microtunnel0   # on macOS use: interface: utun\n")
	if opts.Generate {
		fmt.Fprintf(&b, "private_key_file: %s     # keep this file secret; place it next to this config\n", keyFile)
	} else {
		fmt.Fprintf(&b, "private_key_file: %s     # path to the private key whose public half you registered\n", keyFile)
	}
	if cfg.HasPSK {
		fmt.Fprintf(&b, "pre_shared_key: %s\n", cfg.PreSharedKey)
	}
	fmt.Fprintf(&b, "tunnel_address: %s/%d\n", ip, subnet.Bits())
	// Retry quickly: right after enrolment the relay may not have loaded this
	// peer yet, and the default 30s would make the first connection slow.
	fmt.Fprintf(&b, "reconnect_interval: 5\n")
	fmt.Fprintf(&b, "peers:\n  - public_key: %s\n    endpoint: %s\n    allowed_ips:\n      - %s\n",
		proto.BytesToHex(relayPub[:]), endpoint, subnet)
	return b.String()
}

// writeAtomic writes data to path via a temp file and rename, so a watching
// relay never sees a partially written peer file. The temp name has no .yaml
// suffix, which the loader ignores.
func writeAtomic(path string, data []byte) error {
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp")
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
