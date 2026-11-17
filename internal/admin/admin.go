// Package admin manages a relay's peer files (the directory named by
// `peers_dir`): adding a peer allocates it an overlay IP and writes its file,
// removing deletes the file. A running relay notices the change by itself (see
// peer.WatchPeers), so no restart or signal is needed.
//
// Adds are not serialised across processes: two `peer add` runs started at the
// same instant could pick the same free IP. Run them one at a time.
package admin

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jecklgamis/microtunnel/internal/config"
	"github.com/jecklgamis/microtunnel/internal/proto"
)

// Kind classifies an Error so callers (the admin API) can map it to a response.
type Kind int

const (
	KindInvalid  Kind = iota + 1 // the request itself is wrong
	KindConflict                 // valid, but clashes with existing state
	KindNotFound                 // names something that does not exist
)

// Error is a request error with a Kind. Errors without one are server-side
// problems (unreadable config, I/O failure).
type Error struct {
	Kind Kind
	Err  error
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

// KindOf returns the Kind of err, or 0 if it is not a request error.
func KindOf(err error) Kind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return 0
}

func invalid(format string, a ...any) error {
	return &Error{KindInvalid, fmt.Errorf(format, a...)}
}
func conflict(format string, a ...any) error {
	return &Error{KindConflict, fmt.Errorf(format, a...)}
}
func notFound(format string, a ...any) error {
	return &Error{KindNotFound, fmt.Errorf(format, a...)}
}

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ValidName reports whether name is usable as a peer name (it becomes the
// file name <name>.yaml in peers_dir, so no path separators or leading dots).
func ValidName(name string) bool { return nameRE.MatchString(name) }

// Key is a 32-byte X25519 public key; it marshals to and from hex, so JSON
// carries it as a string.
type Key [proto.PubKeyLen]byte

func (k Key) String() string { return proto.BytesToHex(k[:]) }

func (k Key) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

func (k *Key) UnmarshalText(b []byte) error {
	raw, err := proto.HexToBytes(string(b), proto.PubKeyLen)
	if err != nil {
		return fmt.Errorf("want %d hex characters: %w", 2*proto.PubKeyLen, err)
	}
	copy(k[:], raw)
	return nil
}

// RegisterOptions describes one registration with the relay.
type RegisterOptions struct {
	Name         string
	PublicKeyHex string // the peer's own public key
	IP           string // fixed overlay IP; empty allocates the lowest free one
	Subnet       string // overlay subnet; default: the relay's tunnel_address network
	Endpoint     string // relay's public host:port; default: public_endpoint, else a placeholder
}

// Registration is everything a newly registered peer needs to join.
type Registration struct {
	Name           string       `json:"name"`
	IP             netip.Addr   `json:"ip"`
	Subnet         netip.Prefix `json:"subnet"`
	PublicKey      Key          `json:"public_key"`
	RelayPublicKey Key          `json:"relay_public_key"`
	Endpoint       string       `json:"endpoint"`
	PreSharedKey   string       `json:"pre_shared_key,omitempty"`
	PeerFile       string       `json:"-"` // the file written into peers_dir
}

// Register adds a peer to the relay described by configPath: it validates the
// request, allocates (or checks) an overlay IP and writes the peer file
// atomically. A running relay picks the file up on its own.
func Register(configPath string, o RegisterOptions) (*Registration, error) {
	if !ValidName(o.Name) {
		return nil, invalid("invalid peer name %q (letters, digits, '.', '_', '-'; must start with a letter or digit; max 64)", o.Name)
	}
	cfg, err := loadRelay(configPath)
	if err != nil {
		return nil, err
	}
	file := filepath.Join(cfg.PeersDir, o.Name+".yaml")
	if _, err := os.Stat(file); err == nil {
		return nil, conflict("peer %q already exists (%s); remove it first", o.Name, file)
	}

	subnet, relayIP, err := overlay(cfg, o.Subnet)
	if err != nil {
		return nil, err
	}
	ip, err := pickIP(subnet, relayIP, cfg.Peers, o.IP)
	if err != nil {
		return nil, err
	}

	var pub Key
	if err := pub.UnmarshalText([]byte(o.PublicKeyHex)); err != nil {
		return nil, invalid("invalid public key: %v", err)
	}
	for _, p := range cfg.Peers {
		if p.PublicKey == [proto.PubKeyLen]byte(pub) {
			return nil, conflict("that public key is already registered (peer %q)", peerLabel(p))
		}
	}
	relayPub, err := relayPublicKey(cfg, configPath)
	if err != nil {
		return nil, err
	}

	endpoint := o.Endpoint
	if endpoint == "" {
		endpoint = cfg.PublicEndpoint
	}
	if endpoint == "" {
		endpoint = fmt.Sprintf("RELAY_HOST:%d", cfg.Port)
	} else if _, _, err := config.SplitHostPort(endpoint); err != nil {
		return nil, invalid("%v", err)
	}

	body := fmt.Sprintf("# Added by `microtunnel peer add` on %s\npublic_key: %s\nallowed_ips:\n  - %s/32\n",
		time.Now().UTC().Format(time.RFC3339), pub, ip)
	if err := writeAtomic(file, []byte(body)); err != nil {
		return nil, err
	}
	reg := &Registration{
		Name: o.Name, IP: ip, Subnet: subnet, PublicKey: pub, RelayPublicKey: Key(relayPub),
		Endpoint: endpoint, PeerFile: file,
	}
	if cfg.HasPSK {
		reg.PreSharedKey = cfg.PreSharedKey
	}
	return reg, nil
}

// SpokeOptions tunes SpokeConfig.
type SpokeOptions struct {
	KeyFile   string // value for private_key_file
	Generated bool   // only changes the comment on private_key_file
	Interface string // default "microtunnel0" (with a macOS hint); "utun" on macOS
}

// SpokeConfig renders the config file for the registered peer.
func SpokeConfig(reg *Registration, o SpokeOptions) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# microtunnel config for %s, generated by `microtunnel peer add`.\n", reg.Name)
	switch o.Interface {
	case "", "microtunnel0":
		b.WriteString("interface: microtunnel0   # on macOS use: interface: utun\n")
	default:
		fmt.Fprintf(&b, "interface: %s\n", o.Interface)
	}
	if o.Generated {
		fmt.Fprintf(&b, "private_key_file: %s     # keep this file secret; place it next to this config\n", o.KeyFile)
	} else {
		fmt.Fprintf(&b, "private_key_file: %s     # path to the private key whose public half you registered\n", o.KeyFile)
	}
	if reg.PreSharedKey != "" {
		fmt.Fprintf(&b, "pre_shared_key: %s\n", yamlScalar(reg.PreSharedKey))
	}
	if reg.IP.IsValid() {
		fmt.Fprintf(&b, "tunnel_address: %s/%d\n", reg.IP, reg.Subnet.Bits())
	} else {
		// No address assigned yet: leave a marked line to uncomment once the relay's admin has one.
		fmt.Fprintf(&b, "#tunnel_address: <assigned-overlay-ip>/%d   # set to the address the relay's admin assigns, then uncomment\n", reg.Subnet.Bits())
	}
	// Retry quickly: right after enrolment the relay may not have loaded this
	// peer yet, and the default 30s would make the first connection slow.
	b.WriteString("reconnect_interval: 5\n")
	fmt.Fprintf(&b, "peers:\n  - public_key: %s\n    endpoint: %s\n    allowed_ips:\n      - %s\n",
		reg.RelayPublicKey, yamlScalar(reg.Endpoint), reg.Subnet)
	return b.String()
}

// yamlScalar renders s as a single YAML scalar, quoting and escaping when
// needed, so a value containing ':', '#', quotes or newlines can neither break
// the generated config nor smuggle extra keys into it.
func yamlScalar(s string) string {
	b, err := yaml.Marshal(s)
	if err != nil {
		return strconv.Quote(s)
	}
	return strings.TrimSpace(string(b))
}

// AddOptions describes one `peer add` in file mode.
type AddOptions struct {
	ConfigPath string // the relay's config file
	Name       string

	// Exactly one of PublicKeyHex (the peer generated its own key; preferred,
	// since the private key never leaves its machine) or Generate (create a key
	// pair here, into KeyDir) must be set.
	PublicKeyHex string
	Generate     bool
	KeyDir       string // where Generate writes <name>.key/.crt/.yaml (default ".")

	IP       string
	Subnet   string
	Endpoint string
}

// AddResult is what Add created.
type AddResult struct {
	Name        string
	IP          netip.Addr
	PublicKey   Key
	PeerFile    string // the file written into peers_dir
	KeyFile     string // set when a key pair was generated
	CrtFile     string
	SpokeConfig string // ready-to-use config for the new peer
	SpokeFile   string // set when a key pair was generated: SpokeConfig saved beside the keys
}

// Add registers a new peer with the relay described by opts.ConfigPath, in file
// mode (editing peers_dir directly).
func Add(opts AddOptions) (*AddResult, error) {
	if !ValidName(opts.Name) {
		return nil, invalid("invalid peer name %q (letters, digits, '.', '_', '-'; must start with a letter or digit; max 64)", opts.Name)
	}
	if (opts.PublicKeyHex == "") == !opts.Generate {
		return nil, invalid("specify exactly one of a public key (the peer's own) or generate (create a key pair here)")
	}

	res := &AddResult{Name: opts.Name}
	pubHex := opts.PublicKeyHex
	var cleanup []string // files to remove if a later step fails
	fail := func(err error) (*AddResult, error) {
		for _, f := range cleanup {
			_ = os.Remove(f)
		}
		return nil, err
	}
	if opts.Generate {
		key, err := proto.GenerateKey()
		if err != nil {
			return nil, err
		}
		pub := proto.PubBytes(key)
		pubHex = proto.BytesToHex(pub[:])
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
		cleanup = append(cleanup, res.KeyFile, res.CrtFile)
	}

	reg, err := Register(opts.ConfigPath, RegisterOptions{
		Name: opts.Name, PublicKeyHex: pubHex, IP: opts.IP, Subnet: opts.Subnet, Endpoint: opts.Endpoint,
	})
	if err != nil {
		return fail(err)
	}
	cleanup = append(cleanup, reg.PeerFile)
	res.IP, res.PublicKey, res.PeerFile = reg.IP, reg.PublicKey, reg.PeerFile

	res.SpokeConfig = SpokeConfig(reg, SpokeOptions{KeyFile: opts.Name + ".key", Generated: opts.Generate})
	if opts.Generate {
		res.SpokeFile = filepath.Join(filepath.Dir(res.KeyFile), opts.Name+".yaml")
		if err := os.WriteFile(res.SpokeFile, []byte(res.SpokeConfig), 0o600); err != nil {
			return fail(err)
		}
	}
	return res, nil
}

// Remove deletes the named peer's file. The running relay drops its session
// and rejects it from then on.
func Remove(configPath, name string) error {
	if !ValidName(name) {
		return invalid("invalid peer name %q", name)
	}
	cfg, err := loadRelay(configPath)
	if err != nil {
		return err
	}
	file := filepath.Join(cfg.PeersDir, name+".yaml")
	if err := os.Remove(file); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return notFound("no such peer %q in %s (peers listed inline in the main config must be removed by editing it)", name, cfg.PeersDir)
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
			return subnet, netip.Addr{}, invalid("invalid subnet %q (want IPv4 CIDR, e.g. 10.9.0.0/24)", override)
		}
		subnet = p.Masked()
	case cfg.TunnelAddress.IsValid():
		subnet = cfg.TunnelAddress.Masked()
	default:
		return subnet, netip.Addr{}, invalid("cannot tell which subnet to allocate from: set tunnel_address in the relay config or pass a subnet")
	}
	if subnet.Bits() > 30 {
		return subnet, netip.Addr{}, invalid("subnet %s is too small", subnet)
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
			return ip, invalid("invalid IP %q", want)
		}
		if !subnet.Contains(ip) || addrU32(ip) < first || addrU32(ip) > last {
			return ip, invalid("%s is not a usable host address in %s", ip, subnet)
		}
		if by, taken := used[ip]; taken {
			return ip, conflict("%s is already used by %s", ip, by)
		}
		return ip, nil
	}
	for v := first; v <= last; v++ {
		if _, taken := used[u32Addr(v)]; !taken {
			return u32Addr(v), nil
		}
	}
	return netip.Addr{}, conflict("no free addresses left in %s", subnet)
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
