package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/jecklgamis/microtunnel/internal/admin"
	"github.com/jecklgamis/microtunnel/internal/adminapi"
	"github.com/jecklgamis/microtunnel/internal/config"
	"github.com/jecklgamis/microtunnel/internal/proto"
	"github.com/jecklgamis/microtunnel/internal/setup"
)

const peerUsage = `Usage:
  microtunnel peer add <name> [flags]     register a peer with a relay
  microtunnel peer remove <name> [flags]  unregister a peer
  microtunnel peer list [flags]           show peers (with live state when the relay is reachable)

Where it acts:
  -socket <path>     the relay's admin socket: the relay allocates the IP, applies the
                     change immediately and reports live session state. Reach a remote
                     relay by forwarding its socket over SSH:
                       ssh -L /tmp/mt.sock:/run/microtunnel/admin.sock relay
  -c <file>          relay config file (default /etc/microtunnel/microtunnel.yaml). If it sets admin_socket and the
                     socket is reachable that is used; otherwise the CLI edits peers_dir
                     directly (a running relay loads the change within a second or two).

peer add:
  -public-key <hex>  the peer's own public key (recommended: its private key never leaves it)
  -generate          instead, create a key pair for the peer here
  -key-dir <dir>     where -generate writes <name>.key, .crt and .yaml (default .)
  -ip <addr>         fixed overlay IP (default: the lowest free address)
  -subnet <cidr>     overlay subnet (default: the relay's tunnel_address network)
  -endpoint <h:p>    the relay's reachable host:port for the peer's config
                     (default: the relay's public_endpoint)
`

// runPeerCmd implements `microtunnel peer ...`; args exclude "peer".
func runPeerCmd(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, peerUsage)
		return errors.New("missing peer subcommand")
	}
	sub, rest := args[0], args[1:]

	fs := flag.NewFlagSet("peer "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, peerUsage) }
	configPath := fs.String("c", setup.DefaultConfigPath, "relay config file")
	socket := fs.String("socket", "", "relay admin socket")

	var (
		pubHex, keyDir, ip, subnet, endpoint string
		generate                             bool
	)
	if sub == "add" {
		fs.StringVar(&pubHex, "public-key", "", "")
		fs.BoolVar(&generate, "generate", false, "")
		fs.StringVar(&keyDir, "key-dir", ".", "")
		fs.StringVar(&ip, "ip", "", "")
		fs.StringVar(&subnet, "subnet", "", "")
		fs.StringVar(&endpoint, "endpoint", "", "")
	}

	// add/remove take the name first: `peer add laptop -generate`.
	var name string
	switch sub {
	case "add", "remove":
		if len(rest) == 0 || strings.HasPrefix(rest[0], "-") {
			fs.Usage()
			return fmt.Errorf("peer %s needs a name", sub)
		}
		name, rest = rest[0], rest[1:]
	case "list":
	case "help", "-h", "--help":
		fmt.Fprint(stdout, peerUsage)
		return nil
	default:
		fs.Usage()
		return fmt.Errorf("unknown peer subcommand %q", sub)
	}
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q (put flags after the name)", fs.Arg(0))
	}

	client, via := pickBackend(*socket, *configPath)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	switch sub {
	case "add":
		o := addOpts{name: name, pubHex: pubHex, generate: generate, keyDir: keyDir, ip: ip, subnet: subnet, endpoint: endpoint}
		var out *addOutcome
		var err error
		if client != nil {
			out, err = addViaAPI(ctx, client, o)
		} else {
			out, err = addViaFiles(*configPath, o)
		}
		if err != nil {
			return err
		}
		printAdded(stdout, out, via)
	case "remove":
		if client != nil {
			if err := client.Remove(ctx, name); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "Removed peer %q; its session was dropped immediately\n", name)
			return nil
		}
		if err := admin.Remove(*configPath, name); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Removed peer %q; a running relay drops its session within a second or two\n", name)
	case "list":
		if client != nil {
			peers, err := client.List(ctx)
			if err != nil {
				return err
			}
			printLive(stdout, peers)
			return nil
		}
		entries, err := admin.List(*configPath)
		if err != nil {
			return err
		}
		printConfigured(stdout, entries)
	}
	return nil
}

// pickBackend returns the admin API client to use, and a description of where
// changes go. A nil client means "edit peers_dir directly". An explicit
// -socket is always used (and fails loudly if unreachable); otherwise the
// config's admin_socket is used when its socket is reachable.
func pickBackend(socket, configPath string) (*adminapi.Client, string) {
	if socket != "" {
		return adminapi.NewClient(socket), "admin socket " + socket
	}
	if cfg, err := config.Load(configPath); err == nil && cfg.AdminSocket != "" && socketReachable(cfg.AdminSocket) {
		return adminapi.NewClient(cfg.AdminSocket), "admin socket " + cfg.AdminSocket
	}
	return nil, ""
}

func socketReachable(path string) bool {
	c, err := net.DialTimeout("unix", path, 500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

type addOpts struct {
	name, pubHex, keyDir, ip, subnet, endpoint string
	generate                                   bool
}

// addOutcome is what an add produced, whichever backend did it.
type addOutcome struct {
	name, ip, peerFile, spokeConfig string
	publicKey                       admin.Key
	keyFile, crtFile, spokeFile     string
}

func addViaFiles(configPath string, o addOpts) (*addOutcome, error) {
	res, err := admin.Add(admin.AddOptions{
		ConfigPath: configPath, Name: o.name, PublicKeyHex: o.pubHex, Generate: o.generate,
		KeyDir: o.keyDir, IP: o.ip, Subnet: o.subnet, Endpoint: o.endpoint,
	})
	if err != nil {
		return nil, err
	}
	return &addOutcome{
		name: res.Name, ip: res.IP.String(), peerFile: res.PeerFile, spokeConfig: res.SpokeConfig,
		publicKey: res.PublicKey, keyFile: res.KeyFile, crtFile: res.CrtFile, spokeFile: res.SpokeFile,
	}, nil
}

// addViaAPI registers through the relay's admin socket. -generate still creates
// the key pair locally (here, not on the relay): only the public key is sent.
func addViaAPI(ctx context.Context, c *adminapi.Client, o addOpts) (*addOutcome, error) {
	if !admin.ValidName(o.name) {
		return nil, fmt.Errorf("invalid peer name %q (letters, digits, '.', '_', '-')", o.name)
	}
	if (o.pubHex == "") == !o.generate {
		return nil, errors.New("specify exactly one of -public-key or -generate")
	}
	out := &addOutcome{name: o.name}
	pubHex := o.pubHex
	var made []string
	if o.generate {
		key, err := proto.GenerateKey()
		if err != nil {
			return nil, err
		}
		pub := proto.PubBytes(key)
		pubHex = proto.BytesToHex(pub[:])
		if err := os.MkdirAll(o.keyDir, 0o755); err != nil {
			return nil, err
		}
		if out.keyFile, out.crtFile, err = proto.WriteKeyPair(filepath.Join(o.keyDir, o.name), key); err != nil {
			return nil, err
		}
		made = append(made, out.keyFile, out.crtFile)
	}
	reg, err := c.Add(ctx, adminapi.AddRequest{
		Name: o.name, PublicKey: pubHex, IP: o.ip, Subnet: o.subnet, Endpoint: o.endpoint,
	})
	if err != nil {
		for _, f := range made {
			_ = os.Remove(f)
		}
		return nil, err
	}
	out.ip, out.publicKey = reg.IP.String(), reg.PublicKey
	out.spokeConfig = admin.SpokeConfig(reg, admin.SpokeOptions{KeyFile: o.name + ".key", Generated: o.generate})
	if o.generate {
		out.spokeFile = filepath.Join(o.keyDir, o.name+".yaml")
		if err := os.WriteFile(out.spokeFile, []byte(out.spokeConfig), 0o600); err != nil {
			// The registration succeeded; do not lose the config, print it instead.
			fmt.Fprintf(os.Stderr, "warning: could not save %s: %v\n", out.spokeFile, err)
			out.spokeFile = ""
		}
	}
	return out, nil
}

func printAdded(w io.Writer, out *addOutcome, via string) {
	fmt.Fprintf(w, "Added peer %q: %s/32 (public key %s)\n", out.name, out.ip, proto.BytesToHex(out.publicKey[:8])+"...")
	if via != "" {
		fmt.Fprintf(w, "  registered through the %s; the relay applied it immediately\n", via)
	} else {
		fmt.Fprintf(w, "  wrote %s\n", out.peerFile)
		fmt.Fprintln(w, "  a running relay loads it within a second or two")
	}
	if out.keyFile != "" {
		fmt.Fprintf(w, "  generated %s (private, 0600), %s", out.keyFile, out.crtFile)
		if out.spokeFile != "" {
			fmt.Fprintf(w, " and %s", out.spokeFile)
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  copy the .key and .yaml to the new machine, then delete the key from here")
	}
	fmt.Fprintf(w, "\nConfig for %s:\n\n%s", out.name, out.spokeConfig)
}

func printConfigured(w io.Writer, entries []admin.Entry) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tALLOWED IPS\tPUBLIC KEY\tENDPOINT\tSOURCE")
	for _, e := range entries {
		n, src := e.Name, "peers_dir"
		if e.Inline {
			n, src = "-", "config"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", n, strings.Join(e.AllowedIPs, ","),
			proto.BytesToHex(e.PublicKey[:8])+"...", orDash(e.Endpoint), src)
	}
	_ = tw.Flush()
}

func printLive(w io.Writer, peers []adminapi.PeerInfo) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tALLOWED IPS\tSTATE\tADDRESS\tLAST SEEN\tRX\tTX\tSOURCE")
	for _, p := range peers {
		n := p.Name
		if n == "" {
			n = "-"
		}
		state, addr, seen := "offline", "-", "-"
		if p.Connected {
			state, addr = "connected", p.Addr
			if p.LastSeen != nil {
				seen = ago(time.Since(*p.LastSeen))
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", n, strings.Join(p.AllowedIPs, ","),
			state, addr, seen, humanBytes(p.RxBytes), humanBytes(p.TxBytes), p.Source)
	}
	_ = tw.Flush()
}

func ago(d time.Duration) string {
	switch {
	case d < 2*time.Second:
		return "now"
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d/time.Second))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d/time.Minute))
	default:
		return fmt.Sprintf("%dh ago", int(d/time.Hour))
	}
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
