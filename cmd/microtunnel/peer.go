package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/jecklgamis/microtunnel/internal/admin"
	"github.com/jecklgamis/microtunnel/internal/proto"
)

const peerUsage = `Usage:
  microtunnel peer add <name> [flags]     register a peer with this relay
  microtunnel peer remove <name> [flags]  unregister a peer
  microtunnel peer list [flags]           show configured peers

These edit the relay's peers_dir; a running relay picks the change up within a
couple of seconds, with no restart. Flags:
  -c <file>          relay config file (default peer.yaml)

peer add:
  -public-key <hex>  the peer's own public key (recommended: its private key never leaves it)
  -generate          instead, create a key pair for the peer here
  -key-dir <dir>     where -generate writes <name>.key, .crt and .yaml (default .)
  -ip <addr>         fixed overlay IP (default: the lowest free address)
  -subnet <cidr>     overlay subnet (default: the relay's tunnel_address network)
  -endpoint <h:p>    the relay's public host:port, written into the peer's config
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
	configPath := fs.String("c", "peer.yaml", "relay config file")

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

	switch sub {
	case "add":
		res, err := admin.Add(admin.AddOptions{
			ConfigPath: *configPath, Name: name, PublicKeyHex: pubHex, Generate: generate,
			KeyDir: keyDir, IP: ip, Subnet: subnet, Endpoint: endpoint,
		})
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Added peer %q: %s/32 (public key %s)\n", res.Name, res.IP, proto.BytesToHex(res.PublicKey[:8])+"...")
		fmt.Fprintf(stdout, "  wrote %s\n", res.PeerFile)
		fmt.Fprintln(stdout, "  a running relay loads it within a second or two")
		if res.KeyFile != "" {
			fmt.Fprintf(stdout, "  generated %s (private, 0600), %s and %s\n", res.KeyFile, res.CrtFile, res.SpokeFile)
			fmt.Fprintln(stdout, "  copy the .key and .yaml to the new machine, then delete the key from here")
		}
		fmt.Fprintf(stdout, "\nConfig for %s:\n\n%s", res.Name, res.SpokeConfig)
	case "remove":
		if err := admin.Remove(*configPath, name); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Removed peer %q; a running relay drops its session within a second or two\n", name)
	case "list":
		entries, err := admin.List(*configPath)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tALLOWED IPS\tPUBLIC KEY\tENDPOINT\tSOURCE")
		for _, e := range entries {
			n, src := e.Name, "peers_dir"
			if e.Inline {
				n, src = "-", "config"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", n, strings.Join(e.AllowedIPs, ","),
				proto.BytesToHex(e.PublicKey[:8])+"...", orDash(e.Endpoint), src)
		}
		return tw.Flush()
	}
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
