package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jecklgamis/microtunnel/internal/setup"
)

const initUsage = `Usage:
  microtunnel init relay [flags]    set this machine up as a relay
  microtunnel init peer  [flags]    set this machine up as a peer of an existing relay

Both generate the machine's key (an existing key is reused, never replaced) and write a
complete, validated config. An existing config is never overwritten unless you pass -force.

init relay:
  -dir <dir>            config directory (default /etc/microtunnel)
  -endpoint <host:port> the relay's public address; handed to peers and shown in the peer hint
  -address <ip/len>     the relay's overlay address (default 10.9.0.1/24)
  -port <n>             UDP port (default 5040)
  -admin-socket <path>  admin API socket (default /run/microtunnel/admin.sock; "none" turns it off)
  -force                replace an existing relay.yaml (a NEW pre-shared key is generated)
  -start                also run: systemctl enable --now microtunnel-relay

init peer:
  -dir <dir>            config directory (default /etc/microtunnel)
  -name <name>          names the files <name>.key/.yaml (default "peer", which the
                        microtunnel-peer service uses; any other name uses microtunnel-peer@<name>)
  -relay <host:port>    the relay's public address                      (required)
  -relay-key <hex>      the relay's public key                          (required)
  -psk <secret>         the relay's pre-shared key; or -psk-file <file>, or the MICROTUNNEL_PSK
                        environment variable, which keep it out of the process list   (required)
  -address <ip/len>     this peer's overlay address, once the relay's admin has assigned one
  -subnet <cidr>        overlay subnet when no -address is given (default 10.9.0.0/24)
  -force                replace an existing <name>.yaml (the key is kept)
  -start                also run: systemctl enable --now <the service>
`

// runInit implements `microtunnel init ...`; args exclude "init".
func runInit(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, initUsage)
		return errors.New("missing init subcommand (relay or peer)")
	}
	switch args[0] {
	case "relay":
		return initRelayCmd(args[1:], stdout, stderr)
	case "peer":
		return initPeerCmd(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, initUsage)
		return nil
	}
	fmt.Fprint(stderr, initUsage)
	return fmt.Errorf("unknown init subcommand %q", args[0])
}

func newInitFlags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("init "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, initUsage) }
	return fs
}

func initRelayCmd(args []string, stdout, stderr io.Writer) error {
	fs := newInitFlags("relay", stderr)
	var o setup.RelayOptions
	var start bool
	fs.StringVar(&o.Dir, "dir", setup.DefaultDir, "")
	fs.StringVar(&o.Endpoint, "endpoint", "", "")
	fs.StringVar(&o.Address, "address", "", "")
	fs.IntVar(&o.Port, "port", 0, "")
	fs.StringVar(&o.AdminSocket, "admin-socket", "", "")
	fs.BoolVar(&o.Force, "force", false, "")
	fs.BoolVar(&start, "start", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if start && !isDefaultDir(o.Dir) {
		return errors.New("-start works only with the default config directory (the service reads /etc/microtunnel/relay.yaml)")
	}

	res, err := setup.InitRelay(o)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Relay initialised.\n")
	fmt.Fprintf(stdout, "  config:      %s   (mode 0600: it holds the pre-shared key)\n", res.ConfigFile)
	reuse := ""
	if res.ReusedKey {
		reuse = "   (existing key reused)"
	}
	fmt.Fprintf(stdout, "  private key: %s%s\n", res.KeyFile, reuse)
	fmt.Fprintf(stdout, "  peers dir:   %s\n", res.PeersDir)
	fmt.Fprintf(stdout, "  overlay:     %s, UDP port %d\n", res.Address, res.Port)
	fmt.Fprintf(stdout, "  public key:  %s\n", res.PublicKey)
	if res.Overwrote {
		fmt.Fprintf(stdout, "\nNOTE: -force generated a NEW pre-shared key. Existing peers must be updated with it.\n")
	}

	unit := "microtunnel-relay"
	if start {
		if err := systemctlEnableNow(unit, stderr); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "\nStarted %s.\n", unit)
	} else {
		fmt.Fprintf(stdout, "\nStart it:\n  %s\n", startHint(unit, res.ConfigFile, o.Dir))
	}

	endpoint := res.Endpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("RELAY_HOST:%d", res.Port)
	}
	fmt.Fprintf(stdout, "\nAdd peers:\n")
	fmt.Fprintf(stdout, "  # on this relay, for a machine that sends you its public key:\n")
	fmt.Fprintf(stdout, "  microtunnel peer add <name> -public-key <hex>\n")
	fmt.Fprintf(stdout, "  # on the new machine (this line contains the pre-shared key: send it over a secure channel):\n")
	fmt.Fprintf(stdout, "  MICROTUNNEL_PSK=%s microtunnel init peer -relay %s -relay-key %s\n", res.PSK, endpoint, res.PublicKey)
	return nil
}

func initPeerCmd(args []string, stdout, stderr io.Writer) error {
	fs := newInitFlags("peer", stderr)
	var o setup.PeerOptions
	var pskFile string
	var start bool
	fs.StringVar(&o.Dir, "dir", setup.DefaultDir, "")
	fs.StringVar(&o.Name, "name", "peer", "")
	fs.StringVar(&o.Relay, "relay", "", "")
	fs.StringVar(&o.RelayKey, "relay-key", "", "")
	fs.StringVar(&o.PSK, "psk", "", "")
	fs.StringVar(&pskFile, "psk-file", "", "")
	fs.StringVar(&o.Address, "address", "", "")
	fs.StringVar(&o.Subnet, "subnet", "", "")
	fs.BoolVar(&o.Force, "force", false, "")
	fs.BoolVar(&start, "start", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	psk, err := resolvePSK(o.PSK, pskFile)
	if err != nil {
		return err
	}
	o.PSK = psk
	if start && !isDefaultDir(o.Dir) {
		return errors.New("-start works only with the default config directory (the service reads /etc/microtunnel/<name>.yaml)")
	}

	res, err := setup.InitPeer(o)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Peer %q initialised.\n", res.Name)
	fmt.Fprintf(stdout, "  config:      %s   (mode 0600: it holds the pre-shared key)\n", res.ConfigFile)
	reuse := ""
	if res.ReusedKey {
		reuse = "   (existing key reused)"
	}
	fmt.Fprintf(stdout, "  private key: %s%s\n", res.KeyFile, reuse)
	fmt.Fprintf(stdout, "  public key:  %s\n", res.PublicKey)

	fmt.Fprintf(stdout, "\nThe relay's administrator must register this peer:\n")
	if res.Address.IsValid() {
		fmt.Fprintf(stdout, "  microtunnel peer add %s -public-key %s -ip %s\n", res.Name, res.PublicKey, res.Address.Addr())
	} else {
		fmt.Fprintf(stdout, "  microtunnel peer add %s -public-key %s\n", res.Name, res.PublicKey)
		fmt.Fprintf(stdout, "It prints the overlay address assigned to this peer. Then set it here (the key is kept):\n")
		fmt.Fprintf(stdout, "  %s\n", rerunHint(o, res.Name))
	}

	unit := peerUnit(res.Name)
	if start {
		if err := systemctlEnableNow(unit, stderr); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "\nStarted %s.\n", unit)
	} else {
		fmt.Fprintf(stdout, "\nStart it:\n  %s\n", startHint(unit, res.ConfigFile, o.Dir))
	}
	return nil
}

// resolvePSK takes the pre-shared key from -psk, then -psk-file, then the
// MICROTUNNEL_PSK environment variable.
func resolvePSK(flagVal, file string) (string, error) {
	switch {
	case flagVal != "":
		return flagVal, nil
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("-psk-file: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return os.Getenv("MICROTUNNEL_PSK"), nil
}

func isDefaultDir(dir string) bool {
	abs, err := filepath.Abs(dir)
	return err == nil && abs == setup.DefaultDir
}

func peerUnit(name string) string {
	if name == "peer" {
		return "microtunnel-peer"
	}
	return "microtunnel-peer@" + name
}

func startHint(unit, configFile, dir string) string {
	if isDefaultDir(dir) {
		return "sudo systemctl enable --now " + unit
	}
	return "sudo microtunnel -c " + configFile
}

// rerunHint builds the command that sets the assigned address, without ever
// echoing the pre-shared key.
func rerunHint(o setup.PeerOptions, name string) string {
	var b strings.Builder
	b.WriteString("MICROTUNNEL_PSK=<the relay's pre-shared key> microtunnel init peer")
	if name != "peer" {
		fmt.Fprintf(&b, " -name %s", name)
	}
	if !isDefaultDir(o.Dir) {
		fmt.Fprintf(&b, " -dir %s", o.Dir)
	}
	fmt.Fprintf(&b, " -relay %s -relay-key %s -address <assigned-ip>/%d -force", o.Relay, o.RelayKey, subnetBits(o))
	return b.String()
}

func subnetBits(o setup.PeerOptions) int {
	s := o.Subnet
	if s == "" {
		return 24
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Bits()
	}
	return 24
}

func systemctlEnableNow(unit string, stderr io.Writer) error {
	path, err := exec.LookPath("systemctl")
	if err != nil {
		return fmt.Errorf("-start needs systemd, but systemctl was not found; start it yourself with `microtunnel -c <config>`")
	}
	cmd := exec.Command(path, "enable", "--now", unit)
	cmd.Stdout, cmd.Stderr = stderr, stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemctl enable --now %s: %w (config and keys were written; fix the cause and run it yourself)", unit, err)
	}
	return nil
}
