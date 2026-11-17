package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/jecklgamis/microtunnel/internal/adminapi"
	"github.com/jecklgamis/microtunnel/internal/config"
	"github.com/jecklgamis/microtunnel/internal/enroll"
	"github.com/jecklgamis/microtunnel/internal/logx"
	"github.com/jecklgamis/microtunnel/internal/setup"
)

const enrollUsage = `Usage:
  microtunnel enroll serve [flags]            run the enrollment service next to a relay
  microtunnel enroll token create [flags]     make a single-use join token
  microtunnel enroll token list [flags]       show tokens and their state
  microtunnel enroll token revoke <id>        delete a token
  microtunnel join <url> -token <token>       (on a new machine) enroll and write a config

enroll serve:
  -listen <addr>     address to listen on (default :8443)
  -socket <path>     the relay's admin socket  (or -c <relay.yaml>: use its admin_socket)
  -tokens <dir>      token directory (default enroll-tokens)
  -tls-cert <file> -tls-key <file>   serve HTTPS (required unless -insecure-http)
  -insecure-http     serve plain HTTP: only behind a TLS-terminating proxy or on a trusted network

enroll token create:
  -tokens <dir>      token directory (default enroll-tokens)
  -name <name>       bind the token to this peer name (otherwise the new machine picks one)
  -ttl <duration>    lifetime (default 1h, max 168h)
  -url <url>         the service's public URL, to print a complete join command
`

const joinUsage = `Usage: microtunnel join <url> -token <token> [flags]

Generates a key pair on this machine, enrolls its public key with the service at
<url> and writes <name>.key, <name>.crt and <name>.yaml. The private key never
leaves this machine.
  -token <token>     the join token (or set MICROTUNNEL_JOIN_TOKEN, which keeps it out of shell history)
  -name <name>       peer name (not needed if the token carries one)
  -dir <dir>         where to write the files (default /etc/microtunnel when run as root, else .)
  -ca-file <file>    trust this CA for the service's certificate (private/self-signed CA)
  -allow-http        permit a plain http:// URL (trusted networks only)
`

const defaultTokensDir = "enroll-tokens"

// runEnroll implements `microtunnel enroll ...`; args exclude "enroll".
func runEnroll(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, enrollUsage)
		return errors.New("missing enroll subcommand")
	}
	switch args[0] {
	case "serve":
		return enrollServeCmd(args[1:], stderr)
	case "token":
		return enrollTokenCmd(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, enrollUsage)
		return nil
	}
	fmt.Fprint(stderr, enrollUsage)
	return fmt.Errorf("unknown enroll subcommand %q", args[0])
}

type serveOpts struct {
	listen, socket, tokens, certFile, keyFile string
	insecureHTTP                              bool
}

func enrollServeCmd(args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("enroll serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, enrollUsage) }
	var o serveOpts
	configPath := fs.String("c", "", "relay config file (to read admin_socket)")
	fs.StringVar(&o.listen, "listen", ":8443", "")
	fs.StringVar(&o.socket, "socket", "", "")
	fs.StringVar(&o.tokens, "tokens", defaultTokensDir, "")
	fs.StringVar(&o.certFile, "tls-cert", "", "")
	fs.StringVar(&o.keyFile, "tls-key", "", "")
	fs.BoolVar(&o.insecureHTTP, "insecure-http", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if o.socket == "" && *configPath != "" {
		cfg, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		if cfg.AdminSocket == "" {
			return fmt.Errorf("%s has no admin_socket", *configPath)
		}
		o.socket = cfg.AdminSocket
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	return serveEnroll(ctx, o, nil)
}

// serveEnroll runs the service until ctx is done. ready, if non-nil, receives
// the bound address once listening (used by tests).
func serveEnroll(ctx context.Context, o serveOpts, ready chan<- string) error {
	if o.socket == "" {
		return errors.New("the relay's admin socket is required: pass -socket <path> or -c <relay.yaml>")
	}
	var tlsCfg *tls.Config
	switch {
	case o.certFile != "" || o.keyFile != "":
		if o.certFile == "" || o.keyFile == "" {
			return errors.New("-tls-cert and -tls-key must be given together")
		}
		cert, err := tls.LoadX509KeyPair(o.certFile, o.keyFile)
		if err != nil {
			return fmt.Errorf("TLS: %w", err)
		}
		tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	case o.insecureHTTP:
		logx.Warnf("Serving enrollment over plain HTTP: join tokens and the pre-shared key travel unencrypted unless a TLS proxy sits in front")
	default:
		return errors.New("refusing to serve without TLS: pass -tls-cert and -tls-key (or -insecure-http behind a TLS-terminating proxy)")
	}

	store, err := enroll.OpenStore(o.tokens)
	if err != nil {
		return err
	}
	// Fail fast if the relay is not reachable, rather than on the first enrollment.
	client := adminapi.NewClient(o.socket)
	pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	_, err = client.Status(pctx)
	cancel()
	if err != nil {
		return fmt.Errorf("cannot reach the relay's admin API at %s: %w", o.socket, err)
	}

	ln, err := net.Listen("tcp", o.listen)
	if err != nil {
		return err
	}
	scheme := "https"
	if tlsCfg == nil {
		scheme = "http"
	}
	logx.Infof("Enrollment service listening on %s://%s (relay admin socket %s, tokens in %s)", scheme, ln.Addr(), o.socket, o.tokens)
	if ready != nil {
		ready <- ln.Addr().String()
	}
	return enroll.NewServer(store, client).Serve(ctx, ln, tlsCfg)
}

func enrollTokenCmd(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, enrollUsage)
		return errors.New("missing token subcommand")
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("enroll token "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, enrollUsage) }
	tokens := fs.String("tokens", defaultTokensDir, "token directory")
	var (
		name, urlFlag string
		ttl           time.Duration
		id            string
	)
	switch sub {
	case "create":
		fs.StringVar(&name, "name", "", "")
		fs.StringVar(&urlFlag, "url", "", "")
		fs.DurationVar(&ttl, "ttl", enroll.DefaultTTL, "")
	case "revoke":
		if len(rest) == 0 || strings.HasPrefix(rest[0], "-") {
			fs.Usage()
			return errors.New("token revoke needs a token id")
		}
		id, rest = rest[0], rest[1:]
	case "list":
	default:
		fs.Usage()
		return fmt.Errorf("unknown token subcommand %q", sub)
	}
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	store, err := enroll.OpenStore(*tokens)
	if err != nil {
		return err
	}

	switch sub {
	case "create":
		if name != "" && !validPeerName(name) {
			return fmt.Errorf("invalid peer name %q", name)
		}
		now := time.Now()
		tok, rec, err := store.Create(name, ttl, now)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Join token (shown once; valid until %s, single use):\n\n  %s\n\n", rec.Expires.Local().Format(time.RFC3339), tok)
		u := urlFlag
		if u == "" {
			u = "<enrollment-url>"
		}
		extra := ""
		if name == "" {
			extra = " -name <name>"
		}
		fmt.Fprintf(stdout, "On the new machine:\n\n  microtunnel join %s -token %s%s\n", u, tok, extra)
	case "list":
		entries, err := store.List(time.Now())
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tNAME\tSTATE\tEXPIRES")
		for _, e := range entries {
			n := e.Name
			if n == "" {
				n = "-"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.ID, n, e.Status, e.Expires.Local().Format(time.RFC3339))
		}
		return tw.Flush()
	case "revoke":
		if err := store.Revoke(id); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Revoked token %s\n", id)
	}
	return nil
}

// runJoin implements `microtunnel join <url> -token ...`; args exclude "join".
func runJoin(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("join", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, joinUsage) }
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "-help") {
			fmt.Fprint(stdout, joinUsage)
			return nil
		}
		fs.Usage()
		return errors.New("join needs the enrollment service URL")
	}
	url, rest := args[0], args[1:]
	token := fs.String("token", "", "")
	name := fs.String("name", "", "")
	dir := fs.String("dir", "", "")
	ca := fs.String("ca-file", "", "")
	allowHTTP := fs.Bool("allow-http", false, "")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q (put flags after the URL)", fs.Arg(0))
	}
	if *token == "" {
		*token = os.Getenv("MICROTUNNEL_JOIN_TOKEN")
	}
	if *dir == "" { // as root, write where the services look; otherwise the current directory
		*dir = "."
		if os.Geteuid() == 0 {
			*dir = setup.DefaultDir
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := enroll.Join(ctx, enroll.JoinOptions{
		URL: url, Token: *token, Name: *name, Dir: *dir, CAFile: *ca, AllowHTTP: *allowHTTP,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Enrolled as %q with overlay address %s\n", res.Name, res.IP)
	fmt.Fprintf(stdout, "  private key: %s (mode 0600)\n  public key:  %s\n  config:      %s\n\n", res.KeyFile, res.CrtFile, res.ConfigFile)
	fmt.Fprintf(stdout, "Start it with:\n\n  %s\n", startHint(res.Name, res.ConfigFile, *dir))
	return nil
}
