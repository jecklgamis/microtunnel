// Command microtunnel is a simple hub-and-spoke layer 3 overlay network for
// Linux and macOS: a TUN virtual interface carried over encrypted UDP.
//
// Usage:
//
//	microtunnel [-c <config.yaml>]          run the tunnel
//	microtunnel peer add|remove|list ...    manage the relay's peers_dir
//	microtunnel keygen <name>               create a key pair and print the public key
//	microtunnel enroll serve|token ...      self-service enrollment service (next to a relay)
//	microtunnel join <url> -token <t>       enroll this machine with such a service
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jecklgamis/microtunnel/internal/adminapi"
	"github.com/jecklgamis/microtunnel/internal/config"
	"github.com/jecklgamis/microtunnel/internal/logx"
	"github.com/jecklgamis/microtunnel/internal/peer"
	"github.com/jecklgamis/microtunnel/internal/proto"
	"github.com/jecklgamis/microtunnel/internal/tun"
)

// peersPollInterval is how often peers_dir is checked for changes.
const peersPollInterval = time.Second

// version is stamped at build time: -ldflags "-X main.version=1.2.3".
var version = "dev"

func main() {
	if err := run(); err != nil {
		logx.Errorf("%v", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "peer":
			return runPeerCmd(os.Args[2:], os.Stdout, os.Stderr)
		case "keygen":
			return runKeygen(os.Args[2:], os.Stdout, os.Stderr)
		case "enroll":
			return runEnroll(os.Args[2:], os.Stdout, os.Stderr)
		case "join":
			return runJoin(os.Args[2:], os.Stdout, os.Stderr)
		}
	}
	configPath := flag.String("c", "peer.yaml", "YAML config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [-c <config.yaml>]\n       %s peer add|remove|list ...  (see `%s peer help`, `enroll help`, `join -h`)\n", os.Args[0], os.Args[0], os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if *showVersion {
		fmt.Println("microtunnel", version)
		return nil
	}

	logx.Infof("Loading config: %s", *configPath)
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	logx.SetVerbose(cfg.Verbose)

	addrInfo := ""
	if cfg.Address != "" {
		addrInfo = " address=" + cfg.Address
	}
	logx.Infof("Config: interface=%s port=%d%s", cfg.Interface, cfg.Port, addrInfo)
	logx.Infof("Config: keepalive_interval=%ds rekey_after=%ds reconnect_interval=%ds",
		cfg.KeepaliveInterval, cfg.RekeyAfter, cfg.ReconnectInterval)
	logx.Infof("Config: session_expiry=%ds prev_key_grace=%ds handshake_timeout=%ds handshake_cooldown=%ds",
		cfg.SessionExpiry, cfg.PrevKeyGrace, cfg.HandshakeTimeout, cfg.HandshakeCooldown)
	logx.Infof("Config: worker_threads=%d", cfg.WorkerThreads)

	static, err := proto.LoadStaticKey(cfg.PrivateKeyFile)
	if err != nil {
		return err
	}
	logx.Infof("Loaded static key from %s", cfg.PrivateKeyFile)
	pub := proto.PubBytes(static)
	logx.Infof("Peer public key: %s", proto.BytesToHex(pub[:]))

	for i := range cfg.Peers {
		p := &cfg.Peers[i]
		mode := " [inbound-only]"
		if p.HasEndpoint() {
			mode = " [outbound]"
		}
		logx.Infof("Known peer: %s (%d route(s))%s", proto.BytesToHex(p.PublicKey[:]), len(p.AllowedIPs), mode)
	}
	if cfg.HasPSK {
		logx.Infof("PSK set — handshake will be authenticated")
	} else {
		logx.Warnf("No PSK — handshake unauthenticated (MITM-vulnerable)")
	}

	dev, name, err := tun.Open(cfg.Interface)
	if err != nil {
		return err
	}
	logx.Infof("Opened tunnel %s", name)
	if cfg.TunnelAddress.IsValid() {
		if err := tun.Configure(name, cfg.TunnelAddress, cfg.TunnelRoutes); err != nil {
			_ = dev.Close()
			return err
		}
	}

	conn, err := peer.Listen(cfg.Address, cfg.Port)
	if err != nil {
		_ = dev.Close()
		return err
	}
	bindAddr := cfg.Address
	if bindAddr == "" {
		bindAddr = "0.0.0.0"
	}
	logx.Infof("Listening on UDP %s:%d", bindAddr, cfg.Port)

	p, err := peer.New(cfg, static, dev, conn)
	if err != nil {
		_ = conn.Close()
		_ = dev.Close()
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// SIGUSR1 dumps the active session table.
	usr1 := make(chan os.Signal, 1)
	signal.Notify(usr1, syscall.SIGUSR1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-usr1:
				p.PrintSessions()
			}
		}
	}()

	if cfg.AdminSocket != "" {
		ln, err := adminapi.Listen(cfg.AdminSocket)
		if err != nil {
			_ = conn.Close()
			_ = dev.Close()
			return err
		}
		logx.Infof("Admin API listening on %s (mode 0600)", cfg.AdminSocket)
		go func() {
			if err := adminapi.New(p, *configPath, version).Serve(ctx, ln); err != nil {
				logx.Errorf("admin API: %v", err)
			}
		}()
	}

	// SIGHUP, or a change in peers_dir, re-reads the peer list without
	// restarting or disturbing the other sessions.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	trigger := make(chan struct{}, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				select {
				case trigger <- struct{}{}:
				default: // a reload is already queued
				}
			}
		}
	}()
	if cfg.PeersDir != "" {
		logx.Infof("Watching peers_dir %s (reloads on change; SIGHUP forces a reload)", cfg.PeersDir)
	}
	go p.WatchPeers(ctx, *configPath, cfg.PeersDir, peersPollInterval, trigger)

	return p.Run(ctx)
}
