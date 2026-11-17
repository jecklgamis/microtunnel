// Command microtunnel is a simple Linux hub-and-spoke layer 3 overlay network:
// a TUN virtual interface carried over encrypted UDP.
//
// Usage:
//
//	microtunnel [-c <config.yaml>]
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jecklgamis/microtunnel/internal/config"
	"github.com/jecklgamis/microtunnel/internal/logx"
	"github.com/jecklgamis/microtunnel/internal/peer"
	"github.com/jecklgamis/microtunnel/internal/proto"
	"github.com/jecklgamis/microtunnel/internal/tun"
)

// version is stamped at build time: -ldflags "-X main.version=1.2.3".
var version = "dev"

func main() {
	if err := run(); err != nil {
		logx.Errorf("%v", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("c", "peer.yaml", "YAML config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [-c <config.yaml>]\n", os.Args[0])
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

	return p.Run(ctx)
}
